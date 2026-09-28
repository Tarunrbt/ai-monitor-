"""
collector.py

Samples running processes and normalizes the data into flat dictionaries
ready for storage and analysis.

Responsibilities:
    - Process discovery
    - CPU / memory / thread / status collection
    - Optional I/O metrics
    - Process start/end event detection
    - PID reuse protection
    - Crash-loop start tracking
    - Last known command line for recovery

Designed for:
    - Termux / Android
    - Linux
    - Other psutil-supported systems
"""

import time

import psutil


class Collector:
    def __init__(self, config: dict, storage):
        self.config = config
        self.storage = storage

        # pid -> process metadata
        #
        # create_time is important because Linux/Android can reuse
        # a PID after the previous process exits.
        self._known_pids = {}

        # process name -> list of start timestamps
        self._start_counts = {}

        # process name -> list of (end_timestamp, lifetime_seconds)
        # Used to distinguish restart churn from actual short-lived exits.
        self._end_events = {}

        # process name -> last known command line
        self._last_cmdline = {}

    def _is_ignored(self, name: str) -> bool:
        """
        Apply ignore_names and watch_only filters.

        Matching is case-insensitive so configuration such as
        'python' also matches 'Python' / 'PYTHON'.
        """

        name_lower = (name or "unknown").lower()

        ignore_names = [
            str(x).lower()
            for x in self.config.get(
                "ignore_names",
                [],
            )
        ]

        watch_only = [
            str(x).lower()
            for x in self.config.get(
                "watch_only",
                [],
            )
        ]

        if any(
            token in name_lower
            for token in ignore_names
        ):
            return True

        if watch_only and not any(
            token in name_lower
            for token in watch_only
        ):
            return True

        return False

    def sample_once(self):
        """
        Take one snapshot of currently visible processes.

        Returns:
            list[dict]

        Each dictionary contains:
            ts
            pid
            name
            cpu_percent
            mem_percent
            status
            num_threads
            io_read_bytes
            io_write_bytes
        """

        now = time.time()

        seen_pids = set()
        samples = []

        for proc in psutil.process_iter(
            [
                "pid",
                "name",
                "status",
                "num_threads",
                "create_time",
            ]
        ):

            try:
                info = proc.info

                pid = info.get("pid")

                if pid is None:
                    continue

                name = (
                    info.get("name")
                    or "unknown"
                )

                if self._is_ignored(name):
                    continue

                seen_pids.add(pid)

                create_time = info.get(
                    "create_time"
                )

                # -------------------------------------------------
                # Command line
                # -------------------------------------------------

                try:
                    cmdline = proc.cmdline()

                except (
                    psutil.AccessDenied,
                    psutil.NoSuchProcess,
                    psutil.ZombieProcess,
                ):
                    cmdline = []

                # -------------------------------------------------
                # CPU
                # -------------------------------------------------

                try:
                    cpu = proc.cpu_percent(
                        interval=None
                    )

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    continue

                # -------------------------------------------------
                # Memory
                # -------------------------------------------------

                try:
                    mem = proc.memory_percent()

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    continue

                # -------------------------------------------------
                # I/O
                # -------------------------------------------------

                io_read = None
                io_write = None

                try:
                    io = proc.io_counters()

                    io_read = io.read_bytes
                    io_write = io.write_bytes

                except (
                    psutil.AccessDenied,
                    psutil.NoSuchProcess,
                    psutil.ZombieProcess,
                    AttributeError,
                    NotImplementedError,
                ):
                    # Normal on some Android/Termux processes.
                    pass

                # -------------------------------------------------
                # Normalized sample
                # -------------------------------------------------

                sample = {
                    "ts": now,
                    "pid": pid,
                    "name": name,
                    "cpu_percent": cpu,
                    "mem_percent": mem,
                    "status": info.get("status"),
                    "num_threads": info.get(
                        "num_threads"
                    ),
                    "io_read_bytes": io_read,
                    "io_write_bytes": io_write,
                }

                samples.append(sample)

                # -------------------------------------------------
                # Process lifecycle tracking
                # -------------------------------------------------

                previous = self._known_pids.get(
                    pid
                )

                is_new_process = (
                    previous is None
                )

                # PID reuse protection:
                #
                # Same PID does NOT necessarily mean same process.
                # Compare create_time and name when available.
                if previous is not None:

                    old_create_time = previous.get(
                        "create_time"
                    )

                    old_name = previous.get(
                        "name"
                    )

                    if (
                        create_time is not None
                        and old_create_time is not None
                        and create_time
                        != old_create_time
                    ):
                        is_new_process = True

                    elif (
                        old_name is not None
                        and old_name != name
                    ):
                        is_new_process = True

                if is_new_process:

                    # If this PID was reused, record the previous
                    # process as ended before recording the new one.
                    if previous is not None:

                        self.storage.insert_event(
                            previous["name"],
                            "ended",
                            pid,
                            detail=(
                                "PID reused; "
                                "previous process replaced"
                            ),
                        )

                    # Concurrent siblings (a process tree's children, or threads that
                    # share a process name) are NOT sequential restarts -- only
                    # count this as a crash-loop "start" if no other live PID
                    # with this name existed the instant before.
                    already_alive = any(
                        m["name"] == name
                        for p, m in self._known_pids.items()
                        if p != pid
                    )

                    self._known_pids[pid] = {
                        "name": name,
                        "start_ts": now,
                        "create_time": create_time,
                        "cmdline": cmdline,
                    }

                    if not already_alive:
                        self._start_counts.setdefault(
                            name,
                            [],
                        ).append(now)

                    self.storage.insert_event(
                        name,
                        "started",
                        pid,
                    )

                    # Keep the latest command line for recovery.
                    if cmdline:
                        self._last_cmdline[
                            name
                        ] = cmdline

                else:

                    # Update command line if it became available
                    # after the initial process discovery.
                    if cmdline:
                        self._known_pids[pid][
                            "cmdline"
                        ] = cmdline

                        self._last_cmdline[
                            name
                        ] = cmdline

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                continue

        # ---------------------------------------------------------
        # Detect processes that disappeared
        # ---------------------------------------------------------

        ended_pids = [
            pid
            for pid in self._known_pids
            if pid not in seen_pids
        ]

        for pid in ended_pids:

            meta = self._known_pids.pop(
                pid
            )

            lifetime = (
                now - meta["start_ts"]
            )

            self.storage.insert_event(
                meta["name"],
                "ended",
                pid,
                detail=(
                    f"lived {lifetime:.1f}s"
                ),
            )

            self._end_events.setdefault(
                meta["name"],
                [],
            ).append(
                (now, lifetime)
            )

        return samples

    def pids_for_name(
        self,
        name: str,
    ) -> list:
        """
        Return currently known live PIDs
        matching the supplied process name.
        """

        return [
            pid
            for pid, meta
            in self._known_pids.items()
            if meta["name"] == name
        ]

    def last_cmdline_for(
        self,
        name: str,
    ) -> list:
        """
        Return the last known command line.

        Used by RecoveryManager when attempting
        a policy-approved relaunch.
        """

        return self._last_cmdline.get(
            name,
            [],
        )

    def crash_loop_count(
        self,
        name: str,
        window_sec: int = 300,
    ) -> int:
        """
        Count process starts during the recent window.

        Note:
            This is a restart/churn indicator, not proof of a crash.
            Analyzer should combine it with ended events/lifetime
            before classifying it as a crash loop.
        """

        cutoff = (
            time.time()
            - window_sec
        )

        starts = self._start_counts.get(
            name,
            [],
        )

        # Prune old entries in place.
        starts[:] = [
            timestamp
            for timestamp in starts
            if timestamp >= cutoff
        ]

        return len(starts)
