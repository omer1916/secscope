"""QProcess bridge to the worker: the UI thread never blocks on a scan."""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import ValidationError
from PySide6.QtCore import QObject, QProcess, QProcessEnvironment, Signal

from secscope.core.events import Command, ErrorEvent, Event, decode_event, encode
from secscope.worker.client import worker_command


class WorkerBridge(QObject):
    event_received = Signal(object)  # Event
    # (exit code, crashed): crashed=True when the worker died without scan.finished
    finished = Signal(int, bool)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._proc: QProcess | None = None
        self._buffer = b""
        self._saw_scan_finished = False

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.state() != QProcess.ProcessState.NotRunning

    def start(self, command: Command, env: Mapping[str, str] | None = None) -> None:
        if self.running:
            raise RuntimeError("a scan is already running")
        proc = QProcess(self)
        program, *args = worker_command()
        proc.setProgram(program)
        proc.setArguments(args)
        if env is not None:
            qenv = QProcessEnvironment()
            for key, value in env.items():
                qenv.insert(key, value)
            proc.setProcessEnvironment(qenv)
        proc.readyReadStandardOutput.connect(self._on_stdout)
        proc.finished.connect(self._on_finished)
        self._proc = proc
        self._buffer = b""
        self._saw_scan_finished = False
        proc.start()
        self.send(command)

    def send(self, command: Command) -> None:
        if self._proc is not None:
            self._proc.write(encode(command).encode("utf-8"))

    def shutdown(self, timeout_ms: int = 5000) -> None:
        """Close stdin (worker cancels and exits); kill if it does not."""
        if self._proc is None:
            return
        self._proc.closeWriteChannel()
        if not self._proc.waitForFinished(timeout_ms):
            self._proc.kill()
            self._proc.waitForFinished(timeout_ms)

    def _on_stdout(self) -> None:
        assert self._proc is not None
        self._buffer += bytes(self._proc.readAllStandardOutput().data())
        *lines, self._buffer = self._buffer.split(b"\n")
        for line in lines:
            if not line.strip():
                continue
            try:
                event: Event = decode_event(line)
            except ValidationError as exc:
                event = ErrorEvent(
                    scan_id="-", message="undecodable worker output", detail=str(exc)
                )
            if event.type == "scan.finished":
                self._saw_scan_finished = True
            self.event_received.emit(event)

    def _on_finished(self, code: int, _status: QProcess.ExitStatus) -> None:
        self._on_stdout()
        self.finished.emit(code, not self._saw_scan_finished)
