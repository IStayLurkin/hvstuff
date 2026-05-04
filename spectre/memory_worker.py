from __future__ import annotations
import traceback
from typing import Callable, Any
from PyQt5.QtCore import QObject, QTimer, pyqtSignal


class MemoryWorker(QObject):
    """
    Runs build_fn() on a QThread, emits scene_ready with the result each tick.

    Usage:
        worker = MemoryWorker(build_fn=lambda: memory.build_scene(...))
        thread = QThread()
        worker.moveToThread(thread)
        worker.scene_ready.connect(overlay.update_scene)
        thread.started.connect(worker.start)
        thread.start()
        # To stop from the main thread (thread-safe):
        worker.stop_requested.emit()
    """

    scene_ready   = pyqtSignal(object)
    error         = pyqtSignal(str)
    stop_requested = pyqtSignal()

    def __init__(self, build_fn: Callable[[], Any], interval_ms: int = 16) -> None:
        super().__init__()
        self._build_fn = build_fn
        self._interval = interval_ms
        self._timer: QTimer | None = None

    def start(self) -> None:
        self._timer = QTimer(self)
        self._timer.setInterval(self._interval)
        self._timer.timeout.connect(self._run_once)
        self.stop_requested.connect(self._timer.stop)
        self._timer.start()

    def stop(self) -> None:
        """Call from the worker thread only. For cross-thread stop, emit stop_requested."""
        if self._timer:
            self._timer.stop()

    def _run_once(self) -> None:
        try:
            scene = self._build_fn()
            self.scene_ready.emit(scene)
        except Exception:
            self.error.emit(traceback.format_exc())
