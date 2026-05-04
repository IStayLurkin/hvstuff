import pytest
from unittest.mock import MagicMock

pytest.importorskip('PyQt5')

from PyQt5.QtCore import QCoreApplication
import sys

@pytest.fixture(scope='module')
def qt_app():
    app = QCoreApplication.instance() or QCoreApplication(sys.argv)
    yield app

def test_memory_worker_emits_scene(qt_app):
    from memory_worker import MemoryWorker
    fake_scene = object()
    build_fn = MagicMock(return_value=fake_scene)

    worker = MemoryWorker(build_fn=build_fn, interval_ms=0)
    received = []
    worker.scene_ready.connect(lambda s: received.append(s))

    worker._run_once()

    assert received == [fake_scene]
    build_fn.assert_called_once()

def test_memory_worker_emits_error_on_exception(qt_app):
    from memory_worker import MemoryWorker

    def explode():
        raise RuntimeError("boom")

    worker = MemoryWorker(build_fn=explode, interval_ms=0)
    errors = []
    worker.error.connect(lambda e: errors.append(e))

    worker._run_once()

    assert len(errors) == 1
    assert 'boom' in errors[0]
