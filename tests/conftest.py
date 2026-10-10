import os
from pathlib import Path
import pytest
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

@pytest.fixture
def examples():
    return Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture(scope="session", autouse=True)
def qt_application_lifetime():
    """Keep one QApplication alive across GUI tests and join local workers.

    Qt widgets must never outlive their application; repeated per-test creation
    can otherwise fault during PySide interpreter teardown.
    """
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import QThreadPool
    application = QApplication.instance() or QApplication([])
    yield application
    QThreadPool.globalInstance().waitForDone(45000)
    # Dispose top-level widgets while the application and their signals are alive.
    from PySide6.QtCore import QCoreApplication, QEvent
    for widget in application.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    application.processEvents()
