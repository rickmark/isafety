from src.isafety.backup import MobileBackup
from src.isafety.collectors import CollectorBase
from src.isafety.collectors.icloud import CloudKitKeyStorageCollector
from src.isafety.collectors.ioreg import IORegCollector
from src.isafety.collectors.remotectl import RemoteAPCollector

MACOS_COLLECTORS = [
OctagonTrustCollector,
    CloudKitKeyStorageCollector,
    IORegCollector,
    RemoteAPCollector,
    SysCfgCollector
]

class Context:
    shared_context: Context | None = None

    _backup: MobileBackup | None
    collectors: dict[str, CollectorBase]

    def __init__(self, backup: MobileBackup | None = None):
        self._backup = backup
        if self._backup is None:

        else:
            self.collectors = {}

    @classmethod
    @property
    def current(cls):
        if cls.shared_context is None:
            cls.shared_context = Context()
        return cls.shared_context

    @classmethod
    def open_backup(cls, backup) -> Context:
        if cls.shared_context is None:
            cls.shared_context = Context(backup)
        elif cls.shared_context.backup != backup:
            raise Exception("Cannot open backup with different domain")
        return cls.shared_context
