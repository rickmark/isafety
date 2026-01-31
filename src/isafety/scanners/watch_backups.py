from . import ScannerBase
import re


class WatchBackupScanner(ScannerBase):
    WATCH_BACKUP_REGEX = re.compile('Library/NanoBackup/[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$')

    def scan(self):
        for file in self.backup.files_in_domain('HomeDomain'):
            if WatchBackupScanner.WATCH_BACKUP_REGEX.search(file.relative_path):
                yield {'file_path': file.relative_path}
