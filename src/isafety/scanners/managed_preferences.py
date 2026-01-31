from . import ScannerBase
import re


class ManagedPreferencesScanner(ScannerBase):
    MANAGED_PREFERENCE_REGEX = re.compile('\\.plist$')

    def scan(self):
        for file in self.backup.files_in_domain('ManagedPreferencesDomain'):
            if ManagedPreferencesScanner.MANAGED_PREFERENCE_REGEX.search(file.relative_path):
                yield {'file_path': file.relative_path}
