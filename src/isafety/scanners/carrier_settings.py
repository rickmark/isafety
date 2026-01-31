from . import ScannerBase
import re


class CarrierSettingsScanner(ScannerBase):
    CARRIER_REGEX = re.compile('Library/Preferences/com.apple.carrier')
    OPERATOR_REGEX = re.compile('Library/Preferences/com.apple.operator')

    def scan(self):
        for file in self.backup.files_in_domain('HomeDomain'):
            if 'Library/Preferences/com.apple.carrier' in file.relative_path:
                yield {'file_path': file.relative_path}
            if 'Library/Preferences/com.apple.operator' in file.relative_path:
                yield {'file_path': file.relative_path}
