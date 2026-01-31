from . import ScannerBase
import plistlib


class PairingRecordScanner(ScannerBase):
    def scan(self):
        for file in self.backup.files_in_domain('HomeDomain'):
            if 'Library/Preferences/com.apple.mobile.ldpair.plist' in file.relative_path:
                full_path = self.backup.get_path_by_id(file.file_id)
                with open(full_path, "rb") as data_file:
                    data = plistlib.loads(data_file.read())
                    for key in data.keys():
                        yield {'uuid': key}
