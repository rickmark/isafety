from . import ScannerBase
import plistlib


class DisabledServicesScanner(ScannerBase):
    def scan(self):
        for file in self.backup.files_in_domain('DatabaseDomain'):
            if file.relative_path == "com.apple.xpc.launchd/disabled.plist":
                full_path = self.backup.get_path_by_id(file.file_id)
                with open(full_path, "rb") as data_file:
                    data = plistlib.loads(data_file.read())
                    for key in data.keys():
                        if data[key]:
                            yield {'service': key}
