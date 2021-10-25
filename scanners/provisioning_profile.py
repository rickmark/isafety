from . import ScannerBase
import re


class ProvisioningProfileScanner(ScannerBase):
    GUID_REGEX = re.compile('[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}')

    def scan(self):
        for file in self.backup.files_in_domain('MobileDeviceDomain'):
            if ProvisioningProfileScanner.GUID_REGEX.search(file.relative_path):
                yield {'file_id': file.file_id}
