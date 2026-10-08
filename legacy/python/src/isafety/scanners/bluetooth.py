from . import ScannerBase
import plistlib


class BluetoothScanner(ScannerBase):
    def scan(self):
        for file in self.backup.files_in_domain('SysSharedContainerDomain-systemgroup.com.apple.bluetooth'):
            if file.relative_path == "Library/Preferences/com.apple.MobileBluetooth.devices.plist":
                full_path = self.backup.get_path_by_id(file.file_id)
                with open(full_path, "rb") as data_file:
                    data = plistlib.loads(data_file.read())
                    for key in data.keys():
                        yield {'mac_address': key}
