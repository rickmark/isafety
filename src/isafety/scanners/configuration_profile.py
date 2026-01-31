from . import ScannerBase
import plistlib


class ConfigurationProfileScanner(ScannerBase):
    def scan(self):
        for file in self.backup.files_in_domain('SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles'):
            if "profile-" in file.relative_path:
                full_path = self.backup.get_path_by_id(file.file_id)
                with open(full_path, "rb") as data_file:
                    data = plistlib.loads(data_file.read())
                    yield {'display_name': data['PayloadDisplayName']}
