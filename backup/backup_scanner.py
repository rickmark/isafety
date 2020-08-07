from .libibackup import LocalBackup
from plistlib import *

class BackupScanner(object):
    def __init__(self, backup: LocalBackup):
        self.backup = backup

    def get_profiles(self):
        result = []
        for file in self.backup.files_in_domain('SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles'):
            if "profile-" in file.relative_path:
                full_path = self.backup.get_path_by_id(file.file_id)
                with open(full_path, "rb") as data_file:
                    data = loads(data_file.read())
                    result.append(data['PayloadDisplayName'])

        if len(result) == 0:
            return None
        return result

    def get_provisioning(self):
        result = []
        for file in self.backup.files_in_domain('MobileDeviceDomain'):
            
