from .libibackup import LocalBackup
from plistlib import *
import asn1
import re

GUID_REGEX = re.compile('[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}')
WATCH_BACKUP_REGEX = re.compile('Library/NanoBackup/[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$')
MANAGED_PREFERENCE_REGEX = re.compile('.plist$')

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
            if GUID_REGEX.search(file.relative_path):
                result.append(file.file_id)

        if len(result) == 0:
            return None
        return result

    def get_watch_backups(self):
        result = []
        for file in self.backup.files_in_domain('HomeDomain'):
            if WATCH_BACKUP_REGEX.search(file.relative_path):
                result.append(file.relative_path)

        if len(result) == 0:
            return None
        return result

    def get_managed_preferences(self):
        result = []
        for file in self.backup.files_in_domain('ManagedPreferencesDomain'):
            if MANAGED_PREFERENCE_REGEX.search(file.relative_path):
                result.append(file.relative_path)

        if len(result) == 0:
            return None
        return result

    def get_bluetooth_pairings(self):
        result = []
        for file in self.backup.files_in_domain('SysSharedContainerDomain-systemgroup.com.apple.bluetooth'):
            pass

        if len(result) == 0:
            return None
        return result

    def get_wifi_settings(self):
        result = []
        for file in self.backup.files_in_domain('SystemPreferencesDomain'):
            if 'SystemConfiguration/com.apple.wifi.plist' in file:
                file_path = self.backup.get_path_by_id(file.file_id)
                with open(file_path, "rb") as data_file:
                    data = loads(data_file.read())



        if len(result) == 0:
            return None
        return result