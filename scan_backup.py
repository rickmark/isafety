#!/usr/bin/env python

from backup.libibackup import LocalBackup
from backup.backup_scanner import *
import sys

backup = LocalBackup(sys.argv[1])

scanner = BackupScanner(backup)

profiles = scanner.get_profiles()
if profiles:
    print("Backup contains configuration profiles:")
    for profile in profiles:
        print(f"\t{profile}")