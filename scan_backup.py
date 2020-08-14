#!/usr/bin/env python

from backup.backup_scanner import *
from libimobiledevice.libibackup import LocalBackup
import sys

backup = LocalBackup(sys.argv[1])

scanner = BackupScanner(backup)

pairings = scanner.get_pairing_records()
if pairings:
    print("Backup contains iTunes Pairing records:")
    for pairing in pairings:
        print(f"\t{pairing}")


profiles = scanner.get_profiles()
if profiles:
    print("Backup contains configuration profiles:")
    for profile in profiles:
        print(f"\t{profile}")

provisionings = scanner.get_provisioning()
if provisionings:
    print("Backup contains provisioning profiles:")
    for provisioning in provisionings:
        print(f"\t{provisioning}")


watch_backups = scanner.get_watch_backups()
if watch_backups:
    print("Backup contains watch backups")
    for watch_backup in watch_backups:
        print(f"\t{watch_backup}")

managed_preferences = scanner.get_managed_preferences()
if watch_backups:
    print("Backup contains managed preferences")
    for preference in managed_preferences:
        print(f"\t{preference}")

carrier_settings = scanner.get_carrier_settings()
if carrier_settings:
    print("Backup has explicit cellular configuration")
    for setting in carrier_settings:
        print(f"\t{setting}")

bluetooth_settings = scanner.get_bluetooth_pairings()
if bluetooth_settings:
    print("Backup has explicit bluetooth pairings")
    for setting in bluetooth_settings:
        print(f"\t{setting}")

disabled_services_settings = scanner.get_disabled_services()
if disabled_services_settings:
    print("Backup has launchd services disabled")
    for service in disabled_services_settings:
        print(f"\t{service}")