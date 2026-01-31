#!/usr/bin/env python

from libimobiledevice.libibackup import LocalBackup
import sys

backup = LocalBackup(sys.argv[1])

scanner = BackupScanner(backup)

for scanner_result in scanner.scan():
    print(scanner_result.title)

    for result in scanner_result.results:
        print("\t" + scanner_result.format_item(result))

    print("\n\n")
