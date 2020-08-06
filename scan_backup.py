#!/usr/bin/env python

from backup.libibackup import LocalBackup
import sys

backup = LocalBackup(sys.argv[1])

for domain in backup.domains():
    print(domain)