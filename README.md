# iSafety
Toolset to examine iDevices for Security / Safety Threats.

## Pre-requsites

* only tested on macOS - but should work on linux
* `libibackup` from https://github.com/rickmark/libibackup
* OpenSSL from homebrew (`brew install openssl`)
* un-encrypted backup from an iPhone
* Python 3
* pip / pipenv

## Usage - Scanning a Backup

* `pipenv install`
* `./scan_backup.py <path_to_backup_directory>`