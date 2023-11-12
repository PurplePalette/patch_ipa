# patch\_ipa

## Features

* Inject FridaGadget.dylib to ipa
  * Inject FridaGadget.config to ipa
* Inject Ellekit to ipa
* Inject other dylibs to ipa
* Modify Info.plist

## Install

```
poetry install
```

## Usage

```
usage: patch.py [-h] [-c CONFIG] [--override-info-plist OVERRIDE_INFO_PLIST] [--dump-info-plist DUMP_INFO_PLIST] file

Patch a file

positional arguments:
  file                  file to patch

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        FridaGadget.config
  --override-info-plist OVERRIDE_INFO_PLIST
                        override key and value for Info.plist(json file)
  --dump-info-plist DUMP_INFO_PLIST
                        dump Info.plist
```

## Libraries/\*

Please put the dylib you want to add here.

## Note

About Libraries/libfaketouch.dylib\
This is a library for dynamically generating touch from the outside.\
Please delete it if it is not needed.
