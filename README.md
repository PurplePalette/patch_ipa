# patch\_ipa

```
poetry install
poetry shell
python patch.py <ipa file> -c FridaGadget.config --override-info-plist override_info.plist.json
```

## Features

* Inject FridaGadget.dylib to ipa
  * Inject FridaGadget.config to ipa
* Inject Ellekit to ipa
* Inject other dylibs to ipa
* Modify Info.plist

## Libraries/\*

Please put the dylib you want to add here.

## Note

About Libraries/libfaketouch.dylib\
This is a library for dynamically generating touch from the outside.\
Please delete it if it is not needed.
