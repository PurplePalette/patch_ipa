# patch_ipa

```
poetry install
poetry shell
python patch.py <ipa file> -c FridaGadget.config --override-info-plist override_info.plist.json
```

## Features
- Inject FridaGadget.dylib to ipa
  - Inject FridaGadget.config to ipa
- Inject Ellekit to ipa
- Inject other dylibs to ipa
- Modify Info.plist
