# Inject Frida, CydiaSubstrate, Tweak to ipa
```
poetry install
poetry shell
python patch.py <ipa file> -c FridaGadget.config --override-info-plist override_info.plist.json
```