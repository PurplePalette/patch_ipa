import argparse
import json
import lzma
import os
import plistlib
import shutil
import zipfile
from pathlib import Path

import lief
import requests


def get_app_name(package_path: Path) -> str:
    apps = list(
        filter(lambda x: x.endswith(".app"), os.listdir(package_path / "Payload"))
    )
    return apps[0]


def wget(path: Path, url: str) -> None:
    response = requests.request(method="GET", url=url, stream=True)
    with open(path, mode="wb") as file:
        for data in response.iter_content(chunk_size=1024):
            file.write(data)


def download_frida(package_path: Path, gadget_name: str = "FridaGadget.dylib") -> None:
    GADGET_VER = "16.1.4"
    ARCH = "universal"
    GADGET = f"frida-gadget-{GADGET_VER}-ios-{ARCH}.dylib.xz"
    app_name = get_app_name(package_path)

    frida_cache_path = Path.home() / ".patch_ipa/frida"
    os.makedirs(frida_cache_path, exist_ok=True)
    # check cache
    if not os.path.exists(frida_cache_path / GADGET):
        print("Downloading Frida Gadget to", frida_cache_path)
        wget(
            frida_cache_path / GADGET,
            url=f"https://github.com/frida/frida/releases/download/{GADGET_VER}/{GADGET}",
        )
    else:
        print("Frida Gadget cached in", frida_cache_path)
    with lzma.open(frida_cache_path / GADGET) as file:
        with open(
            package_path / "Payload" / app_name / "Frameworks" / gadget_name,
            mode="wb",
        ) as out:
            out.write(file.read())
    print("Frida downloaded!")


def inject_frida(package_path: Path, gadget_name: str = "FridaGadget.dylib") -> None:
    print("Injecting Frida Gadget...")
    app_name = get_app_name(package_path)
    app_binary = app_name.split(".")[0]
    print("App binary: " + app_binary)

    binary_path = package_path / "Payload" / app_name / app_binary
    gadget_path = f"@executable_path/Frameworks/{gadget_name}"
    app = lief.parse(str(binary_path))
    app.add_library(str(gadget_path))
    app.write(str(binary_path))
    print("Frida injected!")


def copy_config(
    package_path: Path, config_path: Path, gadget_name: str = "FridaGadget.dylib"
) -> None:
    print("Copying config...")
    app_name = get_app_name(package_path)
    config_name = gadget_name.split(".")[0] + ".config"

    shutil.copy(
        config_path,
        package_path / "Payload" / app_name / "Frameworks" / config_name,
    )
    print("Config copied!")


def inject_cydia_substrate(package_path: Path) -> None:
    print("Injecting Cydia Substrate...")
    app_name = get_app_name(package_path)
    app_binary = app_name.split(".")[0]

    os.makedirs(
        package_path / "Payload" / app_name / "Frameworks" / "CydiaSubstrate.framework",
        exist_ok=True,
    )

    shutil.copy(
        "Frameworks/libellekit.dylib",
        package_path
        / "Payload"
        / app_name
        / "Frameworks"
        / "CydiaSubstrate.framework"
        / "CydiaSubstrate",
    )

    binary_path = package_path / "Payload" / app_name / app_binary
    app = lief.parse(str(binary_path))
    app.add_library(
        "@executable_path/Frameworks/CydiaSubstrate.framework/CydiaSubstrate"
    )
    app.write(str(binary_path))
    print("Cydia Substrate injected!")


def inject_libraries(package_path: Path) -> None:
    print("Injecting libraries...")
    app_name = get_app_name(package_path)
    app_binary = app_name.split(".")[0]

    binary_path = package_path / "Payload" / app_name / app_binary
    libraries = os.listdir("Libraries")
    app = lief.parse(str(binary_path))
    for library in libraries:
        if library.endswith(".dylib"):
            shutil.copy(
                "Libraries/" + library,
                package_path / "Payload" / app_name / "Frameworks",
            )
            app.add_library(f"@executable_path/Frameworks/{library}")
    app.write(str(binary_path))
    print("Libraries injected!")


def edit_info_plist(package_path: Path, override_info_plist: Path) -> None:
    print("Editing Info.plist...")
    app_name = get_app_name(package_path)
    info_plist = package_path / "Payload" / app_name / "Info.plist"
    with open(info_plist, mode="rb") as file:
        info = plistlib.load(file)
    with open(override_info_plist, mode="r") as file:
        json_data = json.load(file)
    for key, value in json_data.items():
        info[key] = value
    with open(info_plist, mode="wb") as file:
        plistlib.dump(info, file)
    print("Info.plist edited!")


def repackage_ipa(package_path: Path) -> None:
    print("Repackaging...")
    shutil.make_archive(str(package_path) + "_patched.ipa", "zip", package_path)
    os.rename(
        str(package_path) + "_patched.ipa.zip", str(package_path) + "_patched.ipa"
    )
    print("Repackaged!")


def dump_info_plist(ipa_file_path: Path) -> None:
    print("Dumping Info.plist...")
    with zipfile.ZipFile(ipa_file_path, "r") as zip_ref:
        generator = (
            name for name in zip_ref.namelist() if name.endswith(".app/Info.plist")
        )
        plist_path = next(generator, None)
        with zip_ref.open(plist_path) as file:
            info = plistlib.load(file)
        with open(args.dump_info_plist, mode="w", encoding="utf-8") as file:
            json.dump(info, file, indent=4, ensure_ascii=False)
    print("Dumped!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Patch a file")
    parser.add_argument("file", help="file to patch")
    parser.add_argument("-c", "--config", help="FridaGadget.config")
    parser.add_argument(
        "--override-info-plist", help="override key and value for Info.plist(json file)"
    )
    parser.add_argument("--dump-info-plist", help="dump Info.plist")
    args = parser.parse_args()

    if args.dump_info_plist:
        dump_info_plist(Path(args.file))
        exit(0)

    print("Patching file: " + args.file)

    # unpack
    package_path = Path(args.file.rstrip(".ipa"))
    shutil.unpack_archive(args.file, package_path, "zip")

    # download and inject frida
    download_frida(package_path)
    inject_frida(package_path)
    # copy config
    if args.config:
        copy_config(package_path, Path(args.config))

    # inject cydia substrate
    inject_cydia_substrate(package_path)
    # inject other libraries
    inject_libraries(package_path)

    # edit info.plist
    if args.override_info_plist:
        edit_info_plist(package_path, args.override_info_plist)

    # repack
    repackage_ipa(package_path)

    # clean up
    shutil.rmtree(package_path)
