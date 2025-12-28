import os
import shutil
from glob import glob
from uuid import uuid4
from typing import Optional, Literal

from .executable import Executable
from .main_executable import MainExecutable
from .plist import Plist

class AppBundle:
  def __init__(self, path: str):
    self.path = path
    self.plist = Plist(f"{path}/Info.plist", path)

    self.executable = MainExecutable(
      f"{path}/{self.plist['CFBundleExecutable']}",
      path
    )

    self.cached_executables: Optional[list[str]] = None

  def remove(self, *names: str) -> bool:
    existed = False

    for name in names:
      if self.path in name:  # i do this in `remove_encrypted_extensions()`
        path = name
      else:
        path = f"{self.path}/{name}"

      if not os.path.exists(path):
        continue

      try:
        shutil.rmtree(path)
      except NotADirectoryError:
        os.remove(path)

      existed = True

    return existed

  def remove_watch_apps(self) -> None:
    if self.remove("Watch", "WatchKit", "com.apple.WatchPlaceholder"):
      print("[*] removed watch app")
    else:
      print("[?] watch app not present")

  def get_executables(self) -> list[str]:
    return sum((
        glob(f"{self.path}/**/*.dylib", recursive=True),
        glob(f"{self.path}/**/*.appex", recursive=True),
        glob(f"{self.path}/**/*.framework", recursive=True)
    ), [])  # type: ignore

  def get_all_appex(self) -> list[str]:
    return glob(f"{self.path}/Extensions/*.appex") + glob(f"{self.path}/PlugIns/*.appex")

  def mass_operate(self, op: str, func: Literal["fakesign", "thin"]) -> None:
    # this works since we call this after injecting
    if self.cached_executables is None:
      self.cached_executables = self.get_executables()

    if getattr(self.executable, func)():
      count = 1
    else:
      count = 0

    for ts in self.cached_executables:
      if ts.endswith(".dylib"):
        call = getattr(Executable(ts), func)()
      else:
        pl = Plist(f"{ts}/Info.plist")
        call = getattr(Executable(f"{ts}/{pl['CFBundleExecutable']}"), func)()

      if call:
        count += 1

    print(f"[*] {op} \033[96m{count}\033[0m item(s)")

  def fakesign_all(self) -> None:
    self.mass_operate("fakesigned", "fakesign")

  def thin_all(self) -> None:
    self.mass_operate("thinned", "thin")

  def remove_all_extensions(self) -> None:
    if self.remove("Extensions", "PlugIns"):
      print("[*] removed app extensions")
    else:
      print("[?] no app extensions")

  def remove_encrypted_extensions(self) -> None:
    removed: list[str] = []

    # a singular * is used to not detect watch apps
    for plugin in glob(f"{self.path}/*/*.appex"):
      bundle = AppBundle(plugin)
      if bundle.executable.is_encrypted():
        self.remove(plugin)
        removed.append(bundle.executable.bn)

    if len(removed) == 0:
      print("[?] no encrypted plugins")
    else:
      print("[*] removed encrypted plugins:", ", ".join(removed))

  def change_icon(self, path: str, tmpdir: str) -> None:
    try:
      from PIL import Image  # type: ignore
    except Exception:
      return print("[?] pillow is not installed, -k is not available")

    tmpath = f"{tmpdir}/icon.png"
    if not path.endswith(".png"):
      with Image.open(path) as img:
        img.save(tmpath, "PNG")
    else:
      shutil.copyfile(path, tmpath)

    uid = f"cyan_{uuid4().hex[:7]}a"  # can't have it end with a num
    i60 = f"{uid}60x60"
    i76 = f"{uid}76x76"

    with Image.open(tmpath) as img:
      img.resize((120, 120)).save(f"{self.path}/{i60}@2x.png", "PNG")
      img.resize((152, 152)).save(f"{self.path}/{i76}@2x~ipad.png", "PNG")

    if "CFBundleIcons" not in self.plist:
      self.plist["CFBundleIcons"] = {}
    if "CFBundleIcons~ipad" not in self.plist:
      self.plist["CFBundleIcons~ipad"] = {}

    self.plist["CFBundleIcons"] = self.plist["CFBundleIcons"] | {
      "CFBundlePrimaryIcon": {
        "CFBundleIconFiles": [i60],
        "CFBundleIconName": uid
      }
    }
    self.plist["CFBundleIcons~ipad"] = self.plist["CFBundleIcons~ipad"] | {
      "CFBundlePrimaryIcon": {
        "CFBundleIconFiles": [i60, i76],
        "CFBundleIconName": uid
      }
    }

    self.plist.save()
    print("[*] updated app icon")

  def _inject_into_extension(
    self,
    appex_path: str,
    tweaks: dict[str, str],
    inject_to_path: bool
  ) -> None:
    appex_name = os.path.basename(appex_path)

    try:
      ext_bundle = AppBundle(appex_path)
    except Exception:
      print(f"[?] skipping {appex_name}: couldn't read Info.plist")
      return

    if ext_bundle.executable.is_encrypted():
      print(f"[?] skipping {appex_name}: encrypted")
      return

    # Inject only dylibs (not frameworks, debs, or appex)
    dylibs_to_inject = {k: v for k, v in tweaks.items() if k.endswith(".dylib")}

    if not dylibs_to_inject:
      return

    # Save entitlements, remove signature, inject, then re-sign (same as main binary)
    ent_path = f"{appex_path}/cyan.entitlements"
    has_entitlements = ext_bundle.executable.write_entitlements(ent_path)
    ext_bundle.executable.remove_signature()

    # Inject load commands
    for dylib_name in dylibs_to_inject:
      if inject_to_path:
        # With -p: dylib is at app root (App.app/dylib.dylib)
        # Extension is at App.app/PlugIns/X.appex/ or App.app/Extensions/X.appex/
        # So we need to go up 2 levels: ../../dylib.dylib
        ext_bundle.executable.inj_func(f"@executable_path/../../{dylib_name}")
      else:
        # Without -p: dylib is in Frameworks/, use @rpath
        ext_bundle.executable.inj_func(f"@rpath/{dylib_name}")

    if ext_bundle.executable.inj is not None:
      ext_bundle.executable.inj.write(ext_bundle.executable.path)

    if has_entitlements:
      ext_bundle.executable.sign_with_entitlements(ent_path)

    print(f"[*] injected into extension: {appex_name}")

  def inject_all_extensions(
    self,
    tweaks: dict[str, str],
    tmpdir: str,
    inject_to_path: bool,
    inject_all: bool
  ) -> None:
    # First inject into main binary (existing behavior)
    self.executable.inject(tweaks, tmpdir, inject_to_path)

    if not inject_all:
      return

    # Then inject into all extensions
    appex_list = self.get_all_appex()
    if not appex_list:
      print("[?] no app extensions found for -a")
      return

    for appex_path in appex_list:
      self._inject_into_extension(appex_path, tweaks, inject_to_path)

