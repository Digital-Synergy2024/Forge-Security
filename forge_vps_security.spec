# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for FORGE/DB — onefile, windowed Windows executable.

Build via:  controller.bat   (recommended)
or directly:  pyinstaller --noconfirm forge_vps_security.spec
"""

from PyInstaller.utils.hooks import collect_all

block_cipher = None

# Bundle CustomTkinter's data files (themes, fonts) and submodules.
ctk_datas, ctk_binaries, ctk_hidden = collect_all("customtkinter")

a = Analysis(
    ["forge_vps_security.py"],
    pathex=[],
    binaries=ctk_binaries,
    datas=ctk_datas + [("assets", "assets")],
    hiddenimports=ctk_hidden + ["pymysql", "pymysql.cursors", "PIL", "PIL.Image"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="FORGE-DB",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,           # windowed (no console)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="assets/img/icon.ico",
)
