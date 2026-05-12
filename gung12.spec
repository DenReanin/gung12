# -*- mode: python ; coding: utf-8 -*-
"""
Configuración de PyInstaller para Gung12.

Construye un ejecutable autocontenido que incluye Playwright. Los binarios
de Chromium no se empaquetan dentro del ejecutable (pesan ~280 MB y tienen
estructura de directorios incompatible con PyInstaller), pero Playwright
los descargará automáticamente al primer uso de `--spa` cacheándolos en
el directorio del usuario:
    Windows: %USERPROFILE%\\AppData\\Local\\ms-playwright
    Linux:   ~/.cache/ms-playwright
    macOS:   ~/Library/Caches/ms-playwright

Uso:
    pyinstaller gung12.spec --clean --noconfirm
    # produce dist/gung12.exe (Windows) o dist/gung12 (Linux/macOS)
"""

from PyInstaller.utils.hooks import collect_all

block_cipher = None

# Playwright se incluye completamente (Python + datos auxiliares).
# Los navegadores en sí no se empaquetan, se descargan al primer uso.
pw_datas, pw_binaries, pw_hiddenimports = collect_all("playwright")

# Hidden imports adicionales: módulos cargados dinámicamente que
# PyInstaller no detecta por importaciones estáticas.
hiddenimports = pw_hiddenimports + [
    "gung12.payloads.xss",
    "gung12.payloads.sqli",
    "gung12.payloads.ssti",
    "gung12.payloads.xpath",
    "gung12.payloads.cmdi",
    "gung12.payloads.nosql",
    "gung12.payloads.xxe",
    "gung12.payloads.csrf",
    "gung12.payloads.file_upload",
    "gung12.payloads.open_redirect",
    "gung12.payloads.htmli",
    "gung12.payloads.logic",
    "gung12.auth",
    "gung12.waf_bypass",
    "gung12.ai_analyzer",
    "gung12.spa_parser",
]

a = Analysis(
    ["gung12/__main__.py"],
    pathex=[],
    binaries=pw_binaries,
    datas=pw_datas,
    hiddenimports=hiddenimports,
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
    name="gung12",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
