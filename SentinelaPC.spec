# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[('app', 'app'), ('installer', 'installer')],
    hiddenimports=['app.services.analyzer_behavior', 'app.services.analyzer_browser', 'app.services.analyzer_context', 'app.services.analyzer_hash', 'app.services.analyzer_static', 'app.services.archive_inspector', 'app.services.behavior_monitor', 'app.services.edge_extension_service', 'app.services.network_intrusion_monitor', 'app.services.pre_execution_monitor', 'app.services.ransomware_behavior_monitor', 'app.services.reputation_service', 'app.services.risk_engine', 'app.services.script_pattern_analyzer', 'app.services.shortcut_analyzer', 'app.services.url_threat_service', 'app.services.usb_guard_monitor', 'app.services.virustotal_service', 'app.integration.antivirus_bridge'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='SentinelaPC',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='installer\\version-info.txt',
    icon=['app\\assets\\branding\\sentinelapc.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SentinelaPC',
)
