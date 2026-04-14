# cascade.spec — PyInstaller build for Windows standalone .exe
#
# Build:
#   pip install pyinstaller
#   pyinstaller cascade.spec
#
# Output: dist/cascade.exe  (~80-120 MB, no Python install needed)

block_cipher = None

a = Analysis(
    ['cascade/__main__.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'paramiko',
        'paramiko.transport',
        'paramiko.auth_handler',
        'cryptography',
        'cascade',
        'cascade._attack_main',
        'cascade_cracker',
        'cascade_cracker.cracker',
        'cascade_cracker.doctor',
        'cascade_cracker.config',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='cascade',
    debug=False,
    strip=False,
    upx=True,
    console=True,   # keep console window — this is a CLI tool
    icon=None,
)
