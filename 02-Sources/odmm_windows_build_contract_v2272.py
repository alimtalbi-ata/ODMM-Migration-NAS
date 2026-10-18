"""Static release gate for Windows build inputs; does not pretend to compile Windows binaries."""
from pathlib import Path
import ast
import re


def audit(root):
    root=Path(root)
    script=root/'BUILD-WINDOWS-V2272.cmd'
    desktop=root/'odmm_windows_desktop_v2272.py'
    setup=root/'ODMM-WINDOWS-V2272.iss'
    errors=[]
    if not all(p.is_file() for p in (script,desktop,setup)):
        return ['MISSING_RELEASE_INPUT']
    cmd=script.read_text(encoding='utf-8')
    imports=re.findall(r'--hidden-import\s+([A-Za-z_][A-Za-z_0-9.]*)',cmd)
    for module in imports:
        if not (root/(module.replace('.', '/')+'.py')).is_file() and not (root/module.replace('.', '/')/'__init__.py').is_file():
            errors.append('MISSING_HIDDEN_IMPORT:'+module)
    if not imports: errors.append('NO_HIDDEN_IMPORTS')
    tree=ast.parse(desktop.read_text(encoding='utf-8'))
    local=[]
    for node in ast.walk(tree):
        if isinstance(node,ast.ImportFrom) and node.module and node.module.startswith('odmm_'):
            local.append(node.module)
    for module in local:
        if not (root/(module+'.py')).is_file(): errors.append('MISSING_DESKTOP_DEPENDENCY:'+module)
    if 'odmm_windows_desktop_v2272.py' not in cmd: errors.append('WRONG_ENTRYPOINT')
    if 'ODMM-WINDOWS-V2272.iss' not in cmd: errors.append('WRONG_INSTALLER_SCRIPT')
    if 'dist\\ODMM-Setup-V227.2.exe' not in cmd: errors.append('WRONG_INSTALLER_OUTPUT')
    iss=setup.read_text(encoding='utf-8')
    if 'OutputBaseFilename=ODMM-Setup-V227.2' not in iss: errors.append('WRONG_INNO_OUTPUT')
    return errors

if __name__=='__main__':
    import sys
    problems=audit(sys.argv[1] if len(sys.argv)>1 else '.')
    print('PASS' if not problems else '\n'.join(problems))
    raise SystemExit(bool(problems))
