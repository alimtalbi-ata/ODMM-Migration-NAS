"""Conservative recovery: never restore an unverified backup."""
from pathlib import Path
import importlib.util, shutil, sys

def _validate(folder):
    spec=importlib.util.spec_from_file_location('odmm_release_validation',Path(__file__).with_name('VALIDATE-WINDOWS-RELEASE.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.validate(folder)

def recover(destination):
    destination=Path(destination)
    candidate=destination.with_name(destination.name+'.next')
    backup=destination.with_name(destination.name+'.previous')
    if destination.exists():
        if (destination/'BUILD-STATUS.json').exists():
            _validate(destination)
        if candidate.exists(): shutil.rmtree(candidate)
        return 'active release retained'
    if backup.exists():
        _validate(backup)
        backup.rename(destination)
        if candidate.exists(): shutil.rmtree(candidate)
        return 'verified previous release restored'
    if candidate.exists():
        raise RuntimeError('Orphan candidate without prior release: manual verification required')
    return 'no prior release'

if __name__=='__main__': print(recover(sys.argv[1]))
