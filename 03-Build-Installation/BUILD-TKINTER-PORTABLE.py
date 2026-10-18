"""Build the Windows portable executable with explicitly bundled Tcl/Tk runtime data."""
from pathlib import Path
import subprocess
import sys
import tkinter
import _tkinter


def main():
    if len(sys.argv) != 5:
        raise SystemExit("Usage: BUILD-TKINTER-PORTABLE.py entry.py source_dir dist_dir work_dir")
    entry, source, dist, work = map(lambda p: Path(p).resolve(), sys.argv[1:])
    interpreter = tkinter.Tcl()
    tcl_library = Path(interpreter.eval("info library")).resolve()
    tk_library = tcl_library.parent / f"tk{_tkinter.TK_VERSION}"
    if not tk_library.is_dir():
        candidates = sorted(tcl_library.parent.glob("tk8.*"))
        if not candidates:
            raise RuntimeError(f"Tk data missing next to Tcl data: {tcl_library}")
        tk_library = candidates[-1]
    for directory, required in ((tcl_library, "init.tcl"), (tk_library, "tk.tcl")):
        if not (directory / required).is_file():
            raise RuntimeError(f"Missing {required} in {directory}")
    args = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--onefile", "--windowed", "--name", "ODMM-Compact",
        "--distpath", str(dist), "--workpath", str(work),
        "--specpath", str(work), "--paths", str(source),
        "--add-data", f"{tcl_library}{';'}_tcl_data",
        "--add-data", f"{tk_library}{';'}_tk_data",
        str(entry),
    ]
    print(f"Bundling Tcl: {tcl_library}", flush=True)
    print(f"Bundling Tk: {tk_library}", flush=True)
    subprocess.run(args, check=True)


if __name__ == "__main__":
    main()
