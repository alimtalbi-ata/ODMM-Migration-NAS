"""Conservative capability gates and bounded ACL tool execution. Not a sandbox."""
import os, shutil, subprocess

class PolicyError(RuntimeError): pass

CAPABILITIES = {
    "NFSv4": {"mount_types": ("nfs4", "nfs"), "tool": "nfs4_getfacl", "acl_semantics": "UNVERIFIED", "effective_access": False},
    "SMB": {"mount_types": ("cifs",), "tool": "getcifsacl", "acl_semantics": "UNVERIFIED", "effective_access": False},
}

def precheck(protocol, *, executable_lookup=shutil.which):
    if protocol not in CAPABILITIES: raise PolicyError("unsupported protocol")
    c=CAPABILITIES[protocol]
    executable=executable_lookup(c["tool"])
    if not executable or not os.path.isabs(executable):
        raise PolicyError("ACL collector executable unavailable or not absolute")
    return {"protocol":protocol,"tool":c["tool"],"executable":executable,
            "acl_semantics":c["acl_semantics"],"effective_access":False,
            "production_qualified":False}

def bounded_run(argv, *, timeout=20, max_output=4*1024*1024, popen_factory=subprocess.Popen):
    """POSIX collector limits. Not a sandbox; only invoke trusted executables."""
    import tempfile, signal, sys
    if not isinstance(argv, (list, tuple)) or len(argv) != 2 or not all(isinstance(x, str) for x in argv):
        raise PolicyError("invalid argv")
    if not os.path.isabs(argv[0]):
        raise PolicyError("executable must be absolute")
    if not (0 < timeout <= 60 and 0 < max_output <= 4*1024*1024):
        raise PolicyError("invalid limits")
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise PolicyError("resource-limited collector requires Linux")
    import resource
    def limit_child():
        # File size is enforced by the kernel on stdout/stderr temporary files.
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_output, max_output))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        cpu=max(1, int(timeout)+1)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu+1))
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc=popen_factory(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                               shell=False, close_fds=True, start_new_session=True,
                               preexec_fn=limit_child)
        except (OSError, ValueError) as exc:
            raise PolicyError("collector could not start") from exc
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait()
            raise PolicyError("collector timed out") from exc
        out.seek(0, os.SEEK_END); err.seek(0, os.SEEK_END)
        if out.tell() >= max_output or err.tell() >= max_output or proc.returncode in (-signal.SIGXFSZ, 128+signal.SIGXFSZ):
            raise PolicyError("collector output exceeded limit")
        out.seek(0); err.seek(0)
        return subprocess.CompletedProcess(argv, proc.returncode, out.read(), err.read())
