import multiprocessing
import socket
import tempfile
import unittest
from pathlib import Path
from ldaps_ipc_persistent_identity import IdentityPinError
from ldaps_two_host_observation import collect_local, ObservationRegistry

def worker(path, obs, queue):
    try: ObservationRegistry(path).register(obs); queue.put('OK')
    except IdentityPinError: queue.put('REPLAY')

class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'observations.db'
        self.f=Path(self.temp.name)/'evidence.txt'; self.f.write_text('technical-evidence')
        self.obs=collect_local(host='source',run_id='run-1887',incident_id='INC-1',scenario='restart',probe=('file_sha256',str(self.f)))
    def test_hash_observation(self): self.assertEqual(len(self.obs['result']),64)
    def test_review_only(self):
        r=ObservationRegistry(self.path).register(self.obs)
        self.assertFalse(r['cutover_authorized']); self.assertTrue(r['manual_review_required'])
    def test_replay(self):
        ObservationRegistry(self.path).register(self.obs)
        with self.assertRaises(IdentityPinError): ObservationRegistry(self.path).register(self.obs)
    def test_unsafe_claim(self):
        self.obs['cutover_authorized']=True
        with self.assertRaises(IdentityPinError): ObservationRegistry(self.path).register(self.obs)
    def test_unknown_field(self):
        self.obs['unexpected']=1
        with self.assertRaises(IdentityPinError): ObservationRegistry(self.path).register(self.obs)
    def test_symlink_refused(self):
        link=Path(self.temp.name)/'link'; link.symlink_to(self.f)
        with self.assertRaises(IdentityPinError): collect_local(host='source',run_id='r',incident_id='i',scenario='s',probe=('file_sha256',str(link)))
    def test_relative_path_refused(self):
        with self.assertRaises(IdentityPinError): collect_local(host='source',run_id='r',incident_id='i',scenario='s',probe=('file_sha256','foo'))
    def test_file_too_large(self):
        self.f.write_bytes(b'x'*(1024*1024+1))
        with self.assertRaises(IdentityPinError): collect_local(host='source',run_id='r',incident_id='i',scenario='s',probe=('file_sha256',str(self.f)))
    def test_invalid_timeout(self):
        with self.assertRaises(IdentityPinError): collect_local(host='source',run_id='r',incident_id='i',scenario='s',probe=('tcp','localhost',80),timeout=0)
    def test_invalid_port(self):
        with self.assertRaises(IdentityPinError): collect_local(host='source',run_id='r',incident_id='i',scenario='s',probe=('tcp','localhost',0))
    def test_tcp_connected(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1',0)); s.listen(1)
            r=collect_local(host='source',run_id='r',incident_id='i',scenario='s',probe=('tcp','127.0.0.1',s.getsockname()[1]))
            self.assertEqual(r['result'],'CONNECTED')
    def test_tcp_unavailable(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
        r=collect_local(host='source',run_id='r',incident_id='i',scenario='s',probe=('tcp','127.0.0.1',port))
        self.assertEqual(r['result'],'UNAVAILABLE')
    def test_multiprocess_single_writer(self):
        ctx=multiprocessing.get_context('spawn'); q=ctx.Queue()
        ps=[ctx.Process(target=worker,args=(str(self.path),self.obs,q)) for _ in range(6)]
        for p in ps:p.start()
        for p in ps:p.join(12); self.assertEqual(p.exitcode,0)
        results=[q.get(timeout=2) for _ in ps]
        self.assertEqual(results.count('OK'),1); self.assertEqual(results.count('REPLAY'),5)
    def test_independent_hosts(self):
        ObservationRegistry(self.path).register(self.obs)
        self.obs['host']='witness'
        self.assertEqual(ObservationRegistry(self.path).register(self.obs)['status'],'OBSERVATION_RECORDED_REVIEW_REQUIRED')

if __name__=='__main__':unittest.main()
