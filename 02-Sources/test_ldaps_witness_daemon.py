import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ldaps_witness_daemon import DeploymentError, load_config, secure_file, serve

class DaemonConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        for name in ('cert','key','ca','hmac'):
            p=self.root/name;p.write_bytes(b'x'*40);p.chmod(0o600)
        self.cfg={'host':'127.0.0.1','port':9443,'db_path':str(self.root/'witness.db'),'certfile':str(self.root/'cert'),'keyfile':str(self.root/'key'),'cafile':str(self.root/'ca'),'hmac_key_file':str(self.root/'hmac')}
        self.write()
    def write(self):
        self.path=self.root/'config.json';self.path.write_text(json.dumps(self.cfg));self.path.chmod(0o600)
    def test_valid(self):self.assertEqual(load_config(self.path)[1],b'x'*40)
    def test_secret_world_readable(self):
        (self.root/'hmac').chmod(0o644)
        with self.assertRaises(DeploymentError):load_config(self.path)
    def test_config_world_readable(self):
        self.path.chmod(0o644)
        with self.assertRaises(DeploymentError):load_config(self.path)
    def test_config_symlink(self):
        p=self.root/'link';p.symlink_to(self.path)
        with self.assertRaises(DeploymentError):load_config(p)
    def test_key_symlink(self):
        (self.root/'key').rename(self.root/'original');(self.root/'key').symlink_to(self.root/'original')
        with self.assertRaises(DeploymentError):load_config(self.path)
    def test_wrong_schema(self):
        self.cfg['extra']=1;self.write()
        with self.assertRaises(DeploymentError):load_config(self.path)
    def test_bool_port(self):
        self.cfg['port']=True;self.write()
        with self.assertRaises(DeploymentError):load_config(self.path)
    def test_invalid_port(self):
        self.cfg['port']=70000;self.write()
        with self.assertRaises(DeploymentError):load_config(self.path)
    def test_short_key(self):
        (self.root/'hmac').write_bytes(b'a'*16)
        with self.assertRaises(DeploymentError):load_config(self.path)
    def test_db_symlink(self):
        (self.root/'witness.db').symlink_to(self.root/'cert')
        with self.assertRaises(DeploymentError):load_config(self.path)
    def test_world_writable_cert(self):
        (self.root/'cert').chmod(0o666)
        with self.assertRaises(DeploymentError):load_config(self.path)
    def test_root_refused(self):
        with patch('ldaps_witness_daemon.os.geteuid',return_value=0):
            with self.assertRaises(DeploymentError):serve(self.path)
    def test_unit_read_only_network(self):
        unit=(Path(__file__).parent/'deploy/debian13/odmm-witness.service').read_text()
        self.assertIn('NoNewPrivileges=yes',unit)
        self.assertIn('User=odmm-witness',unit)
        self.assertIn('ProtectSystem=strict',unit)
        self.assertNotIn('ExecStartPre=/bin/chmod',unit)

if __name__=='__main__':unittest.main()
