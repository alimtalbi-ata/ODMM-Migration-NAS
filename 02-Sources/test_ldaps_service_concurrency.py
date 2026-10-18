import multiprocessing as mp
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from ldaps_service_concurrency import InterprocessServiceGate,ServiceConcurrencyError

def _hold(path,ready,release):
    with InterprocessServiceGate(path,timeout=1).exclusive():
        ready.set()
        release.wait(5)

def _crash(path,ready):
    with InterprocessServiceGate(path,timeout=1).exclusive():
        ready.set()
        import os
        os._exit(19)

class InterprocessGateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=str(Path(self.temp.name)/'service-lock.sqlite')
        self.ctx=mp.get_context('spawn')
    def test_basic_acquire(self):
        with InterprocessServiceGate(self.path).exclusive():pass
    def test_reacquire(self):
        for _ in range(3):
            with InterprocessServiceGate(self.path).exclusive():pass
    def test_rollback_after_exception(self):
        with self.assertRaisesRegex(ValueError,'stop'):
            with InterprocessServiceGate(self.path).exclusive():raise ValueError('stop')
        with InterprocessServiceGate(self.path).exclusive():pass
    def test_missing_parent_denied(self):
        with self.assertRaisesRegex(ServiceConcurrencyError,'DIRECTORY'):
            InterprocessServiceGate(self.path+'/missing/gate')
    def test_invalid_timeout_denied(self):
        with self.assertRaisesRegex(ServiceConcurrencyError,'TIMEOUT'):
            InterprocessServiceGate(self.path,timeout=-1)
    def test_nested_busy(self):
        with InterprocessServiceGate(self.path,timeout=0.01).exclusive():
            with self.assertRaisesRegex(ServiceConcurrencyError,'BUSY'):
                with InterprocessServiceGate(self.path,timeout=0.01).exclusive():pass
    def test_multiprocess_contention(self):
        ready=self.ctx.Event();release=self.ctx.Event()
        p=self.ctx.Process(target=_hold,args=(self.path,ready,release))
        p.start()
        try:
            self.assertTrue(ready.wait(8))
            with self.assertRaisesRegex(ServiceConcurrencyError,'BUSY'):
                with InterprocessServiceGate(self.path,timeout=0.05).exclusive():pass
        finally:
            release.set();p.join(8)
            if p.is_alive():p.terminate();p.join()
        self.assertEqual(p.exitcode,0)
        with InterprocessServiceGate(self.path).exclusive():pass
    def test_crash_releases_gate(self):
        ready=self.ctx.Event();p=self.ctx.Process(target=_crash,args=(self.path,ready))
        p.start()
        try:self.assertTrue(ready.wait(8))
        finally:
            p.join(8)
            if p.is_alive():p.terminate();p.join()
        self.assertEqual(p.exitcode,19)
        with InterprocessServiceGate(self.path).exclusive():pass
    def test_separate_paths(self):
        with InterprocessServiceGate(self.path).exclusive():
            with InterprocessServiceGate(self.path+'.other').exclusive():pass
