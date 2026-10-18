import importlib.util, tempfile, unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('experiment',Path(__file__).with_name('sqlite_experiment_v22848.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ExperimentTests(unittest.TestCase):
    def test_both_modes(self):
        r=m.run(3)
        self.assertEqual([x['mode'] for x in r['results']],['baseline','returning'])
        self.assertTrue(all(x['iterations']==3 for x in r['results']))
    def test_bad_mode(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):m.trial(Path(d)/'x.db',mode='bad')
    def test_bad_iterations(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):m.trial(Path(d)/'x.db',mode='baseline',repetitions=0)
if __name__=='__main__':unittest.main()
