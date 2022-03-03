import unittest


class TestEbpf(unittest.TestCase):

    def test1(self):
        from efads.traffic_analyser.ebpf import EbpfAnalyser

if __name__ == '__main__':
    unittest.main()
