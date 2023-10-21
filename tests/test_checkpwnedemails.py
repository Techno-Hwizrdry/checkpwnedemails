import unittest
import sys
sys.path.insert(1, "..")
import checkpwnedemails as cpe

TEST_EMAIL = 'account-exists@hibp-integration-tests.com'

class Args():
    def __init__(self, names_only=True, only_pwned=False):
        self.names_only = names_only
        self.only_pwned = only_pwned

class TestCheckPwnedEmails(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = cpe.read_config_file('../checkpwnedemails.conf')

    def test_read_config_file_success(self):
        cfg = cpe.read_config_file('../checkpwnedemails.conf')
        for val in cfg.values():
            self.assertEqual(bool(val), True)

    def test_read_config_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            cfg = cpe.read_config_file('thisfiledoesnotexist.conf')

    def test_clean_list(self):
        input_list = [
            '\n  Holy     ',
            '           whitespace     \t',
            '\t  Batman!  \n'
        ]
        expected = ['Holy', 'whitespace', 'Batman!']
        self.assertEqual(cpe.clean_list(input_list), expected)

    def test_clean_and_encode(self):
        input_list = [ u'Holy', 'unicode, ', u'Batman!']
        expected = ['Holy', 'unicode, ', 'Batman!']
        self.assertEqual(cpe.clean_and_encode(input_list), expected)

    def test_get_results_breaches(self):
        opts = Args(names_only=False, only_pwned=False)
        emails = tuple([TEST_EMAIL])
        i = cpe.get_results(emails, cpe.BREACHED, opts, self.config)
        self.assertEqual(True, i[0][1])
        self.assertGreater(len(i[0][2]), 0)

    def test_get_results_breach_names_only(self):
        opts = Args()
        emails = tuple([TEST_EMAIL])
        i = cpe.get_results(emails, cpe.BREACHED, opts, self.config)
        expected = [
            (
                'account-exists@hibp-integration-tests.com',
                True,
                [{'Name': 'Adobe'}]
            )
        ]
        self.assertEqual(i, expected)

if __name__ == '__main__':
    unittest.main()