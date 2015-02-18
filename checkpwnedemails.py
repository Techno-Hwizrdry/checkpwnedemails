__author__  = "Alexan Mardigian"
__version__ = "0.1.0"

from argparse import ArgumentParser

import json
import sys
import traceback
import urllib
import urllib2

PWNED_API_URL = "https://haveibeenpwned.com/api/v2/%s/%s"

EMAILINDEX = 0
PWNEDINDEX = 1
DATAINDEX  = 2

BREACHED = "breachedaccount"
PASTEBIN = "pasteaccount"

class PwnedArgParser(ArgumentParser):
	def error(self, message):
		sys.stderr.write('error: %s\n' %message)
		self.print_help()
		sys.exit(2)

def get_args():
	parser = PwnedArgParser()

	parser.add_argument('-b', action="store_true", dest='only_breaches', help='Return results for breaches only.')
	parser.add_argument('-i', dest='input_path',   help='Path to text file that lists email addresses.')
	parser.add_argument('-o', dest='output_path',  help='Path to output (tab deliminated) text file.')
        parser.add_argument('-p', action="store_true", dest='only_pwned', help='Print only the pwned email addresses.')
        parser.add_argument('-s', dest="single_email", help='Send query for just one email address.')
        parser.add_argument('-t', action="store_true", dest='only_pastebins', help='Return results for pastebins only.')

	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(1)

	return parser.parse_args()

#  Used for removing the trailing '\n' character on each email.
def clean_list(list_of_strings):
	return [str(x).strip() for x in list_of_strings]

def get_results(email_list, service, opts):
	results = []  # list of tuples (email adress, been pwned?, json data)

	for email in email_list:
		data = []
                req  = urllib2.Request(PWNED_API_URL % (urllib.quote(service), urllib.quote(email)))

                try:
                	response = urllib2.urlopen(req)  # This is a json object.
                        data     = json.loads(response.read())
			results.append( (email, True, data) )

                except urllib2.HTTPError as e:
                        if e.code == 400:
                                raise InvalidEmail("%s does not appear to be a valid email address.")
                        if e.code == 404 and not opts.only_pwned:
				results.append( (email, False, data) )

		if not opts.output_path:
			try:
				last_result = results[-1]

				if not last_result[PWNEDINDEX]:
					if service == BREACHED:
						print "Email address %s not pwned.  Yay!" % (email)
					else:
						print "Email address %s was not found in any pastes.  Yay!" %(email)
				elif data:
					print "\n%s pwned!\n==========" % (email)
					print json.dumps(data, indent=4)
					print '\n'

			except IndexError:
				pass

	return results

def tab_delimited_string(data):
	DATACLASSES = 'DataClasses'

	begining_sub_str = data[EMAILINDEX] + '\t' + str(data[PWNEDINDEX])
        tab_string       = ""

	if data[DATAINDEX]:
		for bp in data[DATAINDEX]:  # bp stands for breaches and pastbins
			d = bp
			flat_data_classes = [str(x) for x in d[DATACLASSES]]
			d[DATACLASSES]    = flat_data_classes

			flat_d     = [str(x) for x in d.values()]
			tab_string = tab_string + begining_sub_str + '\t' + tab_string + "\t".join(flat_d) + '\n'
	else:
		tab_string = begining_sub_str

	return tab_string.rstrip()

def write_results_to_file(filepath, results):
	outfile = open(filepath, 'w')

        for r in results:
		outfile.write(tab_delimited_string(r) + '\n')

        outfile.close()

def main():
	email_list = []
	opts = get_args()

	if opts.single_email:
		email_list = [opts.single_email]
	else:
		email_list_file = open(opts.input_path, 'r')
		email_list      = clean_list(email_list_file.readlines())

		email_list_file.close()

        results = None

        if opts.only_breaches:
		results = get_results(email_list, BREACHED, opts)
	elif opts.only_pastebins:
		results = get_results(email_list, PASTEBIN, opts)
	else:
		results = get_results(email_list, BREACHED, opts) + get_results(email_list, PASTEBIN, opts)

	if opts.output_path:
		write_results_to_file(opts.output_path, results)


if __name__ == '__main__':
	main()
