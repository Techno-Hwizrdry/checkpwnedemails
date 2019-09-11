__author__  = "Alexan Mardigian"
__version__ = "1.2"

from argparse import ArgumentParser
from time     import sleep

import json
import sys
import traceback
import urllib
import urllib2


PWNED_API_URL = "https://haveibeenpwned.com/api/v3/%s/%s?truncateResponse=%s"
HEADERS = {
           "User-Agent": "checkpwnedemails",
           "hibp-api-key": "",
}

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

	parser.add_argument('-a', dest='apikey_path',  help='Path to text file that contains your HIBP API key.')
	parser.add_argument('-b', action="store_true", dest='only_breaches', help='Return results for breaches only.')
	parser.add_argument('-i', dest='input_path',   help='Path to text file that lists email addresses.')
	parser.add_argument('-n', action="store_true", dest='names_only', help='Return the name of the breach(es) only.')
	parser.add_argument('-o', dest='output_path',  help='Path to output (tab deliminated) text file.')
	parser.add_argument('-p', action="store_true", dest='only_pwned', help='Print only the pwned email addresses.')
	parser.add_argument('-s', dest="single_email", help='Send query for just one email address.')
	parser.add_argument('-t', action="store_true", dest='only_pastebins', help='Return results for pastebins only.')

	if len(sys.argv) == 1:  # If no arguments were provided, then print help and exit.
		parser.print_help()
		sys.exit(1)

	return parser.parse_args()

#  Used for removing the trailing '\n' character on each email.
def clean_list(list_of_strings):
	return [str(x).strip() for x in list_of_strings]

def get_results(email_list, service, opts, hibp_api_key):
	results = []  # list of tuples (email adress, been pwned?, json data)

	for email in email_list:
		email = email.strip()
		data = []
		names_only = "true" if opts.names_only else "false"
		req = urllib2.Request(PWNED_API_URL % (urllib.quote(service), urllib.quote(email), urllib.quote(names_only)), headers=HEADERS)

		try:
			response = urllib2.urlopen(req)  # This is a json object.
			data     = json.loads(response.read())
			results.append( (email, True, data) )
		except urllib2.HTTPError as e:
			if e.code == 400:
				print "%s does not appear to be a valid email address.  HTTP Error 400." % (email)
			if e.code == 401:
				print "Unauthorised - the API key provided (%s) was not valid." % (hibp_api_key)
			if e.code == 403:
				print "Forbidden - no user agent has been specified in the request.  HTTP Error 403."
			if e.code == 404 and not opts.only_pwned:
				results.append( (email, False, data) )
			if e.code == 429:
				print "Too many requests; going over the request rate limit.  HTTP Error 429."
			if e.code == 503:
				print "Service unavailable."

		sleep(1.6)  # This 1.6 second delay is for rate limiting.

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

#  This function will convert every item, in dlist, into a string and
#  encode any unicode strings into an 8-bit string.
def clean_and_encode(dlist):
	cleaned_list = []

	for d in dlist:
		try:
			cleaned_list.append(str(d))
		except UnicodeEncodeError:
			cleaned_list.append(str(d.encode('utf-8')))  # Clean the data.

	return cleaned_list

def tab_delimited_string(data):
	DATACLASSES = 'DataClasses'

	begining_sub_str = data[EMAILINDEX] + '\t' + str(data[PWNEDINDEX])
	output_list      = []

	if data[DATAINDEX]:
		for bp in data[DATAINDEX]:  # bp stands for breaches/pastbins
			d = bp
			
			try:
				flat_data_classes = [str(x) for x in d[DATACLASSES]]
				d[DATACLASSES]    = flat_data_classes
			except KeyError:
				pass  #  Not processing a string for a breach.

			flat_d = clean_and_encode(d.values())
			output_list.append(begining_sub_str + '\t' + "\t".join(flat_d))
	else:
		output_list.append(begining_sub_str)

	return '\n'.join(output_list)

def write_results_to_file(filename, results, opts):
	BREACHESTXT = "_breaches.txt"
	PASTESTXT   = "_pastes.txt"
	files = []

	file_headers = {
			BREACHESTXT: "Email Address\tIs Pwned\tPwn Count\tDomain\tName\tTitle\tData Classes\tLogo Type\tBreach Date\tAdded Date\tIs Verified\tDescription",
			PASTESTXT:   "Email Address\tIs Pwned\tDate\tSource\tEmail Count\tID\tTitle",
	}

	if opts.only_breaches:
		files.append(BREACHESTXT)
	elif opts.only_pastebins:
		files.append(PASTESTXT)
	else:
		files.append(BREACHESTXT)
		files.append(PASTESTXT)

	if filename.rfind('.') > -1:
		filename = filename[:filename.rfind('.')]

	for res, f in zip(results, files):
		outfile = open(filename + f, 'w')

		outfile.write(file_headers[f] + '\n')

		for r in res:
			outfile.write(tab_delimited_string(r) + '\n')

		outfile.close()

def main():
	hibp_api_key = ""
	email_list = []
	opts = get_args()

	if not opts.apikey_path:
		print "\nThe path to the file containing the HaveIBeenPwned API key was not found."
		print "Please provide the file path with the -a switch and try again.\n"
		sys.exit(1)
	else:
		try:
			with open(opts.apikey_path) as apikey_file:
				hibp_api_key = apikey_file.readline().strip()
				HEADERS["hibp-api-key"] = hibp_api_key
		except IOError:
			print "\nCould not read file:", opts.apikey_path
			print "Check if the file path is valid, and try again.\n"
			sys.exit(1)

	if opts.single_email:
		email_list = [opts.single_email]
	else:
		email_list_file = open(opts.input_path, 'r')
		email_list      = clean_list(email_list_file.readlines())
		email_list_file.close()

	results = []

	if opts.only_breaches:
		results.append(get_results(email_list, BREACHED, opts, hibp_api_key))
	elif opts.only_pastebins:
		results.append(get_results(email_list, PASTEBIN, opts, hibp_api_key))
	else:
		results.append(get_results(email_list, BREACHED, opts, hibp_api_key))
		results.append(get_results(email_list, PASTEBIN, opts, hibp_api_key))

	if opts.output_path:
		write_results_to_file(opts.output_path, results, opts)


if __name__ == '__main__':
	main()
