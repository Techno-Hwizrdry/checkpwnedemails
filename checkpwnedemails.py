__author__  = "Alexan Mardigian"
__version__ = "1.2.4"

from argparse import ArgumentParser
from os.path import exists
from time import sleep
import json
import requests
import sys

PWNED_API_URL = "https://haveibeenpwned.com/api/v3/%s/%s?truncateResponse=%s"

EMAILINDEX = 0
PWNEDINDEX = 1
DATAINDEX  = 2

BREACHED = "breachedaccount"
PASTEBIN = "pasteaccount"

RATE_LIMIT = 1.6  # in seconds

def get_args():
	parser = ArgumentParser()

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

#  This function will print the appropriate output string based on the
#  HTTP error code what was passed in. If an invalid HIBP API key was used
#  (error code 401), then checkpwnedemails.py should stop running.
def printHTTPErrorOutput(http_error_code, hibp_api_key, email=None):
	ERROR_CODE_OUTPUT = {
		400: "HTTP Error 400.  %s does not appear to be a valid email address." % (email),
		401: "HTTP Error 401.  Unauthorised - the API key provided (%s) was not valid." % (hibp_api_key),
		403: "HTTP Error 403.  Forbidden - no user agent has been specified in the request.",
		429: "HTTP Error 429.  Too many requests; the rate limit has been exceeded.",
		503: "HTTP Error 503.  Service unavailable."
	}

	default_output = "HTTP Error %s" % (http_error_code)
	print(ERROR_CODE_OUTPUT.get(http_error_code, default_output))

	if http_error_code == 401:
		sys.exit(1)

def get_results(emails, service, opts, hibp_api_key):
	HEADERS = {
		"User-Agent": "checkpwnedemails",
		"hibp-api-key": hibp_api_key,
	}
	results = []  # list of tuples (email address, been pwned?, json data)

	for email in emails:
		email = email.strip()
		data = []
		names_only = "true" if opts.names_only else "false"

		try:
			response = requests.get(url=PWNED_API_URL % (service, email, names_only), headers=HEADERS)
			is_pwned = True

			# Before parsing the response (for JSON), check if any content was returned.
			# Otherwise, a json.decoder.JSONDecodeError will be thrown because we were trying
			# to parse JSON from an empty response.
			if response.content:
				data = response.json()
			else:
				# No results came back for this email.
				# According to HIBP, this email was not pwned.
				data = None
				is_pwned = False

			results.append( (email, is_pwned, data) )
		except requests.exceptions.HTTPError as e:
			if e.code == 404 and not opts.only_pwned:
				# No results came back for this email.
				# According to HIBP, this email was not pwned.
				results.append( (email, False, data) )
			elif e.code != 404:
				printHTTPErrorOutput(e.code, hibp_api_key, email)

		sleep(RATE_LIMIT)  # This delay is for rate limiting.

	return results

def print_results(results, not_pwned_msg):
	for result in results:
		data = result[DATAINDEX]
		email = result[EMAILINDEX]
		if not result[PWNEDINDEX]:
			print(not_pwned_msg % (email))
		else:
			print("\n%s pwned!\n==========" % (email))
			print(json.dumps(data, indent=4))

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
	begining_sub_str = data[EMAILINDEX] + '\t' + str(data[PWNEDINDEX])
	output = []

	if data[DATAINDEX]:
		for bp in data[DATAINDEX]:  # bp stands for breaches/pastebins
			s = clean_and_encode(bp.values())
			output.append(begining_sub_str + '\t' + "\t".join(s))
	else:
		output.append(begining_sub_str)

	return '\n'.join(output)

def write_results_to_file(results, opts):
	BREACHESTXT   = "_breaches.txt"
	PASTESTXT     = "_pastes.txt"
	BREACH_HEADER = (
		"Email Address", "Is Pwned", "Name", "Title", "Domain", "Breach Date",
		"Added Date", "Modified Date", "Pwn Count", "Description", "Logo Path",
		"Data Classes", "Is Verified", "Is Fabricated", "Is Sensitive",
		"Is Retired", "Is SpamList"
	)
	PASTES_HEADER = ("Email Address", "Is Pwned", "ID",
		"Source", "Title", "Date", "Email Count"
	)
	files = []
	file_headers = {
		BREACHESTXT: "\t".join(BREACH_HEADER),
		PASTESTXT:   "\t".join(PASTES_HEADER)
	}

	if opts.only_breaches:
		files.append(BREACHESTXT)
	elif opts.only_pastebins:
		files.append(PASTESTXT)
	else:
		files.append(BREACHESTXT)
		files.append(PASTESTXT)

	out_path = opts.output_path
	filename = out_path
	if out_path.rfind('.') > -1:
		filename = out_path[ : out_path.rfind('.')]

	for result, f in zip(results, files):
		with open(filename + f, 'w', encoding='utf-8') as outfile:
			outfile.write(file_headers[f] + '\n')

			for r in result:
				outfile.write(tab_delimited_string(r) + '\n')

def read_apikey(apikey_path):
	try:
		with open(apikey_path) as apikey_file:
			return apikey_file.readline().strip()
	except IOError:
		return ''

def main():
	opts = get_args()
	if not opts.apikey_path:
		print("\nThe path to the file containing the HaveIBeenPwned API key was not found.")
		print("Please provide the file path with the -a switch and try again.\n")
		sys.exit(1)

	hibp_api_key = read_apikey(opts.apikey_path)
	if not hibp_api_key:
		print("\nCould not read file:", opts.apikey_path)
		print("Check if the file path is valid, and try again.\n")
		sys.exit(1)

	emails = None
	if opts.single_email:
		emails = tuple([opts.single_email])
	elif opts.input_path:
		with open(opts.input_path, 'r') as emails_file:
			emails = tuple(clean_list(emails_file.readlines()))
	else:
		print("\nNo email addresses were provided.")
		print("Please provide a single email address (using -s) or a list of email addresses (using -i).\n")
		sys.exit(1)

	breaches = []
	pastebins = []

	if opts.only_breaches:
		breaches = get_results(emails, BREACHED, opts, hibp_api_key)
	elif opts.only_pastebins:
		pastebins = get_results(emails, PASTEBIN, opts, hibp_api_key)
	else:
		breaches = get_results(emails, BREACHED, opts, hibp_api_key)
		pastebins = get_results(emails, PASTEBIN, opts, hibp_api_key)

	if not opts.output_path:
		print_results(breaches, "Email address %s not pwned.  Yay!")
		print_results(
			pastebins, "Email address %s was not found in any pastebins.  Yay!"
		)
	else:
		results = []
		if breaches: results.append(breaches)
		if pastebins: results.append(pastebins)
		write_results_to_file(tuple(results), opts)

if __name__ == '__main__':
	main()
