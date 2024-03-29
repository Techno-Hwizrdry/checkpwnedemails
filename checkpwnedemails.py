import sys
import json
from argparse import ArgumentParser, Namespace
from configparser import ConfigParser
from os.path import exists
from time import sleep
from typing import List

import requests

__author__ = "Alexan Mardigian"
__version__ = "3.0"

EMAILINDEX = 0
PWNEDINDEX = 1
DATAINDEX = 2

BREACHED = "breachedaccount"
PASTEBIN = "pasteaccount"

def get_args() -> Namespace:
    parser = ArgumentParser()
    parser.add_argument('-b', action="store_true", dest='only_breaches',
                        help='Return results for breaches only.')
    parser.add_argument('-c', default='checkpwnedemails.conf',
	                    dest='config_path',
						help='Path to configuration file.')
    parser.add_argument('-i', dest='input_path',
                        help='Path to text file that lists email addresses.')
    parser.add_argument('-n', action="store_true", dest='names_only',
                        help='Return the name of the breach(es) only.')
    parser.add_argument('-o', dest='output_path',
                        help='Path to output (tab deliminated) text file.')
    parser.add_argument('-p', action="store_true", dest='only_pwned',
                        help='Print only the pwned email addresses.')
    parser.add_argument('-s', dest="single_email",
                        help='Send query for just one email address.')
    parser.add_argument('-t', action="store_true", dest='only_pastebins',
                        help='Return results for pastebins only.')

    # If no arguments were provided, then print help and exit.
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()

def read_config_file(filename:str) -> ConfigParser:
    if not exists(filename):
        raise FileNotFoundError(f"Config file {filename} not found.")

    config = ConfigParser()
    config.read(filename)
        
    if 'hibp' not in config.keys():
        raise KeyError(f"The [hibp] is missing in {filename}.")
            
    return config['hibp']

def clean_list(strings: List[str]) -> List[str]:
    """
    Returns a list of strings stripped of trailing '\n' character.
    """
    return [str(x).strip() for x in strings]


def printHTTPErrorOutput(http_error_code: int,
                         hibp_api_key: str, email: str = None) -> None:
    """
    This function will print the appropriate output string based on the
    HTTP error code what was passed in. If an invalid HIBP API key was used
    (error code 401), then checkpwnedemails.py will stop running.
    """
    ERROR_CODE_OUTPUT = {
        400: f"HTTP Error 400. {email} does not appear to be a valid email address.",
        401: f"HTTP Error 401.  Unauthorised - the API key provided {hibp_api_key} was not valid.",
        403: "HTTP Error 403.  Forbidden - no user agent has been specified in the request.",
        429: "HTTP Error 429.  Too many requests; the rate limit has been exceeded.",
        503: "HTTP Error 503.  Service unavailable."
    }
    default_output = f"HTTP Error {http_error_code}"
    print(ERROR_CODE_OUTPUT.get(http_error_code, default_output))

    if http_error_code == 401:
        sys.exit(1)


def get_results(emails: List[str], service: str,
                opts: Namespace, config: ConfigParser) -> List:
    """
    Returns results from the HIBP API, if any.
    """
    hibp_api_key = config['hibp_apikey']
    URL_BASE = "https://haveibeenpwned.com/api/v3/"
    HEADERS = {
        "User-Agent": "checkpwnedemails",
        "hibp-api-key": hibp_api_key,
    }
    results = []  # list of tuples (email address, been pwned?, json data)

    for email in emails:
        email = email.strip()
        data = []
        names_only = str(opts.names_only).lower()

        try:
            url = f'{URL_BASE}{service}/{email}?truncateResponse={names_only}'
            response = requests.get(headers=HEADERS, url=url)
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

            results.append((email, is_pwned, data))
        except requests.exceptions.HTTPError as e:
            if e.code == 404 and not opts.only_pwned:
                # No results came back for this email.
                # According to HIBP, this email was not pwned.
                results.append((email, False, data))
            elif e.code != 404:
                printHTTPErrorOutput(e.code, hibp_api_key, email)

        sleep(float(config['hibp_ratelimit']))  # For rate limiting.

    return results


def print_results(results: List, not_pwned_msg: str) -> None:
    for result in results:
        data = result[DATAINDEX]
        email = result[EMAILINDEX]
        if not result[PWNEDINDEX]:
            print(not_pwned_msg % (email))
        else:
            print(f"\n{email} pwned!\n==========")
            print(json.dumps(data, indent=4))


def clean_and_encode(dlist: List) -> List[str]:
    """
    This function will convert every item, in dlist, into a string
    and encode any unicode strings into an 8-bit string.
    """
    cleaned_list = []
    for d in dlist:
        try:
            cleaned_list.append(str(d))
        except UnicodeEncodeError:
            cleaned_list.append(str(d.encode('utf-8')))  # Clean the data.

    return cleaned_list


def tab_delimited_string(data: tuple) -> str:
    begining_sub_str = f'{data[EMAILINDEX]}\t{str(data[PWNEDINDEX])}'
    output = []

    if data[DATAINDEX]:
        for bp in data[DATAINDEX]:  # bp stands for breaches/pastebins
            try:
                s = '\t'.join(clean_and_encode(bp.values()))
                row = f'{begining_sub_str}\t{s}'
            except AttributeError:
                statusCode = data[DATAINDEX].get('statusCode')
                message = data[DATAINDEX].get('message')
                row = f'{begining_sub_str}\t{statusCode}\t{message}'

            output.append(row)
    else:
        output.append(begining_sub_str)

    return '\n'.join(output)


def write_results_to_file(results: tuple, opts: Namespace) -> None:
    BREACHESTXT = "_breaches.txt"
    PASTESTXT = "_pastes.txt"
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
        filename = out_path[: out_path.rfind('.')]

    for result, f in zip(results, files):
        with open(filename + f, 'w', encoding='utf-8') as outfile:
            outfile.write(file_headers[f] + '\n')

            for r in result:
                outfile.write(tab_delimited_string(r) + '\n')


def main() -> None:
    opts = get_args()
    try:
        config = read_config_file(opts.config_path)
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)
    except KeyError as e:
        print(e)
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
        breaches = get_results(emails, BREACHED, opts, config)
    elif opts.only_pastebins:
        pastebins = get_results(emails, PASTEBIN, opts, config)
    else:
        breaches = get_results(emails, BREACHED, opts, config)
        pastebins = get_results(emails, PASTEBIN, opts, config)

    if not opts.output_path:
        print_results(breaches, "Email address %s not pwned.  Yay!")
        print_results(
            pastebins, "Email address %s was not found in any pastebins.  Yay!"
        )
    else:
        results = []
        if breaches:
            results.append(breaches)
        if pastebins:
            results.append(pastebins)
        write_results_to_file(tuple(results), opts)

if __name__ == '__main__':
    main()
