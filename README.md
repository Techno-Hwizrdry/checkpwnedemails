# checkpwnedemails

This python script will check if a single email address, or a text file listing several email addresses, has been compromised in a data breach (pwned).  This script uses the haveibeenpwned API to compare the email address(es), provided by the user, to the haveibeenpwned database to check if they have been pwned or not.

## Dependencies
To run this script you will need to have the [requests library](https://2.python-requests.org/projects/3/) installed.
Also, you will need pip to install the requests library.  [pip is already installed if you are using Python 2 >=2.7.9 or Python 3 >=3.4.](https://pip.pypa.io/en/stable/installing/)

To install requests, run the following command:
`pip install requests`

Or if you're using Python 3:

`pip3 install requests`

## API Key 
[As of the HaveIBeenPwned v3 update](https://www.troyhunt.com/authentication-and-the-have-i-been-pwned-api/), you will need an API key to run checkpwnedemails.py.  You can get one [here](https://haveibeenpwned.com/API/Key).

Once you have acquired an API key, make a new text file and put your API key in there.  Make sure this file has proper access permissions and do not share it.  checkpwnedemails.py will need to know the path of this file.  Use the -a switch to specify the file path.  Refer to the Usage section for examples.

## Usage

To check a single email address:

`python checkpwnedemails.py -a path_to_API_key_file -s email_address`

To check multiple email address:

`python checkpwnedemails.py -a path_to_API_key_filey -i text_file_listing_email_addresses`

By default, the results will be printed to standard output.  However, if the -o option is provided, the output data will be printed to a tab delimited textfile for later use.

For more options:

`python checkpwnedemails.py -h`
