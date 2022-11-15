# checkpwnedemails

This Python3 script will check if a single email address, or a text file listing several email addresses, has been compromised in a data breach (pwned).  This script uses the haveibeenpwned API to compare the email address(es), provided by the user, to the haveibeenpwned database to check if they have been pwned or not.

## Prerequisites
This web interface requires:
* python3 (version 3.6 or later)
* python3-pip
* virtualenv

The prerequisites can be installed on a Debian based linux machine, like so:

`sudo apt-get install git python3 python3-pip && sudo pip3 install virtualenv`

## Setup
Once those prerequisites have been installed, git clone this repo, cd into it, and set up the virtual environment:

`cd /path/to/checkpwnedemails && ./setup_virtualenv.sh`

setup_virtualenv.sh will set checkpwnedemails as the virtual environment, activate it, and call pip3 to download and install all the python3 dependencies for this script.  These python dependencies are listed in requirements.txt.

## API Key 
[As of the HaveIBeenPwned v3 update](https://www.troyhunt.com/authentication-and-the-have-i-been-pwned-api/), you will need an API key to run checkpwnedemails.py.  You can get one [here](https://haveibeenpwned.com/API/Key).

Once you have acquired an API key, copy and paste it into the checkpwnedemails.conf file on the line that says 'HIBP_APIKEY='.

## Rate Limit
[As of this HaveIBeenPwned update](https://www.troyhunt.com/the-have-i-been-pwned-api-now-has-different-rate-limits-and-annual-billing/), the rate limit defined in the checkpwnedemails.conf file will depend on your pricing tier.  For example, if you bought the 50 RPM (requests for minute) tier, set HIBP_RATELIMIT to 1.2.  `60 / 50 = 1.2 seconds`

## Usage

To check a single email address:

`python3 checkpwnedemails.py -s email_address`

To check multiple email address:

`python3 checkpwnedemails.py -i text_file_listing_email_addresses`

By default, the results will be printed to standard output.  However, if the -o option is provided, the output data will be printed to a tab delimited textfiles (one for breaches, one for pastebins) for later use.

For more options:

`python3 checkpwnedemails.py -h`
