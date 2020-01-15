# checkpwnedemails
NOTE: This version of checkpwnedemails.py is made for Python 2. [Click here if you want the version that uses Python 3.](https://github.com/Techno-Hwizrdry/checkpwnedemails3)

This python script will check if a single email address, or a text file listing several email addresses, has been compromised in a data breach (pwned).  This script uses the haveibeenpwned API to compare the email address(es), provided by the user, to the haveibeenpwned database to check if they have been pwned or not.


## API Key 
[As of the HaveIBeenPwned v3 update](https://www.troyhunt.com/authentication-and-the-have-i-been-pwned-api/), you will need an API key to run checkpwnedemails.py.  You can get one [here](https://haveibeenpwned.com/API/Key).

Once you have acquired an API key, make a new text file and put your API key in there.  Make sure this file has proper access permissions and do not share it.  checkpwnedemails.py will need to know the path of this file.  Use the -a switch to specify the file path.  Refer to the Usage section for examples.

## Usage

To check a single email address:

`python checkpwnedemails.py -a path_to_API_key_file -s email_address`

To check multiple email address:

`python checkpwnedemails.p -a path_to_API_key_filey -i text_file_listing_email_addresses`

By default, the results will be printed to standard output.  However, if the -o option is provided, the output data will be printed to a tab delimited textfile for later use.

For more options:

`python checkpwnedemails.py -h`
