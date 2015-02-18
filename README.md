# checkpwnedemails
This python script will check the if a single email address, or a text file listing several email addresses, has been compromised in a data breach (pwned).  This script uses the haveIbeenpwned API to compare the email address(es), provided by the user, to the haveIbeenpwned database to check if they have been pwned or not.


To check a single email address:

python checkpwnedemails.py -s <email address>

To check multiple email address:

python checkpwnedemails.py -i <text file listing email addresses>

By default, the results will be printed to standard output.  However, if the -o option is provided, the output data will be printed to a tab delimited textfile for later use.

For more options:

python checkpwnedemails.py -h
