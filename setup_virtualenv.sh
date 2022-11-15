#!/usr/bin/env bash

GITEMP=".gitignore_temp"
PYTHON3=$(which python3)

mv .gitignore $GITEMP
virtualenv -p $PYTHON3 .
mv $GITEMP .gitignore
source bin/activate
pip3 install -r requirements.txt
deactivate
cp checkpwnedemails.conf_example checkpwnedemails.conf