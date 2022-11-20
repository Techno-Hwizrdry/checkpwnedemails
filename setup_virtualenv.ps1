$GITEMP=".\.gitignore_temp"
$PYTHON3=(Get-Command python).Path

Rename-Item .\.gitignore $GITEMP
iex "$($PYTHON3) -m virtualenv ."
Remove-Item .\.gitignore
Rename-Item $GITEMP .gitignore
.\Scripts\activate
pip3 install -r requirements.txt
deactivate