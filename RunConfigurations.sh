# collection of command-line snippets
# ensure using up-to-date pip and build
python -m pip install --upgrade pip build setuptools
# ensure using up-to-date  requirements
python -m pip install -r requirements.txt --upgrade
# build a release
python -m build
# test cpitables
python ciptables.py
# test cpi reading a single image file
python cpi.py
# test cpi reading a single table
python cpi.py v4/data/AccessPointDetails
