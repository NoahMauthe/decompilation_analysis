#!/usr/bin/env bash

echo "###################################"
echo "   Setting up python environment   "
echo "###################################"
pip install --user virtualenv wheel
virtualenv -p python3.9 venv
source venv/bin/activate
python -m pip install --upgrade pip
git clone git@github.com:NoahMauthe/APIs.git
cd APIs
python setup.py sdist bdist_wheel && pip install dist/API-*.tar.gz
cd ..
./build_decompilers.sh
