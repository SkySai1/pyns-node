#!/bin/bash
ami=$(realpath "$0"|sed 's!/[[:alnum:],\.\,\?_\-\s]*$!/!1')
python3 "$ami"backend/setup.py build_ext --inplace --build-lib "$ami"backend