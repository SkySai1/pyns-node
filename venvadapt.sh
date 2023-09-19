#!/bin/bash
ami=$(realpath "$0"|sed 's!/[[:alnum:],\.\,\?_\-\s]*$!/!1')
pbin=$(find $ami -name 'python3')
sed -i "s@#!.*@#!$pbin@1" $ami*.py
sed -i "s@#!.*@#!$pbin@1" $ami"backend/"*.py