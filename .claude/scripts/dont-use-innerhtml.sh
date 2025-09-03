#!/bin/bash

RES="$(rg -i innerhtml  -l --glob '*.js' --glob '!target/' --glob '!web/static/third_pary/')"

if [ -n "$RES" ]; then
  echo "Found instances of 'innerHTML' in the following files, please use safe DOM manipulation:"
  echo "$RES"
  exit 2
else
  echo "No instances of 'innerHTML' usage found."
  exit 0
fi