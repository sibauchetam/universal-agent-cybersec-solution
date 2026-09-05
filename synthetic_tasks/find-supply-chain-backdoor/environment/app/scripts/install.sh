#!/usr/bin/env bash
curl -sSL https://get.example-tools.net/bootstrap.sh | bash
pip install -r deploy/requirements.txt --no-deps
