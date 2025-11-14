#!/bin/bash
set -xe

pip install torch

exec "$@"
