#!/bin/sh
# Run the proof-of-exploit suite in a throwaway Linux container.
docker run --rm -v "$(pwd):/lab" -w /lab python:3.12-slim \
  sh -c "pip install -q -r requirements-dev.txt && python -m pytest -v"
