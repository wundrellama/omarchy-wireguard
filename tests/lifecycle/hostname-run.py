#!/usr/bin/env python3
"""Real hostname regression, using the shared guarded lifecycle supervisor."""
import run
import sys
run.SANDBOX = 'hostname-sandbox.py'
if __name__ == '__main__':
    sys.exit(run.main())
