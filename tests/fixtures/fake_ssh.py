#!/usr/bin/env python3
"""Execute the quoted remote worker locally, without networking, for transport tests."""
import os
import shlex
import sys
command = shlex.split(sys.argv[-1])
os.execvp(command[0], command)
