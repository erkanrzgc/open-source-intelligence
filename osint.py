#!/usr/bin/env python3
"""Open Source Intelligence — main entry point.

Run with: python osint.py
"""
import asyncio
import sys
from core.cli import main

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
