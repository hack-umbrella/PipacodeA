#!/usr/bin/env python3
"""CLI entry point for unified audit engine."""

import sys
from pathlib import Path

# Add engine to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.unified_audit import main

if __name__ == "__main__":
    main()
