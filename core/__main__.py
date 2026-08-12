"""Allow ``python -m core`` to invoke the CLI."""
import sys

from core.cli import main

sys.exit(main())
