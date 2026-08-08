"""Allow ``python -m core`` to invoke the CLI."""
from core.cli import main
import sys

sys.exit(main())
