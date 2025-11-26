#!/usr/bin/env python3

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from subscout.main import main
except ImportError as e:
    print(f"Error importing SubScout package: {e}")
    print("Make sure you are in the root directory of the project.")
    sys.exit(1)

if __name__ == '__main__':
    main()
