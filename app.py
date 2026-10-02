"""ScamShield AI - Root Application Entry Point.

Delegates directly to the unified production Streamlit console in src/app/streamlit_app.py.
Ensures single-entry execution parity whether running:
    streamlit run app.py
or:
    streamlit run src/app/streamlit_app.py
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.app.streamlit_app import main

if __name__ == "__main__":
    main()
