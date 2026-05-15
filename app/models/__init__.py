"""
app/models/__init__.py
──────────────────────
Exports all ORM models so that `import app.models` causes SQLAlchemy to
register them before `Base.metadata.create_all()` is called.
"""

from app.models.user import User                    # noqa: F401
from app.models.scan import Scan, ScanStatus        # noqa: F401
from app.models.device import Device                # noqa: F401
from app.models.port import Port                    # noqa: F401
from app.models.report import Report, ReportFormat  # noqa: F401
