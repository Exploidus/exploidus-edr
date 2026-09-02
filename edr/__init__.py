"""
Exploidus EDR - Modern Python Antivirus Engine
No external API required. Fully local.
"""

__version__ = "1.0.0"
__author__ = "Rahad Bhuiya"
__license__ = "MIT"

from edr.engine.scanner import Scanner
from edr.engine.monitor import RealtimeMonitor
from edr.engine.behavior import BehaviorMonitor
from edr.quarantine.vault import QuarantineVault

__all__ = ["Scanner", "RealtimeMonitor", "BehaviorMonitor", "QuarantineVault"]
