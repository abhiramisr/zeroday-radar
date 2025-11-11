"""
VulnPath Core Data Models
Represents infrastructure as a graph for vulnerability path analysis
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum

class ComponentType(Enum):
    WEB_APP = "web_application"
    DATABASE = "database"
    API = "api_service"
    CACHE = "cache"
    LOAD_BALANCER = "load_balancer"

class Exposure(Enum):
    INTERNET = "internet_facing"
    INTERNAL = "internal_only"
    ISOLATED = "isolated"

@dataclass
class Component:
    id: str
    name: str
    type: ComponentType
    exposure: Exposure
    criticality_score: float
    vulnerabilities: List[str] = None