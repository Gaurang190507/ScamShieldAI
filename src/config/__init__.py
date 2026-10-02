"""Configuration package for ScamShield AI."""

from .runtime_config import (
    FROZEN_CONFIG,
    FrozenModelConfig,
    RuntimeConfig,
    VERSION_METADATA,
    VersionMetadata,
    get_frozen_config,
    get_runtime_config,
    get_version_metadata,
)

__all__ = [
    "FROZEN_CONFIG",
    "FrozenModelConfig",
    "RuntimeConfig",
    "VERSION_METADATA",
    "VersionMetadata",
    "get_frozen_config",
    "get_runtime_config",
    "get_version_metadata",
]
