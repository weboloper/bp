"""
Shared constants used across multiple apps in the project.

✅ ARCHITECTURE: Centralized constants to eliminate magic numbers.

This module contains common choices, configurations, and constants
that are used by multiple models throughout the application.

Following best practices:
- Named constants instead of magic numbers
- Decimal types for precise calculations
- Clear documentation for each constant
- Grouped by functional area
"""

# ============================================================================
# COLOR CONSTANTS
# ============================================================================

# Default color for new categories/tags
DEFAULT_COLOR = '#93C5FD'


# ============================================================================
# TENANT PROVISIONING
# ============================================================================

# Trial period for new tenants (days)
DEFAULT_TRIAL_DAYS = 14