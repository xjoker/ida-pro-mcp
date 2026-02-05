"""IDA Pro MCP Test Package.

This package contains test modules for each API module.
Tests are registered via the @test decorator from the framework module.
"""

# Import all test modules to register tests when the package is imported
from . import test_api_core as test_api_core
from . import test_api_analysis as test_api_analysis
from . import test_api_memory as test_api_memory
from . import test_api_modify as test_api_modify
from . import test_api_types as test_api_types
from . import test_api_stack as test_api_stack
from . import test_api_resources as test_api_resources
