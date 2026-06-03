from app.ai.tool_registry import ToolRegistry
from app.ai.tools.binary import register_binary_tools
from app.config import get_settings
from app.ai.tools.carving import register_carving_tools
from app.ai.tools.comparison import register_comparison_tools
from app.ai.tools.documents import register_document_tools
from app.ai.tools.emulation import register_emulation_tools
from app.ai.tools.fuzzing import register_fuzzing_tools
from app.ai.tools.filesystem import register_filesystem_tools
from app.ai.tools.report_writer import register_report_writer_tools
from app.ai.tools.reporting import register_reporting_tools
from app.ai.tools.rtos import register_rtos_tools
from app.ai.tools.sbom import register_sbom_tools
from app.ai.tools.security import register_security_tools
from app.ai.tools.strings import register_string_tools
from app.ai.tools.uart import register_uart_tools
from app.ai.tools.unpack_control import register_unpack_control_tools


def create_tool_registry() -> ToolRegistry:
    """Create a ToolRegistry with all available tools registered."""
    registry = ToolRegistry()
    register_filesystem_tools(registry)
    register_string_tools(registry)
    register_binary_tools(registry)
    register_security_tools(registry)
    register_reporting_tools(registry)
    register_report_writer_tools(registry)
    register_document_tools(registry)
    register_sbom_tools(registry)
    register_comparison_tools(registry)
    register_rtos_tools(registry)
    register_unpack_control_tools(registry)

    # C6: features that require the host Docker socket (emulation, fuzzing,
    # carving) or host hardware (the UART serial bridge) aren't available in the
    # cloud deployment — they run in a local Wairz install. Register them only
    # in local mode so the cloud profile doesn't expose tools that can't work.
    if get_settings().compute_backend == "local":
        register_emulation_tools(registry)
        register_fuzzing_tools(registry)
        register_carving_tools(registry)
        register_uart_tools(registry)
    return registry
