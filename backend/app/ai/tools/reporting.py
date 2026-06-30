import uuid

from sqlalchemy import select

from app.ai.tool_registry import ToolContext, ToolRegistry
from app.models.finding import Finding
from app.models.firmware import Firmware
from app.schemas.finding import FindingCreate, FindingUpdate, Severity, FindingStatus
from app.services.finding_service import FindingService


async def _resolve_firmware_refs(
    context: ToolContext, refs: list[str]
) -> list[uuid.UUID]:
    """Map firmware references (UUIDs or version labels) to firmware UUIDs.

    References are resolved against the active project's firmware. Labels match
    case-insensitively; entries that resolve to nothing are skipped.
    """
    result = await context.db.execute(
        select(Firmware).where(Firmware.project_id == context.project_id)
    )
    firmware = list(result.scalars().all())
    by_id = {str(fw.id): fw.id for fw in firmware}
    by_label = {
        (fw.version_label or "").strip().lower(): fw.id
        for fw in firmware
        if fw.version_label
    }
    resolved: list[uuid.UUID] = []
    for ref in refs:
        key = str(ref).strip()
        if key in by_id:
            resolved.append(by_id[key])
        elif key.lower() in by_label:
            resolved.append(by_label[key.lower()])
    # De-duplicate while preserving order.
    seen: set[uuid.UUID] = set()
    return [fid for fid in resolved if not (fid in seen or seen.add(fid))]


def register_reporting_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="add_finding",
        description=(
            "Record a security finding for the current firmware project. "
            "Use this whenever you identify a security issue, vulnerability, or notable concern. "
            "Severity levels: critical, high, medium, low, info."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short descriptive title for the finding",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity level of the finding",
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the finding, including why it matters and potential impact",
                },
                "evidence": {
                    "type": "string",
                    "description": "Supporting evidence: command output, file contents, code snippets, etc.",
                },
                "file_path": {
                    "type": "string",
                    "description": "Filesystem path of the affected file (relative to firmware root)",
                },
                "line_number": {
                    "type": "integer",
                    "description": "Line number in the affected file, if applicable",
                },
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Associated CVE identifiers, e.g. ['CVE-2023-1234']",
                },
                "cwe_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Associated CWE identifiers, e.g. ['CWE-798', 'CWE-259'] for hardcoded credentials",
                },
                "source": {
                    "type": "string",
                    "enum": ["ai_discovered", "manual", "sbom_scan", "fuzzing", "security_review"],
                    "description": "How this finding was discovered (default: ai_discovered)",
                },
                "firmware_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Firmware version(s) this finding affects — each entry may be a "
                        "firmware UUID or a version label (e.g. 'V1'). If omitted, the "
                        "finding is tagged with the currently-active firmware version. "
                        "Use list_firmware_versions to see available versions."
                    ),
                },
            },
            "required": ["title", "severity", "description"],
        },
        handler=_handle_add_finding,
    )

    registry.register(
        name="list_findings",
        description=(
            "List all security findings recorded for the current project. "
            "Optionally filter by severity or status."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Filter by severity level",
                },
                "status": {
                    "type": "string",
                    "enum": ["open", "confirmed", "false_positive", "fixed"],
                    "description": "Filter by finding status",
                },
            },
        },
        handler=_handle_list_findings,
    )

    registry.register(
        name="get_finding",
        description=(
            "Read the full details of a single recorded finding by its ID, including "
            "description, evidence, affected file/line, CVE/CWE identifiers, status, "
            "source, and timestamps. Use this to review the complete record of a past "
            "finding (list_findings only returns one-line summaries)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "UUID of the finding to read",
                },
            },
            "required": ["finding_id"],
        },
        handler=_handle_get_finding,
    )

    registry.register(
        name="update_finding",
        description=(
            "Update an existing finding's severity, status, details, or the firmware "
            "version(s) it affects. Use this to re-rate severity after further analysis, "
            "mark findings as confirmed/false_positive/fixed, refine the "
            "description/evidence, or tag additional firmware versions when a "
            "vulnerability is still present in a newer release."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "UUID of the finding to update",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "New severity level for the finding",
                },
                "status": {
                    "type": "string",
                    "enum": ["open", "confirmed", "false_positive", "fixed"],
                    "description": "New status for the finding",
                },
                "description": {
                    "type": "string",
                    "description": "Updated description",
                },
                "evidence": {
                    "type": "string",
                    "description": "Updated or additional evidence",
                },
                "firmware_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Replaces the set of firmware version(s) this finding affects. "
                        "Each entry may be a firmware UUID or version label (e.g. 'V2'). "
                        "To add a newly-released version while keeping existing tags, "
                        "pass the full desired set (old + new). Use list_firmware_versions "
                        "to see available versions."
                    ),
                },
            },
            "required": ["finding_id"],
        },
        handler=_handle_update_finding,
    )


async def _handle_add_finding(input: dict, context: ToolContext) -> str:
    svc = FindingService(context.db)
    # Resolve firmware version tags. When the caller doesn't specify any, tag
    # the finding with the currently-active firmware version.
    if "firmware_ids" in input:
        firmware_ids = await _resolve_firmware_refs(context, input["firmware_ids"])
    else:
        firmware_ids = [context.firmware_id]
    data = FindingCreate(
        title=input["title"],
        severity=Severity(input["severity"]),
        description=input.get("description"),
        evidence=input.get("evidence"),
        file_path=input.get("file_path"),
        line_number=input.get("line_number"),
        cve_ids=input.get("cve_ids"),
        cwe_ids=input.get("cwe_ids"),
        source=input.get("source", "ai_discovered"),
        firmware_ids=firmware_ids,
    )
    finding = await svc.create(context.project_id, data)
    await context.db.commit()
    versions = ", ".join(
        fw.version_label or str(fw.id)[:8] for fw in finding.firmware_versions
    )
    version_str = f" — version(s): {versions}" if versions else ""
    return (
        f"Finding recorded: {finding.title} [{finding.severity}] "
        f"(ID: {finding.id}){version_str}"
    )


async def _handle_list_findings(input: dict, context: ToolContext) -> str:
    svc = FindingService(context.db)
    findings = await svc.list_by_project(
        context.project_id,
        severity=input.get("severity"),
        status=input.get("status"),
    )
    if not findings:
        return "No findings recorded for this project."

    lines = [f"Found {len(findings)} finding(s):\n"]
    for f in findings:
        status_badge = f"[{f.status}]" if f.status != "open" else ""
        file_info = f" in {f.file_path}" if f.file_path else ""
        versions = ", ".join(
            fw.version_label or str(fw.id)[:8] for fw in f.firmware_versions
        )
        version_info = f" {{{versions}}}" if versions else ""
        lines.append(
            f"- [{f.severity.upper()}] {f.title}{file_info}{version_info} {status_badge} (ID: {f.id})"
        )
    return "\n".join(lines)


async def _handle_get_finding(input: dict, context: ToolContext) -> str:
    import uuid

    svc = FindingService(context.db)
    try:
        finding_id = uuid.UUID(input["finding_id"])
    except (ValueError, KeyError):
        return f"Error: '{input.get('finding_id')}' is not a valid finding ID."

    finding = await svc.get(finding_id)
    if not finding or finding.project_id != context.project_id:
        return f"Error: Finding {input['finding_id']} not found in this project."

    lines = [
        f"# {finding.title}",
        f"- ID: {finding.id}",
        f"- Severity: {finding.severity}",
        f"- Status: {finding.status}",
        f"- Source: {finding.source}",
    ]
    if finding.file_path:
        loc = finding.file_path
        if finding.line_number is not None:
            loc += f":{finding.line_number}"
        lines.append(f"- Location: {loc}")
    if finding.cve_ids:
        lines.append(f"- CVEs: {', '.join(finding.cve_ids)}")
    if finding.cwe_ids:
        lines.append(f"- CWEs: {', '.join(finding.cwe_ids)}")
    if finding.firmware_versions:
        versions = ", ".join(
            f"{fw.version_label or 'unlabeled'} ({str(fw.id)[:8]})"
            for fw in finding.firmware_versions
        )
        lines.append(f"- Affected version(s): {versions}")
    lines.append(f"- Created: {finding.created_at}")
    lines.append(f"- Updated: {finding.updated_at}")
    lines.append("")
    lines.append("## Description")
    lines.append(finding.description or "(none)")
    lines.append("")
    lines.append("## Evidence")
    lines.append(finding.evidence or "(none)")

    return "\n".join(lines)


async def _handle_update_finding(input: dict, context: ToolContext) -> str:
    import uuid

    svc = FindingService(context.db)
    finding_id = uuid.UUID(input["finding_id"])
    finding = await svc.get(finding_id)
    if not finding or finding.project_id != context.project_id:
        return f"Error: Finding {input['finding_id']} not found in this project."

    update_fields = {}
    if "severity" in input:
        update_fields["severity"] = Severity(input["severity"])
    if "status" in input:
        update_fields["status"] = FindingStatus(input["status"])
    if "description" in input:
        update_fields["description"] = input["description"]
    if "evidence" in input:
        update_fields["evidence"] = input["evidence"]
    if "firmware_ids" in input:
        update_fields["firmware_ids"] = await _resolve_firmware_refs(
            context, input["firmware_ids"]
        )

    if not update_fields:
        return "No fields to update."

    data = FindingUpdate(**update_fields)
    updated = await svc.update(finding_id, data)
    await context.db.commit()
    versions = ", ".join(
        fw.version_label or str(fw.id)[:8] for fw in updated.firmware_versions
    )
    version_str = f" — version(s): {versions}" if versions else ""
    return (
        f"Finding updated: {updated.title} [{updated.severity}] "
        f"— status: {updated.status}{version_str}"
    )
