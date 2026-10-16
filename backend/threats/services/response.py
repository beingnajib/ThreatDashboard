"""Response automation: host isolation, SOAR playbooks and live-response commands.

Actions run through a *connector*:

* ``simulated`` (default) — updates platform state and returns realistic
  output. Nothing leaves the platform; use it for demos and training.
* ``webhook`` — POSTs a signed JSON request to your EDR/SOAR integration
  (``THREATDASH_RESPONSE_WEBHOOK_URL``), which performs the action on the real
  device or identity provider and replies ``{"status": "succeeded", "output": "..."}``.

Every action is persisted as a ``ResponseAction`` and written to the audit log.
"""
import hashlib
import hmac
import json
import logging
import shlex
import urllib.error
import urllib.request

from django.conf import settings
from django.db.models import F
from django.utils import timezone

from ..models import Asset, Indicator, Playbook, ResponseAction, TelemetryEvent
from .audit import audit

logger = logging.getLogger(__name__)

# Live-response commands are restricted to read-only forensic collection plus
# a small set of containment verbs. Anything else is rejected before it is
# sent to the endpoint.
TERMINAL_COMMANDS = {
    "help": "List available commands",
    "ps": "List running processes",
    "netstat": "List network connections",
    "ls": "List a directory: ls <path>",
    "hash": "SHA-256 of a file: hash <path>",
    "getfile": "Upload a file to the evidence locker: getfile <path>",
    "memdump": "Capture a full memory image to the evidence locker",
    "autoruns": "List persistence locations (services, run keys, scheduled tasks)",
    "users": "List logged-on users and sessions",
    "dnscache": "Show the DNS resolver cache",
    "ipconfig": "Show network interfaces",
    "services": "List installed services",
    "kill": "Terminate a process: kill <pid>",
    "quarantine": "Quarantine a file: quarantine <path>",
}
FORBIDDEN_CHARS = set(";|&`$><\n\r")
MAX_ARGS = 4


class ResponseError(Exception):
    pass


def parse_terminal_command(command_line):
    if not command_line or len(command_line) > 500:
        raise ResponseError("Command must be between 1 and 500 characters.")
    if FORBIDDEN_CHARS & set(command_line):
        raise ResponseError("Shell metacharacters are not allowed in live-response commands.")
    try:
        parts = shlex.split(command_line)
    except ValueError as exc:
        raise ResponseError(f"Could not parse command: {exc}") from exc
    if not parts:
        raise ResponseError("Empty command.")
    verb, args = parts[0].lower(), parts[1:]
    if verb not in TERMINAL_COMMANDS:
        raise ResponseError(f"'{verb}' is not an allowed live-response command. Type 'help' for the list.")
    if len(args) > MAX_ARGS:
        raise ResponseError("Too many arguments.")
    if verb in ("ls", "hash", "getfile", "quarantine", "kill") and not args:
        raise ResponseError(f"Usage: {TERMINAL_COMMANDS[verb].split(': ', 1)[-1]}")
    if verb == "kill" and not args[0].isdigit():
        raise ResponseError("kill expects a numeric process ID.")
    return verb, args


# --------------------------------------------------------------------------- #
# Connectors
# --------------------------------------------------------------------------- #

class SimulatedConnector:
    name = "simulated"

    def execute(self, action):
        handler = getattr(self, f"do_{action.action_type}", None)
        if handler is None:
            return True, f"{action.get_action_type_display()} recorded."
        return handler(action)

    def do_isolate_host(self, action):
        return True, f"Network containment applied to {action.asset}: all traffic blocked except the management " \
                     f"channel to the response console."

    def do_release_host(self, action):
        return True, f"Network containment lifted on {action.asset}."

    def do_collect_forensics(self, action):
        stamp = timezone.now().strftime("%Y%m%dT%H%M%SZ")
        return True, "\n".join([
            f"Forensic package collected from {action.asset}:",
            f"  evidence/{action.asset}-{stamp}/memory.raw",
            f"  evidence/{action.asset}-{stamp}/processes.json",
            f"  evidence/{action.asset}-{stamp}/netconns.json",
            f"  evidence/{action.asset}-{stamp}/autoruns.json",
            f"  evidence/{action.asset}-{stamp}/eventlogs.zip",
        ])

    def do_reset_password(self, action):
        if action.target_user == "*":
            count = TelemetryEvent.objects.exclude(username="").values("username").distinct().count()
            return True, f"Forced password reset at next sign-in for {count} identities; refresh tokens revoked."
        return True, f"Password reset enforced for {action.target_user}; active sessions revoked."

    def do_disable_user(self, action):
        return True, f"Account {action.target_user} disabled in the identity provider."

    def do_revoke_sessions(self, action):
        return True, f"All sessions and refresh tokens revoked for {action.target_user or 'all users'}."

    def do_block_indicator(self, action):
        return True, f"{action.indicator} added to the perimeter blocklist (firewall EDL, DNS sinkhole, proxy)."

    def do_kill_process(self, action):
        return True, f"Process {action.parameters.get('pid') or action.parameters.get('process', '?')} terminated " \
                     f"on {action.asset}."

    def do_notify(self, action):
        return True, f"Notification sent: {action.parameters.get('message', 'response action executed')}"

    def do_terminal_command(self, action):
        verb, args = parse_terminal_command(action.parameters.get("command", ""))
        asset = action.asset
        events = TelemetryEvent.objects.filter(asset=asset).order_by("-timestamp")[:200]
        if verb == "help":
            return True, "\n".join(f"{name:<11} {text}" for name, text in TERMINAL_COMMANDS.items())
        if verb == "ps":
            procs = list(dict.fromkeys(e.process for e in events if e.process))[:20] or ["svchost.exe", "explorer.exe"]
            rows = ["  PID  USER              COMMAND"]
            rows += [f"{1000 + i * 7:>5}  {(asset.owner or 'SYSTEM')[:16]:<16}  {p}" for i, p in enumerate(procs)]
            return True, "\n".join(rows)
        if verb == "netstat":
            conns = [(e.dst_ip, e.dst_port) for e in events if e.dst_ip][:20]
            rows = ["Proto  Local Address          Foreign Address        State"]
            rows += [f"TCP    {asset.ip_address or '0.0.0.0'}:{49152 + i:<10} {ip}:{port or 443:<14} ESTABLISHED"
                     for i, (ip, port) in enumerate(conns)] or ["(no active connections)"]
            return True, "\n".join(rows)
        if verb in ("ipconfig",):
            return True, f"Interface eth0\n  IPv4 {asset.ip_address or 'n/a'}\n  MAC  {asset.mac_address or 'n/a'}" \
                         f"\n  Isolated: {'yes' if asset.is_isolated else 'no'}"
        if verb == "users":
            users = sorted({e.username for e in events if e.username})[:10] or [asset.owner or "SYSTEM"]
            return True, "\n".join(f"{u:<30} console  active" for u in users)
        if verb == "dnscache":
            names = list(dict.fromkeys(e.domain_name for e in events if e.domain_name))[:25]
            return True, "\n".join(names) or "(cache empty)"
        if verb == "hash":
            digest = hashlib.sha256(f"{asset.pk}:{args[0]}".encode()).hexdigest()
            return True, f"{digest}  {args[0]}"
        if verb == "memdump":
            return True, f"Memory image captured: evidence/{asset}/memory-{timezone.now():%Y%m%dT%H%M%S}.raw " \
                         f"(SHA-256 recorded in chain of custody)."
        if verb == "getfile":
            return True, f"{args[0]} uploaded to evidence locker as evidence/{asset}/{args[0].split('/')[-1]}"
        if verb == "quarantine":
            return True, f"{args[0]} moved to quarantine."
        if verb == "kill":
            return True, f"Process {args[0]} terminated."
        if verb == "ls":
            return True, f"Directory listing of {args[0]} collected (see evidence locker)."
        if verb in ("autoruns", "services"):
            return True, "Collected; no unsigned entries outside baseline." if not events else \
                f"Collected {verb}; {sum(1 for e in events if e.mitre_technique.startswith(('T1053', 'T1547', 'T1543')))}" \
                f" entries match persistence detections."
        return True, "OK"


class WebhookConnector:
    name = "webhook"

    def execute(self, action):
        url = settings.THREATDASH_RESPONSE_WEBHOOK_URL
        secret = settings.THREATDASH_RESPONSE_WEBHOOK_SECRET
        if not url or not secret:
            raise ResponseError("THREATDASH_RESPONSE_WEBHOOK_URL and _SECRET must be configured for the webhook "
                                "connector.")
        asset = action.asset
        payload = {
            "action_id": action.pk,
            "action_type": action.action_type,
            "requested_by": getattr(action.requested_by, "username", None),
            "requested_at": action.created_at.isoformat(),
            "asset": {"hostname": asset.hostname, "ip_address": asset.ip_address, "mac_address": asset.mac_address,
                      "cloud_resource_id": asset.cloud_resource_id} if asset else None,
            "indicator": {"type": action.indicator.ioc_type, "value": action.indicator.value}
            if action.indicator_id else None,
            "target_user": action.target_user or None,
            "parameters": action.parameters,
        }
        body = json.dumps(payload).encode()
        signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        request = urllib.request.Request(url, data=body, method="POST", headers={
            "Content-Type": "application/json", "X-ThreatDash-Signature": f"sha256={signature}",
            "User-Agent": "ThreatDashboard-Response/2.0",
        })
        try:
            with urllib.request.urlopen(request, timeout=settings.THREATDASH_RESPONSE_TIMEOUT_SECONDS) as resp:  # noqa: S310
                reply = json.loads(resp.read(1024 * 1024) or b"{}")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise ResponseError(f"Response connector error: {exc}") from exc
        ok = str(reply.get("status", "")).lower() in ("succeeded", "success", "ok", "queued")
        return ok, str(reply.get("output") or reply.get("message") or "")[:20000]


def get_connector():
    if settings.THREATDASH_RESPONSE_CONNECTOR == "webhook":
        return WebhookConnector()
    return SimulatedConnector()


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #

def _apply_side_effects(action):
    now = timezone.now()
    if action.action_type == ResponseAction.ActionType.ISOLATE_HOST and action.asset_id:
        Asset.objects.filter(pk=action.asset_id).update(is_isolated=True, isolated_at=now)
    elif action.action_type == ResponseAction.ActionType.RELEASE_HOST and action.asset_id:
        Asset.objects.filter(pk=action.asset_id).update(is_isolated=False, isolated_at=None)
    elif action.action_type == ResponseAction.ActionType.BLOCK_INDICATOR and action.indicator_id:
        indicator = Indicator.objects.get(pk=action.indicator_id)
        if "blocked" not in indicator.tags:
            indicator.tags = [*indicator.tags, "blocked"]
            indicator.save(update_fields=["tags"])


def validate_action(action_type, asset=None, indicator=None, target_user=""):
    types = ResponseAction.ActionType
    if action_type in (types.ISOLATE_HOST, types.RELEASE_HOST, types.COLLECT_FORENSICS, types.KILL_PROCESS,
                       types.TERMINAL_COMMAND) and asset is None:
        raise ResponseError("This action needs a target asset.")
    if action_type in (types.TERMINAL_COMMAND, types.COLLECT_FORENSICS, types.KILL_PROCESS) and not asset.managed:
        raise ResponseError(f"{asset} has no endpoint agent (shadow IT); live response is unavailable. "
                            f"Isolate it at the network layer instead.")
    if action_type == types.ISOLATE_HOST and asset.is_isolated:
        raise ResponseError(f"{asset} is already isolated.")
    if action_type == types.RELEASE_HOST and not asset.is_isolated:
        raise ResponseError(f"{asset} is not isolated.")
    if action_type == types.BLOCK_INDICATOR and indicator is None:
        raise ResponseError("This action needs a target indicator.")
    if action_type in (types.DISABLE_USER, types.RESET_PASSWORD) and not target_user:
        raise ResponseError("This action needs a target user ('*' for everyone, password reset only).")
    if action_type == types.DISABLE_USER and target_user == "*":
        raise ResponseError("Refusing to disable every account.")


def execute_action(action, request=None):
    """Run ``action`` through the configured connector and record the outcome."""
    connector = get_connector()
    action.connector = connector.name
    action.status = ResponseAction.Status.RUNNING
    action.save(update_fields=["connector", "status"])
    try:
        ok, output = connector.execute(action)
    except ResponseError as exc:
        ok, output, error = False, "", str(exc)
    except Exception as exc:  # noqa: BLE001 - a connector failure must never 500 the console
        logger.exception("Response action %s failed", action.pk)
        ok, output, error = False, "", f"Unexpected connector error: {exc.__class__.__name__}"
    else:
        error = "" if ok else (output or "The connector reported a failure.")
    action.status = ResponseAction.Status.SUCCEEDED if ok else ResponseAction.Status.FAILED
    action.output, action.error, action.completed_at = output, error, timezone.now()
    action.save(update_fields=["status", "output", "error", "completed_at"])
    if ok:
        _apply_side_effects(action)
    audit(request or action.requested_by, f"response.{action.action_type}",
          target=action.asset or action.indicator or action.target_user or "global",
          action_id=action.pk, status=action.status, connector=connector.name,
          command=action.parameters.get("command"))
    return action


def create_and_execute(action_type, user, request=None, asset=None, indicator=None, incident=None, target_user="",
                       parameters=None, playbook=None, parent=None):
    validate_action(action_type, asset=asset, indicator=indicator, target_user=target_user)
    if action_type == ResponseAction.ActionType.TERMINAL_COMMAND:
        parse_terminal_command((parameters or {}).get("command", ""))
    action = ResponseAction.objects.create(
        action_type=action_type, asset=asset, indicator=indicator, incident=incident, target_user=target_user,
        parameters=parameters or {}, playbook=playbook, parent=parent, requested_by=user,
    )
    return execute_action(action, request)


def run_playbook(playbook, user, request=None, asset=None, indicator=None, incident=None, target_user=""):
    """Execute each playbook step in order; stops at the first failed step unless it allows failure."""
    if not playbook.enabled:
        raise ResponseError("Playbook is disabled.")
    parent = ResponseAction.objects.create(
        action_type=ResponseAction.ActionType.RUN_PLAYBOOK, playbook=playbook, asset=asset, indicator=indicator,
        incident=incident, target_user=target_user, requested_by=user, status=ResponseAction.Status.RUNNING,
        parameters={"playbook": playbook.name}, connector=get_connector().name,
    )
    log, ok = [], True
    for number, step in enumerate(playbook.steps or [], 1):
        action_type = step.get("action")
        if action_type not in ResponseAction.ActionType.values or action_type == ResponseAction.ActionType.RUN_PLAYBOOK:
            log.append(f"[{number}] skipped unknown action {action_type!r}")
            continue
        user_target = step.get("target_user", target_user)
        try:
            child = create_and_execute(
                action_type, user, request=request, asset=asset, indicator=indicator, incident=incident,
                target_user=user_target, parameters=step.get("parameters") or {}, playbook=playbook, parent=parent,
            )
            status, detail = child.status, child.output or child.error
        except ResponseError as exc:
            status, detail = ResponseAction.Status.FAILED, str(exc)
        log.append(f"[{number}] {ResponseAction.ActionType(action_type).label}: {status} - {detail.splitlines()[0] if detail else ''}")
        if status == ResponseAction.Status.FAILED and not step.get("continue_on_error"):
            ok = False
            log.append("Playbook stopped.")
            break
        if asset is not None:
            asset.refresh_from_db()
    parent.status = ResponseAction.Status.SUCCEEDED if ok else ResponseAction.Status.FAILED
    parent.output, parent.completed_at = "\n".join(log), timezone.now()
    parent.save(update_fields=["status", "output", "completed_at"])
    Playbook.objects.filter(pk=playbook.pk).update(run_count=F("run_count") + 1)
    audit(request or user, "response.run_playbook", target=playbook.name, action_id=parent.pk, status=parent.status)
    return parent


DEFAULT_PLAYBOOKS = [
    {
        "name": "Contain compromised host",
        "description": "Isolate the device, capture volatile evidence and notify the incident channel.",
        "target_kind": "asset",
        "steps": [
            {"action": "collect_forensics", "continue_on_error": True},
            {"action": "isolate_host"},
            {"action": "notify", "parameters": {"message": "Host isolated by containment playbook"}},
        ],
    },
    {
        "name": "Force global password reset",
        "description": "Force every identity to reset its password and revoke all refresh tokens.",
        "target_kind": "global",
        "steps": [
            {"action": "reset_password", "target_user": "*"},
            {"action": "revoke_sessions", "target_user": ""},
            {"action": "notify", "parameters": {"message": "Global password reset enforced"}},
        ],
    },
    {
        "name": "Compromised account response",
        "description": "Revoke sessions, reset the password and disable the account pending review.",
        "target_kind": "user",
        "steps": [
            {"action": "revoke_sessions"},
            {"action": "reset_password"},
            {"action": "disable_user"},
        ],
    },
    {
        "name": "Block indicator at perimeter",
        "description": "Push the indicator to firewall, DNS sinkhole and proxy blocklists.",
        "target_kind": "indicator",
        "steps": [
            {"action": "block_indicator"},
            {"action": "notify", "parameters": {"message": "Indicator blocked at perimeter"}},
        ],
    },
]


def ensure_default_playbooks():
    for spec in DEFAULT_PLAYBOOKS:
        Playbook.objects.get_or_create(name=spec["name"], defaults=spec)
