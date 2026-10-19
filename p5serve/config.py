"""P5 runtime settings: every tunable is a config entry (R4 / S028).

load() reads the JSON file, validates presence and shape of every
required section, and refuses readiness (raises SettingsError) when a
required entry is missing or invalid. No numeric policy constant lives
in code; operational defaults below exist ONLY as this template file.
p4ops owns policy.file values (queue depth etc.), not this module.
"""
import json
import os

REQUIRED = {
    "adapter": ("bind_host", "bind_port", "path", "origin", "host",
                "subprotocol", "state_db", "release_id",
                "max_connections", "http_header_bytes",
                "http_body_bytes", "http_timeout_seconds",
                "frame_bytes", "json_depth", "write_timeout_seconds",
                "sqlite_busy_seconds", "outbound_messages",
                "outbound_bytes", "queue_safety_messages",
                "queue_safety_bytes", "retry_after_seconds",
                "ws_ping_seconds",
                "ws_pong_timeout_seconds", "session_check_seconds",
                "credential_check_seconds", "reconnect_base_seconds",
                "reconnect_factor", "reconnect_cap_seconds",
                "reconnect_stable_seconds", "draft_bytes",
                "frame_min_height", "frame_max_height",
                "frame_ready_timeout_seconds",
                "upstream_check_seconds", "close_log_entries"),
    "auth": ("account_id", "password_file", "cookie_name",
             "preauth_cookie_name", "token_bytes", "csrf_bytes",
             "salt_bytes", "scrypt_n", "scrypt_r", "scrypt_p",
             "scrypt_dklen", "absolute_seconds", "idle_seconds",
             "preauth_seconds", "login_window_seconds",
             "login_attempts_per_account", "login_attempts_per_peer",
             "command_window_seconds", "commands_per_session"),
    "upstream": ("host", "port", "service_secret_file",
                 "connect_timeout_seconds", "write_timeout_seconds",
                 "read_timeout_seconds", "tcp_keepalive",
                 "tcp_idle_seconds", "tcp_interval_seconds",
                 "tcp_probes"),
    "provider": ("enabled", "bind_host", "bind_port",
                 "hermes_executable", "hermes_home", "workspace",
                 "agent_timeout_seconds", "termination_grace_seconds",
                 "output_bytes", "stdout_line_bytes",
                 "actions_enabled", "drawer_writes_enabled"),
    "policy": ("file",),
}

INT_KEYS = {
    ("adapter", "bind_port"), ("adapter", "max_connections"),
    ("adapter", "http_header_bytes"), ("adapter", "http_body_bytes"),
    ("adapter", "http_timeout_seconds"), ("adapter", "frame_bytes"),
    ("adapter", "json_depth"), ("adapter", "write_timeout_seconds"),
    ("adapter", "sqlite_busy_seconds"), ("adapter", "outbound_messages"),
    ("adapter", "outbound_bytes"), ("adapter", "queue_safety_messages"),
    ("adapter", "queue_safety_bytes"), ("adapter", "retry_after_seconds"),
    ("adapter", "ws_ping_seconds"),
    ("adapter", "ws_pong_timeout_seconds"),
    ("adapter", "session_check_seconds"),
    ("adapter", "credential_check_seconds"),
    ("adapter", "reconnect_base_seconds"),
    ("adapter", "reconnect_factor"),
    ("adapter", "reconnect_cap_seconds"),
    ("adapter", "reconnect_stable_seconds"), ("adapter", "draft_bytes"),
    ("adapter", "frame_min_height"), ("adapter", "frame_max_height"),
    ("adapter", "frame_ready_timeout_seconds"),
    ("adapter", "upstream_check_seconds"),
    ("adapter", "close_log_entries"),
    ("auth", "token_bytes"), ("auth", "csrf_bytes"),
    ("auth", "salt_bytes"), ("auth", "scrypt_n"), ("auth", "scrypt_r"),
    ("auth", "scrypt_p"), ("auth", "scrypt_dklen"),
    ("auth", "absolute_seconds"), ("auth", "idle_seconds"),
    ("auth", "preauth_seconds"), ("auth", "login_window_seconds"),
    ("auth", "login_attempts_per_account"),
    ("auth", "login_attempts_per_peer"),
    ("auth", "command_window_seconds"), ("auth", "commands_per_session"),
    ("upstream", "port"), ("upstream", "connect_timeout_seconds"),
    ("upstream", "write_timeout_seconds"),
    ("upstream", "read_timeout_seconds"),
    ("upstream", "tcp_idle_seconds"), ("upstream", "tcp_interval_seconds"),
    ("upstream", "tcp_probes"), ("provider", "bind_port"),
    ("provider", "agent_timeout_seconds"),
    ("provider", "termination_grace_seconds"),
    ("provider", "output_bytes"), ("provider", "stdout_line_bytes"),
}


class SettingsError(Exception):
    pass


def load(path):
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        raise SettingsError(f"settings-unreadable: {e}")
    if not isinstance(cfg, dict):
        raise SettingsError("settings-must-be-object")
    for section, keys in REQUIRED.items():
        if section not in cfg or not isinstance(cfg[section], dict):
            raise SettingsError(f"settings-missing-section: {section}")
        for key in keys:
            if key not in cfg[section]:
                raise SettingsError(
                    f"settings-missing-entry: {section}.{key}")
    for section, key in INT_KEYS:
        val = cfg[section][key]
        if not isinstance(val, int) or isinstance(val, bool) \
                or val < 0:
            raise SettingsError(
                f"settings-bad-entry: {section}.{key}")
    if cfg["adapter"]["bind_host"] != "127.0.0.1":
        raise SettingsError("settings-adapter-must-bind-loopback")
    if cfg["adapter"]["path"] != "/app/ws":
        raise SettingsError("settings-bad-path")
    for name in ("cookie_name", "preauth_cookie_name"):
        if not cfg["auth"][name].startswith("__Host-"):
            raise SettingsError("settings-cookie-must-be-host-prefix")
    for flag in ("tcp_keepalive",):
        if not isinstance(cfg["upstream"][flag], bool):
            raise SettingsError(f"settings-bad-entry: upstream.{flag}")
    for flag in ("enabled", "actions_enabled",
                 "drawer_writes_enabled"):
        if not isinstance(cfg["provider"][flag], bool):
            raise SettingsError(f"settings-bad-entry: provider.{flag}")
    return cfg


def template_path():
    return os.path.join(os.path.dirname(__file__),
                        "settings.template.json")
