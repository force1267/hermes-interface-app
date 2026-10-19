"""Adapter entry point: python3 -m p5serve.serve /etc/.../settings.json."""
import json
import sys

from p5serve.adapter import AdapterServer
from p1transport.hermes_provider import HermesProvider


def main():
    settings_path = sys.argv[1]
    with open(settings_path) as f:
        cfg = json.load(f)
    provider = None
    if cfg["provider"]["enabled"]:
        with open(cfg["upstream"]["service_secret_file"]) as f:
            secret = f.read().strip()
        provider = HermesProvider(
            cfg["provider"],
            cfg["adapter"]["state_db"] + ".provider.sqlite3",
            secret, account_id=cfg["auth"]["account_id"])
        provider.start(cfg["provider"]["bind_host"],
                       cfg["provider"]["bind_port"])
    server = AdapterServer(settings_path)
    server.start()
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        if provider is not None:
            provider.stop()


if __name__ == "__main__":
    main()
