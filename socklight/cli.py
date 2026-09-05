"""
sockLight — SOCKS5 Dev Proxy — CLI entry point

Installed as the `socklight` command by pip. Also callable via `python run.py`
for development (run.py imports main from here).
"""

import argparse
import errno
import importlib
import socket
import sys


def _check_dependencies() -> None:
    missing = []
    for pkg, import_name in [
        ("anyio[trio]", "anyio"),
        ("textual", "textual"),
        ("rich", "rich"),
    ]:
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(pkg)
    if missing:
        print("Missing required packages:", file=sys.stderr)
        for pkg in missing:
            print(f"  {pkg}", file=sys.stderr)
        print("\nInstall with:", file=sys.stderr)
        print(f"  pip install {' '.join(missing)}", file=sys.stderr)
        sys.exit(1)


def _check_port(host: str, port: int) -> None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            print(f"Error: port {port} is already in use.", file=sys.stderr)
            print("Kill the existing process or use --port to choose another.", file=sys.stderr)
            sys.exit(1)
        raise
    finally:
        sock.close()


def _builtin_categories(name: str) -> str:
    """Return filesystem path to a built-in categories preset."""
    from importlib.resources import files as _pkg_files

    fname = "categories-simple.toml" if name == "simple" else "categories-full.toml"
    return str(_pkg_files("socklight") / "data" / fname)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOCKS5 development proxy with TUI dashboard",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Address to bind the proxy listener (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=1080,
        help="Port to listen on (default: 1080)",
    )
    parser.add_argument(
        "--rules-file",
        metavar="PATH",
        help=(
            "Load filter rules from a file at startup. "
            "Format: one 'deny/allow <pattern>' per line, "
            "'mode denylist|allowlist', '#' comments."
        ),
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help="Also write log output to this file (plain text, no colours).",
    )
    parser.add_argument(
        "--log-level",
        default="all",
        choices=["all", "connections", "denied", "errors", "none"],
        help="Log verbosity (default: all).",
    )

    cat_group = parser.add_mutually_exclusive_group()
    cat_group.add_argument(
        "--categories",
        choices=["simple", "full"],
        metavar="{simple,full}",
        help=(
            "Use built-in category definitions. "
            "'simple' = 10 broad categories; 'full' = 32 detailed categories (default when omitted)."
        ),
    )
    cat_group.add_argument(
        "--categories-file",
        metavar="PATH",
        help="Load category definitions from a custom TOML file.",
    )

    parser.add_argument(
        "--theme",
        metavar="NAME",
        help=(
            "Textual UI theme (e.g. nord, gruvbox, dracula, catppuccin-mocha, tokyo-night). "
            "Also saved to ~/.config/socklight/config.toml for future runs. "
            "You can also change the theme at runtime via Ctrl+P → Change theme."
        ),
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        default=None,
        metavar="N",
        help="Maximum number of concurrent proxied connections (default: unlimited).",
    )
    parser.add_argument(
        "--no-tui",
        action="store_true",
        help="Run without the TUI — log to stdout only. Good for use as a service.",
    )
    args = parser.parse_args()
    _check_dependencies()
    _check_port(args.host, args.port)

    # Resolve which categories file to use; default to built-in full preset
    if args.categories_file:
        categories_file = args.categories_file
    elif args.categories:
        categories_file = _builtin_categories(args.categories)
    else:
        categories_file = _builtin_categories("full")

    try:
        import uvloop
        uvloop.install()
    except ImportError:
        pass

    if args.no_tui:
        _run_headless(args, categories_file)
    else:
        from socklight.tui import LogLevel, ProxyApp

        app = ProxyApp(
            proxy_host=args.host,
            proxy_port=args.port,
            log_level=LogLevel(args.log_level),
            log_file=args.log_file,
            rules_file=args.rules_file,
            categories_file=categories_file,
            theme_name=args.theme,
            max_connections=args.max_connections,
        )
        app.run()


def _run_headless(args, categories_file: str | None) -> None:
    import signal
    import time

    import anyio

    from socklight.classifier import Classifier
    from socklight.filters import FilterEngine, FilterMode
    from socklight.server import ProxyServer
    from socklight.throttle import ThrottleEngine
    from socklight.tracker import ConnectionTracker
    from socklight.tui import LogLevel, _passes_level

    log_level = LogLevel(args.log_level)
    log_fh = open(args.log_file, "a", buffering=1) if args.log_file else None

    def log(msg: str) -> None:
        if not _passes_level(msg, log_level):
            return
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        print(line, flush=True)
        if log_fh:
            log_fh.write(line + "\n")

    engine = FilterEngine(FilterMode.DENYLIST)
    throttle_engine = ThrottleEngine()
    classifier = Classifier()

    if categories_file:
        try:
            n = classifier.load_file(categories_file)
            log(f"CATEGORIES loaded {n} from {categories_file}")
        except OSError as exc:
            print(f"Warning: cannot read categories file: {exc}", flush=True)

    if args.rules_file:
        try:
            n = engine.load_rules_file(args.rules_file)
            nt = throttle_engine.load_from_rules_file(args.rules_file)
            for name, state in engine.cat_overrides.items():
                classifier.set_cat_override(name, state)
            cats = len(engine.blocked_categories)
            throttle_msg = f", {nt} throttle rule(s)" if nt else ""
            log(f"RULES loaded {n} rule(s), {cats} blocked category/ies{throttle_msg} from {args.rules_file}")
        except OSError as exc:
            print(f"Warning: cannot read rules file: {exc}", flush=True)

    tracker = ConnectionTracker()
    server = ProxyServer(
        tracker=tracker,
        filter_engine=engine,
        classifier=classifier,
        throttle_engine=throttle_engine,
        host=args.host,
        port=args.port,
        max_connections=args.max_connections,
        log=log,
    )

    import os
    signal.signal(signal.SIGTERM, lambda *_: os.kill(os.getpid(), signal.SIGINT))

    try:
        anyio.run(server.start)
    except KeyboardInterrupt:
        log("Stopped.")
    finally:
        if log_fh:
            log_fh.close()


if __name__ == "__main__":
    main()
