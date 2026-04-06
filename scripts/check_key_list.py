#!/usr/bin/env python3
from __future__ import annotations

import argparse
import heapq
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen


DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
]
DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"
DEFAULT_OUTPUT = Path("artifacts/short-key-list.txt")
DEFAULT_REPORT = Path("artifacts/check-report.json")
DEFAULT_RATINGS = Path("state/key-ratings.json")
DEFAULT_EXTRA_LIMITS = [100, 50]
USER_AGENT = "short-key-list-checker/1.0"


@dataclass
class CheckResult:
    entry: str
    ok: bool
    stage: str
    detail: str
    elapsed_ms: int


@dataclass
class KeyRating:
    entry: str
    checks: int
    successes: int
    failures: int
    success_streak: int
    failure_streak: int
    last_ok: bool
    last_checked_at: int
    last_elapsed_ms: int
    avg_success_latency_ms: float
    latency_ema_ms: float
    recent_score: float
    rating: float


def env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return default


def fetch_text(url: str) -> str:
    last_error: Exception | None = None
    for attempt in range(5):
        try:
            req = Request(url, headers={"User-Agent": USER_AGENT})
            with urlopen(req, timeout=30) as response:
                return response.read().decode("utf-8", "replace")
        except Exception as exc:  # pragma: no cover - network path
            last_error = exc
            if attempt == 4:
                raise
            time.sleep(2 * (attempt + 1))
    assert last_error is not None
    raise last_error


def parse_sources(args: argparse.Namespace) -> list[str]:
    if args.sources:
        return args.sources
    env_sources = env_first("KEY_LIST_SOURCES", "WHITELIST_SOURCES")
    if env_sources:
        return [item.strip() for item in env_sources.split(",") if item.strip()]
    return DEFAULT_SOURCES


def collect_entries(sources: list[str]) -> list[str]:
    seen: set[str] = set()
    entries: list[str] = []
    for source in sources:
        for line in fetch_text(source).splitlines():
            entry = line.strip()
            if not entry or entry in seen:
                continue
            seen.add(entry)
            entries.append(entry)
    return entries


def parse_vless(entry: str) -> dict[str, Any]:
    parsed = urlparse(entry)
    if parsed.scheme != "vless":
        raise ValueError(f"unsupported scheme: {parsed.scheme or 'missing'}")
    if not parsed.username:
        raise ValueError("missing uuid")
    if not parsed.hostname or not parsed.port:
        raise ValueError("missing host or port")

    params = {key: values[-1] for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}
    return {
        "entry": entry,
        "uuid": unquote(parsed.username),
        "address": parsed.hostname,
        "port": parsed.port,
        "tag": unquote(parsed.fragment) if parsed.fragment else "",
        "params": params,
    }


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_int_csv(value: str) -> list[int]:
    limits: list[int] = []
    for item in split_csv(value):
        limits.append(int(item))
    return limits


def derive_output_path(output: Path, limit: int) -> Path:
    if output.suffix:
        return output.with_name(f"{output.stem}-{limit}{output.suffix}")
    return output.with_name(f"{output.name}-{limit}")


def normalize_limits(primary_limit: int, extra_limits: list[int]) -> list[int]:
    limits = sorted({primary_limit, *extra_limits}, reverse=True)
    if any(limit <= 0 for limit in limits):
        raise SystemExit("all limits must be positive integers")
    return limits


def build_stream_settings(config: dict[str, Any]) -> dict[str, Any]:
    params = config["params"]
    network = params.get("type", "tcp")
    security = params.get("security", "none")

    stream: dict[str, Any] = {
        "network": network,
        "security": security,
    }

    if security == "reality":
        stream["realitySettings"] = {
            "serverName": params.get("sni", ""),
            "fingerprint": params.get("fp", "chrome"),
            "publicKey": params.get("pbk", ""),
            "shortId": params.get("sid", ""),
            "spiderX": params.get("spx", "/"),
        }
    elif security == "tls":
        stream["tlsSettings"] = {
            "serverName": params.get("sni", ""),
            "fingerprint": params.get("fp", "chrome"),
            "alpn": split_csv(params.get("alpn", "")),
        }

    if network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName", ""),
            "authority": params.get("authority", ""),
            "multiMode": params.get("mode", "") == "multi",
        }
    elif network == "ws":
        stream["wsSettings"] = {
            "path": params.get("path", "/"),
            "headers": {"Host": params.get("host", "")} if params.get("host") else {},
        }
    elif network == "tcp" and params.get("headerType"):
        stream["tcpSettings"] = {"header": {"type": params["headerType"]}}

    return stream


def build_xray_config(config: dict[str, Any], socks_port: int) -> dict[str, Any]:
    params = config["params"]
    outbound_user: dict[str, Any] = {
        "id": config["uuid"],
        "encryption": params.get("encryption", "none"),
    }
    if params.get("flow"):
        outbound_user["flow"] = params["flow"]

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": config["address"],
                            "port": config["port"],
                            "users": [outbound_user],
                        }
                    ]
                },
                "streamSettings": build_stream_settings(config),
            },
            {"tag": "direct", "protocol": "freedom"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "inboundTag": ["socks-in"], "outboundTag": "proxy"}],
        },
    }


def wait_for_port(host: str, port: int, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def run_curl(socks_port: int, test_url: str, timeout_s: int) -> tuple[bool, str]:
    cmd = [
        "curl",
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}",
        "--proxy",
        f"socks5h://127.0.0.1:{socks_port}",
        "--max-time",
        str(timeout_s),
        test_url,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return False, proc.stderr.strip() or f"curl exit {proc.returncode}"
    code = proc.stdout.strip()
    if code != "204":
        return False, f"unexpected status {code or 'empty'}"
    return True, "204"


def maybe_tcp_precheck(address: str, port: int, timeout_s: float, enabled: bool) -> tuple[bool, str]:
    if not enabled:
        return True, "skipped"
    try:
        with socket.create_connection((address, port), timeout=timeout_s):
            return True, "tcp ok"
    except OSError as exc:
        return False, str(exc)


def check_entry(
    entry: str,
    xray_bin: str,
    test_url: str,
    curl_timeout_s: int,
    startup_timeout_s: float,
    tcp_precheck: bool,
    port_base: int,
    slot: int,
) -> CheckResult:
    started = time.monotonic()
    try:
        parsed = parse_vless(entry)
    except Exception as exc:
        return CheckResult(entry=entry, ok=False, stage="parse", detail=str(exc), elapsed_ms=elapsed_ms(started))

    tcp_ok, tcp_detail = maybe_tcp_precheck(parsed["address"], parsed["port"], startup_timeout_s, tcp_precheck)
    if not tcp_ok:
        return CheckResult(entry=entry, ok=False, stage="tcp", detail=tcp_detail, elapsed_ms=elapsed_ms(started))

    socks_port = port_base + slot
    with tempfile.TemporaryDirectory(prefix="short-key-list-check-") as tmp_dir:
        config_path = Path(tmp_dir) / "xray-config.json"
        config_path.write_text(json.dumps(build_xray_config(parsed, socks_port)), encoding="utf-8")
        proc = subprocess.Popen(
            [xray_bin, "run", "-config", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            if not wait_for_port("127.0.0.1", socks_port, startup_timeout_s):
                return CheckResult(
                    entry=entry,
                    ok=False,
                    stage="startup",
                    detail="xray socks inbound did not start",
                    elapsed_ms=elapsed_ms(started),
                )
            ok, detail = run_curl(socks_port, test_url, curl_timeout_s)
            return CheckResult(
                entry=entry,
                ok=ok,
                stage="proxy" if ok else "request",
                detail=detail,
                elapsed_ms=elapsed_ms(started),
            )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)


def elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def load_ratings(path: Path) -> dict[str, KeyRating]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    ratings: dict[str, KeyRating] = {}
    for item in raw.get("ratings", []):
        entry = item.get("entry")
        if not entry:
            continue
        ratings[entry] = KeyRating(
            entry=entry,
            checks=int(item.get("checks", 0)),
            successes=int(item.get("successes", 0)),
            failures=int(item.get("failures", 0)),
            success_streak=int(item.get("success_streak", 0)),
            failure_streak=int(item.get("failure_streak", 0)),
            last_ok=bool(item.get("last_ok", False)),
            last_checked_at=int(item.get("last_checked_at", 0)),
            last_elapsed_ms=int(item.get("last_elapsed_ms", 0)),
            avg_success_latency_ms=float(item.get("avg_success_latency_ms", 0.0)),
            latency_ema_ms=float(item.get("latency_ema_ms", 0.0)),
            recent_score=float(item.get("recent_score", 0.5)),
            rating=float(item.get("rating", 0.5)),
        )
    return ratings


def save_ratings(path: Path, ratings: dict[str, KeyRating]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated_at": int(time.time()),
        "ratings": [asdict(item) for item in ratings.values()],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(value, maximum))


def speed_score(latency_ms: float) -> float:
    if latency_ms <= 0:
        return 0.35
    fast_ms = 800.0
    slow_ms = 6000.0
    normalized = clamp((latency_ms - fast_ms) / (slow_ms - fast_ms), 0.0, 1.0)
    return 1.0 - normalized


def calculate_rating(record: KeyRating) -> float:
    checks = max(0, record.checks)
    successes = max(0, record.successes)
    base = (successes + 1.0) / (checks + 2.0)
    recent_score = clamp(record.recent_score, 0.0, 1.0)
    latency_reference = record.latency_ema_ms or record.avg_success_latency_ms
    latency_component = speed_score(latency_reference)

    streak_bonus = min(record.success_streak, 5) * 0.045
    failure_penalty = min(record.failure_streak, 5) * 0.09
    experience_bonus = min(checks, 20) * 0.008
    slow_penalty = clamp((latency_reference - 2500.0) / 3000.0, 0.0, 1.0) * 0.2 if latency_reference > 0 else 0.0

    rating = (
        0.55 * base
        + 0.3 * recent_score
        + 0.25 * latency_component
        + streak_bonus
        + experience_bonus
        - failure_penalty
        - slow_penalty
    )
    return round(max(0.05, min(rating, 2.0)), 4)


def update_rating(record: KeyRating | None, result: CheckResult, checked_at: int) -> KeyRating:
    if record is None:
        record = KeyRating(
            entry=result.entry,
            checks=0,
            successes=0,
            failures=0,
            success_streak=0,
            failure_streak=0,
            last_ok=False,
            last_checked_at=0,
            last_elapsed_ms=0,
            avg_success_latency_ms=0.0,
            latency_ema_ms=0.0,
            recent_score=0.5,
            rating=0.5,
        )

    previous_successes = record.successes
    record.checks += 1
    record.last_ok = result.ok
    record.last_checked_at = checked_at
    record.last_elapsed_ms = result.elapsed_ms
    record.recent_score = record.recent_score * 0.65 + (1.0 if result.ok else 0.0) * 0.35

    if result.ok:
        record.successes += 1
        record.success_streak += 1
        record.failure_streak = 0
        if previous_successes <= 0 or record.avg_success_latency_ms <= 0:
            record.avg_success_latency_ms = float(result.elapsed_ms)
        else:
            record.avg_success_latency_ms = (
                (record.avg_success_latency_ms * previous_successes) + result.elapsed_ms
            ) / record.successes

        if record.latency_ema_ms <= 0:
            record.latency_ema_ms = float(result.elapsed_ms)
        else:
            record.latency_ema_ms = record.latency_ema_ms * 0.7 + result.elapsed_ms * 0.3
    else:
        record.failures += 1
        record.failure_streak += 1
        record.success_streak = 0

    record.rating = calculate_rating(record)
    return record


def weighted_sample_without_replacement(
    entries: list[str],
    rating_map: dict[str, KeyRating],
    limit: int,
    randomizer: random.Random | random.SystemRandom,
) -> list[str]:
    if limit <= 0 or not entries:
        return []
    if len(entries) <= limit:
        return entries[:]

    weighted: list[tuple[float, str]] = []
    for entry in entries:
        rating = rating_map.get(entry)
        weight = rating.rating if rating else 0.25
        ticket = randomizer.random() ** (1.0 / max(weight, 1e-6))
        weighted.append((ticket, entry))

    return [entry for _, entry in heapq.nlargest(limit, weighted)]


def run_checks(args: argparse.Namespace) -> int:
    if shutil.which(args.xray_bin) is None:
        raise SystemExit(f"xray binary not found: {args.xray_bin}")
    if shutil.which("curl") is None:
        raise SystemExit("curl binary not found")

    sources = parse_sources(args)
    randomizer = random.Random(args.seed) if args.seed is not None else random.SystemRandom()
    entries = collect_entries(sources)
    randomizer.shuffle(entries)
    ratings = load_ratings(args.ratings)

    passed: list[str] = []
    results: list[CheckResult] = []
    workers = max(1, args.workers)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_entry: dict[Any, str] = {}
        for index, entry in enumerate(entries):
            future = executor.submit(
                check_entry,
                entry,
                args.xray_bin,
                args.test_url,
                args.curl_timeout,
                args.startup_timeout,
                args.tcp_precheck,
                args.port_base,
                index % workers,
            )
            future_to_entry[future] = entry

        for future in as_completed(future_to_entry):
            result = future.result()
            checked_at = int(time.time())
            results.append(result)
            ratings[result.entry] = update_rating(ratings.get(result.entry), result, checked_at)
            if result.ok:
                passed.append(result.entry)
            print(f"[{result.stage}] {'OK' if result.ok else 'FAIL'} {result.detail}")

    requested_limits = normalize_limits(args.limit, args.extra_limits)
    max_limit = requested_limits[0] if requested_limits else args.limit
    ranked_selection = weighted_sample_without_replacement(passed, ratings, max_limit, randomizer)

    outputs: dict[int, Path] = {}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for limit in sorted(requested_limits, reverse=True):
        output_path = args.output if limit == args.limit else derive_output_path(args.output, limit)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            "\n".join(ranked_selection[:limit]) + ("\n" if ranked_selection[:limit] else ""),
            encoding="utf-8",
        )
        outputs[limit] = output_path

    args.report.parent.mkdir(parents=True, exist_ok=True)
    save_ratings(args.ratings, ratings)
    args.report.write_text(
        json.dumps(
            {
                "checked_at": int(time.time()),
                "sources": sources,
                "counts": {
                    "candidates": len(entries),
                    "passed": len(passed),
                    "selected": len(ranked_selection[:args.limit]),
                },
                "selected_limit": args.limit,
                "selected_limits": requested_limits,
                "outputs": {str(limit): str(path) for limit, path in outputs.items()},
                "test_url": args.test_url,
                "ratings_file": str(args.ratings),
                "top_rated": [
                    {
                        "entry": item.entry,
                        "rating": item.rating,
                        "checks": item.checks,
                        "successes": item.successes,
                        "failures": item.failures,
                        "recent_score": item.recent_score,
                        "avg_success_latency_ms": round(item.avg_success_latency_ms, 1),
                        "latency_ema_ms": round(item.latency_ema_ms, 1),
                    }
                    for item in sorted(ratings.values(), key=lambda value: value.rating, reverse=True)[:20]
                ],
                "results": [asdict(item) for item in results],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    output_summary = ", ".join(f"{limit}:{path}" for limit, path in sorted(outputs.items(), reverse=True))
    print(
        f"candidates={len(entries)} passed={len(passed)} selected={len(ranked_selection[:args.limit])} "
        f"outputs={output_summary} report={args.report}"
    )
    return 0 if passed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate upstream VLESS keys with xray and generate_204.")
    parser.add_argument("--source", dest="sources", action="append", help="Override source URL. Can be used multiple times.")
    parser.add_argument("--output", type=Path, default=Path(env_first("OUTPUT_PATH", default=str(DEFAULT_OUTPUT))))
    parser.add_argument("--report", type=Path, default=Path(env_first("REPORT_PATH", default=str(DEFAULT_REPORT))))
    parser.add_argument("--ratings", type=Path, default=Path(env_first("RATINGS_PATH", default=str(DEFAULT_RATINGS))))
    parser.add_argument(
        "--limit",
        type=int,
        default=int(env_first("KEY_LIST_LIMIT", "WHITELIST_LIMIT", default="200")),
    )
    parser.add_argument(
        "--extra-limit",
        dest="extra_limits",
        action="append",
        type=int,
        default=parse_int_csv(env_first("EXTRA_KEY_LIST_LIMITS", default=",".join(str(item) for item in DEFAULT_EXTRA_LIMITS))),
        help="Additional list sizes to generate from the same checked pool.",
    )
    parser.add_argument("--workers", type=int, default=int(env_first("WORKERS", default="4")))
    parser.add_argument("--port-base", type=int, default=int(env_first("PORT_BASE", default="21080")))
    parser.add_argument("--xray-bin", default=env_first("XRAY_BIN", default="xray"))
    parser.add_argument("--test-url", default=env_first("TEST_URL", default=DEFAULT_TEST_URL))
    parser.add_argument("--curl-timeout", type=int, default=int(env_first("CURL_TIMEOUT", default="10")))
    parser.add_argument("--startup-timeout", type=float, default=float(env_first("STARTUP_TIMEOUT", default="4")))
    parser.add_argument("--tcp-precheck", action="store_true", help="Cheap TCP connect before xray check.")
    parser.add_argument("--seed", type=int, help="Optional deterministic output seed.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not args.tcp_precheck:
        args.tcp_precheck = env_first("TCP_PRECHECK", default="").lower() in {"1", "true", "yes"}
    try:
        return run_checks(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
