from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sentinelueba.domain.events import EventType, TelemetryEvent, deterministic_event_id


@dataclass(frozen=True)
class SyntheticGenerationSummary:
    seed: int
    events: int
    user_id: str
    host_id: str
    start: datetime
    end: datetime
    anomaly_scenarios: list[str]
    scenario_manifest: list[dict[str, str]]


NORMAL_PROCESSES = [
    "editor.exe",
    "browser.exe",
    "terminal.exe",
    "mailclient.exe",
    "syncagent.exe",
    "updater.exe",
]


def generate_synthetic_events(
    seed: int = 42,
    start: datetime | None = None,
    hours: int = 24,
    user_id: str = "demo-user-001",
    host_id: str = "demo-host-001",
    include_anomalies: bool = True,
) -> tuple[list[TelemetryEvent], SyntheticGenerationSummary]:
    rng = random.Random(seed)
    start_time = (start or datetime(2026, 1, 5, 6, 0, tzinfo=UTC)).astimezone(UTC)
    events: list[TelemetryEvent] = []
    steps = hours * 12

    for step in range(steps):
        ts = start_time + timedelta(minutes=5 * step)
        hour = ts.hour
        work_factor = 1.0 if 8 <= hour <= 18 else 0.25
        process_count = max(1, int(rng.gauss(4 * work_factor + 1, 1.0)))
        network_count = max(0, int(rng.gauss(7 * work_factor + 1, 2.0)))
        cpu = min(95.0, max(3.0, rng.gauss(28 * work_factor + 8, 7.0)))
        ram = min(96.0, max(12.0, rng.gauss(46 + 10 * work_factor, 5.0)))

        for index in range(process_count):
            process = rng.choice(NORMAL_PROCESSES)
            events.append(
                _event(
                    ts,
                    EventType.PROCESS,
                    user_id,
                    host_id,
                    {
                        "process_name": process,
                        "pid": 2000 + step * 10 + index,
                        "parent_process": "explorer.exe",
                        "command_family": "interactive",
                    },
                    seed,
                    step,
                    f"process-{index}",
                )
            )

        if network_count:
            for index in range(network_count):
                events.append(
                    _event(
                        ts + timedelta(seconds=index),
                        EventType.NETWORK,
                        user_id,
                        host_id,
                        {
                            "remote_address": f"198.51.100.{rng.randint(10, 40)}",
                            "remote_port": rng.choice([443, 80, 53, 123]),
                            "protocol": "tcp",
                            "connection_count": rng.randint(1, 3),
                        },
                        seed,
                        step,
                        f"network-{index}",
                    )
                )

        events.append(
            _event(
                ts,
                EventType.SYSTEM_METRICS,
                user_id,
                host_id,
                {"cpu_percent": round(cpu, 2), "ram_percent": round(ram, 2)},
                seed,
                step,
                "metrics",
            )
        )

        if step % 72 == 0 and 8 <= hour <= 10:
            events.append(
                _event(
                    ts,
                    EventType.AUTHENTICATION,
                    user_id,
                    host_id,
                    {"result": "success", "method": "local"},
                    seed,
                    step,
                    "auth-success",
                )
            )

    scenarios: list[str] = []
    scenario_manifest: list[dict[str, str]] = []
    if include_anomalies:
        scenarios = [
            "rare_process",
            "outbound_connection_spike",
            "atypical_time_activity",
            "cpu_ram_spike",
            "failed_login_series",
        ]
        scenario_manifest = _scenario_manifest(start_time)
        _inject_anomalies(events, start_time, seed, user_id, host_id)

    events.sort(key=lambda event: (event.timestamp, event.event_id))
    summary = SyntheticGenerationSummary(
        seed=seed,
        events=len(events),
        user_id=user_id,
        host_id=host_id,
        start=start_time,
        end=start_time + timedelta(hours=hours),
        anomaly_scenarios=scenarios,
        scenario_manifest=scenario_manifest,
    )
    return events, summary


def _scenario_manifest(start_time: datetime) -> list[dict[str, str]]:
    scenarios = [
        ("rare_process", start_time + timedelta(hours=18)),
        ("outbound_connection_spike", start_time + timedelta(hours=19)),
        ("atypical_time_activity", start_time + timedelta(hours=21, minutes=15)),
        ("cpu_ram_spike", start_time + timedelta(hours=22)),
        ("failed_login_series", start_time + timedelta(hours=23)),
    ]
    return [
        {
            "name": name,
            "window_start": window_start.isoformat(),
            "window_end": (window_start + timedelta(minutes=15)).isoformat(),
        }
        for name, window_start in scenarios
    ]


def _event(
    ts: datetime,
    event_type: EventType,
    user_id: str,
    host_id: str,
    payload: dict[str, object],
    seed: int,
    step: int,
    suffix: str,
) -> TelemetryEvent:
    event_id = deterministic_event_id(
        [str(seed), ts.isoformat(), event_type.value, user_id, host_id, suffix]
    )
    return TelemetryEvent(
        event_id=event_id,
        timestamp=ts,
        event_type=event_type,
        user_id=user_id,
        host_id=host_id,
        source="synthetic-demo",
        payload=payload,
        synthetic=True,
    )


def _inject_anomalies(
    events: list[TelemetryEvent],
    start_time: datetime,
    seed: int,
    user_id: str,
    host_id: str,
) -> None:
    rare_ts = start_time + timedelta(hours=18, minutes=10)
    for index in range(8):
        events.append(
            _event(
                rare_ts + timedelta(seconds=index),
                EventType.PROCESS,
                user_id,
                host_id,
                {
                    "process_name": f"diagnostic-tool-{index}.exe",
                    "pid": 9000 + index,
                    "parent_process": "cmd.exe",
                    "command_family": "admin_tooling",
                },
                seed,
                5000,
                f"rare-process-{index}",
            )
        )

    net_ts = start_time + timedelta(hours=19, minutes=5)
    for index in range(55):
        events.append(
            _event(
                net_ts + timedelta(seconds=index),
                EventType.NETWORK,
                user_id,
                host_id,
                {
                    "remote_address": f"203.0.113.{index % 250}",
                    "remote_port": 30000 + index,
                    "protocol": "tcp",
                    "connection_count": 1,
                },
                seed,
                5001,
                f"net-spike-{index}",
            )
        )

    night_ts = start_time + timedelta(hours=21, minutes=30)
    for index in range(20):
        events.append(
            _event(
                night_ts + timedelta(seconds=index),
                EventType.PROCESS if index % 2 == 0 else EventType.NETWORK,
                user_id,
                host_id,
                {
                    "process_name": "browser.exe",
                    "pid": 9500 + index,
                    "parent_process": "explorer.exe",
                    "command_family": "interactive",
                }
                if index % 2 == 0
                else {
                    "remote_address": f"198.51.100.{90 + index}",
                    "remote_port": 443,
                    "protocol": "tcp",
                    "connection_count": 2,
                },
                seed,
                5002,
                f"night-{index}",
            )
        )

    metrics_ts = start_time + timedelta(hours=22)
    for index in range(3):
        events.append(
            _event(
                metrics_ts + timedelta(minutes=5 * index),
                EventType.SYSTEM_METRICS,
                user_id,
                host_id,
                {"cpu_percent": 96.0 - index, "ram_percent": 94.0 - index},
                seed,
                5003,
                f"metrics-spike-{index}",
            )
        )

    auth_ts = start_time + timedelta(hours=23, minutes=10)
    for index in range(12):
        events.append(
            _event(
                auth_ts + timedelta(seconds=index),
                EventType.AUTHENTICATION,
                user_id,
                host_id,
                {"result": "failure", "method": "local", "failure_reason": "bad_password"},
                seed,
                5004,
                f"auth-fail-{index}",
            )
        )
