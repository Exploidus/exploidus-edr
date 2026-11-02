"""Command-line interface for Exploidus EDR."""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from edr.config import Config, DEFAULT_CONFIG_PATH
from edr.engine.scanner import Scanner, ScanResult, ThreatLevel
from edr.engine.monitor import RealtimeMonitor
from edr.engine.behavior import BehaviorMonitor, BehaviorAlert, scan_all_processes
from edr.engine.updater import SignatureUpdater
from edr.quarantine.vault import QuarantineVault
from edr.reports.logger import ScanLogger, setup_logging

console = Console()


def _load_config(config_path: Optional[str]) -> Config:
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    return Config.load(path)


def _fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))



# Root group

@click.group()
@click.version_option(version="1.0.0", prog_name="exploidus-edr")
def main() -> None:
    """Exploidus EDR - High-Integrity Endpoint Detection & Response and Antivirus Suite."""



# scan


@main.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--recursive/--no-recursive", default=True, show_default=True)
@click.option("--config", default=None, metavar="FILE")
@click.option("--quarantine", is_flag=True, help="Auto-quarantine MALICIOUS files")
@click.option("--verbose", "-v", is_flag=True, help="Show all files including clean")
def scan(paths, recursive, config, quarantine, verbose) -> None:
    """Scan files or directories for malware."""
    cfg = _load_config(config)
    setup_logging(Path(cfg.log_dir), logging.DEBUG if verbose else logging.WARNING)

    scanner = Scanner(cfg)
    vault = QuarantineVault(Path(cfg.quarantine_dir)) if quarantine else None
    scan_paths = [Path(p) for p in paths]
    total = threats = errors = 0

    threat_table = Table(title="Detected Threats", show_lines=True, border_style="red")
    threat_table.add_column("File", style="cyan", max_width=55)
    threat_table.add_column("Level", justify="center")
    threat_table.add_column("Threat Name", style="red")
    threat_table.add_column("ms", justify="right", style="dim")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as prog:
        task = prog.add_task("Scanning...", total=None)

        for result in scanner.scan_paths(scan_paths, recursive=recursive):
            total += 1
            prog.update(task, description=f"Scanned {total} files...")

            if result.error and not result.is_threat:
                errors += 1
                continue

            if result.is_threat:
                threats += 1
                level_str = (
                    "[bold red]MALICIOUS[/bold red]"
                    if result.threat_level == ThreatLevel.MALICIOUS
                    else "[yellow]SUSPICIOUS[/yellow]"
                )
                threat_table.add_row(
                    Path(result.path).name,
                    level_str,
                    result.threat_name or "",
                    f"{result.scan_duration_ms:.0f}",
                )
                if quarantine and vault and result.threat_level == ThreatLevel.MALICIOUS:
                    try:
                        vault.quarantine(
                            Path(result.path), result.threat_name, result.md5, result.sha256
                        )
                        console.print(f"  [green]Quarantined:[/green] {result.path}")
                    except Exception as exc:
                        console.print(f"  [red]Quarantine failed:[/red] {exc}")

    if threats:
        console.print(threat_table)
    else:
        console.print("\n[bold green]No threats found.[/bold green]")

    console.print(
        f"\n[bold]Summary:[/bold] {total} files | "
        f"[red]{threats} threat(s)[/red] | {errors} skipped"
    )
    sys.exit(1 if threats else 0)



# monitor


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--config", default=None, metavar="FILE")
@click.option("--behavior", is_flag=True, help="Also run behavioral process monitor")
@click.option("--auto-quarantine", "auto_q", is_flag=True)
def monitor(paths, config, behavior, auto_q) -> None:
    """Start real-time filesystem (and optionally behavioral) monitoring."""
    cfg = _load_config(config)
    setup_logging(Path(cfg.log_dir))

    watch = list(paths) or cfg.monitor_paths
    if not watch:
        console.print(
            "[red]Error:[/red] Specify paths to watch or set monitor_paths in config."
        )
        sys.exit(1)

    scanner = Scanner(cfg)
    vault = QuarantineVault(Path(cfg.quarantine_dir))

    def on_file_threat(result: ScanResult) -> None:
        console.print(
            f"[bold red][FILE THREAT][/bold red] "
            f"{result.threat_level.value.upper()} | {result.threat_name} | {result.path}"
        )
        if (auto_q or cfg.auto_quarantine) and result.threat_level == ThreatLevel.MALICIOUS:
            try:
                vault.quarantine(
                    Path(result.path), result.threat_name, result.md5, result.sha256
                )
                console.print("  [green]Auto-quarantined.[/green]")
            except Exception as exc:
                console.print(f"  [red]Quarantine failed:[/red] {exc}")

    def on_behavior_alert(alert: BehaviorAlert) -> None:
        console.print(
            f"[bold yellow][BEHAVIOR][/bold yellow] "
            f"PID {alert.pid} | {alert.process_name} | score={alert.score} | "
            f"{alert.flags[0] if alert.flags else 'suspicious'}"
        )

    mon = RealtimeMonitor(scanner, cfg, on_threat=on_file_threat)
    mon.start(watch)

    bhv_mon: Optional[BehaviorMonitor] = None
    if behavior or cfg.behavior_monitor_enabled:
        bhv_mon = BehaviorMonitor(
            on_alert=on_behavior_alert,
            scan_interval=cfg.behavior_scan_interval,
        )
        bhv_mon.start()
        console.print("[green]Behavioral process monitor active.[/green]")

    console.print(
        f"[green]Watching {len(watch)} path(s). Press Ctrl+C to stop.[/green]"
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        mon.stop()
        if bhv_mon:
            bhv_mon.stop()
        console.print("\n[yellow]Monitor stopped.[/yellow]")



# update  (ClamAV free signature database)


@main.command()
@click.option("--config", default=None, metavar="FILE")
@click.option("--include-main", is_flag=True, help="Also download main.cvd (~160 MB)")
@click.option("--force", is_flag=True, help="Re-download even if updated today")
@click.option("--status", "show_status", is_flag=True, help="Show current DB status only")
def update(config, include_main, force, show_status) -> None:
    """Update malware signature databases from ClamAV (free, no API key)."""
    cfg = _load_config(config)

    def cli_log_status(msg: str) -> None:
        console.print(msg)

    updater = SignatureUpdater(
        cache_dir   = Path(cfg.clamav_cache_dir),
        sig_db_path = Path(cfg.signature_db),
        on_log      = cli_log_status,
    )

    if show_status:
        st = updater.status()
        console.print(f"\n[bold]Signature database:[/bold] {st['db_path']}")
        console.print(f"[bold]Total signatures:[/bold] {st['total_signatures']:,}\n")

        if st["databases"]:
            t = Table(show_lines=True)
            t.add_column("Database")
            t.add_column("Signatures", justify="right")
            t.add_column("Size", justify="right")
            t.add_column("Last Updated")
            for name, info in st["databases"].items():
                t.add_row(
                    name,
                    f"{info['signatures']:,}",
                    f"{info['size_mb']} MB",
                    info["last_updated"],
                )
            console.print(t)
        else:
            console.print("[yellow]No ClamAV databases downloaded yet. Run: xedr update[/yellow]")
        return

    console.print(
        "[bold]Downloading ClamAV signature databases (free, no API key)...[/bold]"
    )
    if include_main:
        console.print("[yellow]Note: main.cvd is ~160 MB and may take a few minutes.[/yellow]")

    total = updater.run(include_main=include_main, force=force)
    console.print(f"\n[bold green]Signatures ready: {total:,} total.[/bold green]")



# behavior  (one-shot process scan)


@main.command()
def behavior() -> None:
    """Scan all currently running processes for suspicious behavior."""
    console.print("[bold]Scanning running processes...[/bold]")
    alerts = scan_all_processes()

    if not alerts:
        console.print("[bold green]No suspicious processes found.[/bold green]")
        return

    t = Table(title=f"Suspicious Processes ({len(alerts)})", show_lines=True)
    t.add_column("PID", justify="right", style="dim")
    t.add_column("Process")
    t.add_column("Verdict")
    t.add_column("Score", justify="right")
    t.add_column("Top Flag", style="yellow")

    for a in sorted(alerts, key=lambda x: x.score, reverse=True):
        verdict_style = "bold red" if a.verdict == "malicious" else "yellow"
        t.add_row(
            str(a.pid),
            a.process_name,
            f"[{verdict_style}]{a.verdict.upper()}[/{verdict_style}]",
            str(a.score),
            a.flags[0] if a.flags else "",
        )
    console.print(t)
    sys.exit(1)



# quarantine


@main.group()
def quarantine() -> None:
    """Manage quarantined files."""


@quarantine.command("list")
@click.option("--config", default=None)
def quarantine_list(config) -> None:
    """List quarantined files."""
    cfg = _load_config(config)
    vault = QuarantineVault(Path(cfg.quarantine_dir))
    entries = vault.list_entries()
    if not entries:
        console.print("[yellow]Quarantine vault is empty.[/yellow]")
        return
    t = Table(title=f"Quarantine Vault ({len(entries)} file(s))", show_lines=True)
    t.add_column("Short ID", style="dim")
    t.add_column("Original Path", style="cyan", max_width=55)
    t.add_column("Threat", style="red")
    t.add_column("Quarantined At")
    for e in entries:
        t.add_row(e.id[:8], e.original_path, e.threat_name or "Unknown", _fmt_time(e.quarantined_at))
    console.print(t)


@quarantine.command("restore")
@click.argument("entry_id")
@click.option("--config", default=None)
def quarantine_restore(entry_id, config) -> None:
    """Restore a quarantined file."""
    cfg = _load_config(config)
    try:
        restored = QuarantineVault(Path(cfg.quarantine_dir)).restore(entry_id)
        console.print(f"[green]Restored:[/green] {restored}")
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


@quarantine.command("delete")
@click.argument("entry_id")
@click.option("--config", default=None)
@click.confirmation_option(prompt="Permanently delete this file?")
def quarantine_delete(entry_id, config) -> None:
    """Permanently delete a quarantined file."""
    cfg = _load_config(config)
    try:
        QuarantineVault(Path(cfg.quarantine_dir)).delete(entry_id)
        console.print("[green]Deleted.[/green]")
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)



# report


@main.command()
@click.option("--config", default=None)
@click.option("--limit", default=50, show_default=True)
def report(config, limit) -> None:
    """Show recent threat detections."""
    cfg = _load_config(config)
    threats = ScanLogger(Path(cfg.log_dir)).get_threats(limit)
    if not threats:
        console.print("[green]No threats recorded in recent scan logs.[/green]")
        return
    t = Table(title=f"Recent Threats ({len(threats)})", show_lines=True)
    t.add_column("File", style="cyan", max_width=50)
    t.add_column("Level")
    t.add_column("Threat", style="red")
    t.add_column("Scanned At")
    for rec in threats:
        level = rec.get("threat_level", "")
        s = "bold red" if level == "malicious" else "yellow"
        t.add_row(
            Path(rec["path"]).name,
            f"[{s}]{level.upper()}[/{s}]",
            rec.get("threat_name") or "",
            _fmt_time(rec["scanned_at"]),
        )
    console.print(t)



# config

@main.group()
def config() -> None:
    """Manage Exploidus EDR configuration."""


@config.command("init")
@click.option("--path", default=None)
def config_init(path) -> None:
    """Create a default config file."""
    cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if cfg_path.exists():
        console.print(f"[yellow]Config already exists:[/yellow] {cfg_path}")
        return
    Config().save(cfg_path)
    console.print(f"[green]Config created:[/green] {cfg_path}")


@config.command("show")
@click.option("--path", default=None)
def config_show(path) -> None:
    """Print the active configuration."""
    import json as _json
    from dataclasses import asdict
    console.print_json(_json.dumps(asdict(_load_config(path)), indent=2))


if __name__ == "__main__":
    main()