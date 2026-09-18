#!/usr/bin/env python3
"""
GuardScan CLI - Interactive & Non-Interactive Command Line Interface
Provides terminal scanning and DevSecOps CI/CD runner capabilities with build failure thresholds,
BOLA API testing, Fintech gateway probes, and PDF/HTML/JSON report exports.
"""

import sys
import os
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import Fore, Style, init
from rich import print as rich_print
from rich.panel import Panel
from rich.console import Console

# Import core modules
from core.scanner_engine import ScannerEngine
from core.payload_loader import PayloadLoader
from core.report_generator import ReportGenerator
from utils.platform_helper import clear_screen
from scanners import get_scanner, list_scanners

init(autoreset=True)
console = Console()

# Initialize core components
scanner = ScannerEngine()
payload_loader = PayloadLoader()
report_gen = ReportGenerator()


def display_menu():
    """Display the main scanner menu"""
    clear_screen()
    
    panel = Panel(r"""
   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║███████╗██║     ███████║██╔██╗ ██║
  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║╚════██║██║     ██╔══██║██║╚██╗██║
  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """,
    style="bold cyan",
    border_style="blue",
    expand=False
    )
    rich_print(panel, "\n")
    
    print(Fore.GREEN + "[ GuardScan ]\n")
    print(Fore.CYAN + "Available Scanners:")
    print(Fore.YELLOW + "  1. LFI Scanner" + Fore.RESET + "       - Local File Inclusion")
    print(Fore.YELLOW + "  2. Open Redirect" + Fore.RESET + "     - Unvalidated Redirects")
    print(Fore.YELLOW + "  3. SQL Injection" + Fore.RESET + "     - Database Injection")
    print(Fore.YELLOW + "  4. XSS Scanner" + Fore.RESET + "       - Cross-Site Scripting")
    print(Fore.YELLOW + "  5. CRLF Injection" + Fore.RESET + "    - HTTP Response Splitting")
    print(Fore.YELLOW + "  6. BOLA / IDOR" + Fore.RESET + "       - Broken Object Level Auth API Scanner")
    print(Fore.YELLOW + "  7. Gateway Probe" + Fore.RESET + "     - Nigerian Fintech / Webhook Security")
    print(Fore.RED + "  8. Exit\n")


def get_urls():
    """Get target URLs from user"""
    print(Fore.CYAN + "\n[?] Enter target URL(s):")
    print(Fore.YELLOW + "    (Enter one URL per line, press Enter twice when done)")
    
    urls = []
    while True:
        url = input(Fore.WHITE + "URL: ").strip()
        if not url:
            break
        urls.append(url)
    
    return urls


def get_threads():
    """Get thread count from user"""
    while True:
        try:
            threads = input(Fore.CYAN + "\n[?] Number of threads (1-10, default 5): ").strip()
            if not threads:
                return 5
            threads = int(threads)
            if 1 <= threads <= 10:
                return threads
            print(Fore.RED + "[!] Please enter a number between 1 and 10")
        except ValueError:
            print(Fore.RED + "[!] Please enter a valid number")


def display_results(results):
    """Display scan results"""
    print(Fore.GREEN + f"\n{'='*70}")
    print(Fore.GREEN + "SCAN RESULTS")
    print(Fore.GREEN + f"{'='*70}\n")
    
    print(Fore.CYAN + f"Scan Type: {results.get('scan_type', 'Scan')}")
    print(Fore.CYAN + f"Duration: {results.get('duration', 0)} seconds")
    print(Fore.CYAN + f"Total Scanned: {results.get('total_scanned', 0)}")
    print(Fore.YELLOW + f"Vulnerabilities Found: {results.get('total_found', 0)}\n")
    
    if results.get('total_found', 0) > 0:
        print(Fore.RED + "VULNERABLE TARGETS:")
        for url in results.get('vulnerable_urls', []):
            print(Fore.RED + f"  ✗ {url}")
    else:
        print(Fore.GREEN + "✓ No vulnerabilities found")
    
    print(Fore.GREEN + f"\n{'='*70}\n")


def save_report_prompt(scan_type, results):
    """Prompt user to save report in multiple formats"""
    save = input(Fore.CYAN + "\n[?] Save report? (y/n): ").strip().lower()
    if save == 'y':
        fmt = input(Fore.CYAN + "[?] Format (pdf/html/json/all, default pdf): ").strip().lower() or 'pdf'
        formats = ['pdf', 'html', 'json'] if fmt == 'all' else [fmt]
        for f in formats:
            try:
                report_path = report_gen.generate_and_save(scan_type, results, format=f)
                print(Fore.GREEN + f"[✓] {f.upper()} report saved: {report_path}")
            except Exception as e:
                print(Fore.RED + f"[✗] Error saving {f.upper()} report: {e}")


def create_realtime_callback():
    """Create a callback function for real-time payload testing display"""
    def progress_callback(data):
        if 'results' in data and data['results']:
            for result in data['results']:
                url = result.get('url', 'N/A')
                payload = str(result.get('payload', 'N/A'))
                vulnerable = result.get('vulnerable', False)
                status_code = result.get('status_code', 'N/A')
                response_time = result.get('response_time', 'N/A')
                
                display_url = url[:90] + '...' if len(url) > 90 else url
                
                if vulnerable:
                    print(Fore.RED + Style.BRIGHT + f"[VULN] " + Style.RESET_ALL + 
                          Fore.WHITE + f"Status: {status_code} | " + 
                          Fore.YELLOW + f"Time: {response_time}s | {result.get('title', 'Vulnerability')}")
                    print(Fore.RED + f"       Target: {display_url}")
                else:
                    if 'error' in result:
                        print(Fore.MAGENTA + f"[ERROR] " + 
                              Fore.WHITE + f"{str(result['error'])[:40]}...")
                        print(Fore.CYAN + f"        Target: {display_url}")
                    else:
                        print(Fore.GREEN + f"[SAFE]  " + 
                              Fore.WHITE + f"Status: {status_code} | " + 
                              Fore.YELLOW + f"Time: {response_time}s")
                        print(Fore.CYAN + f"        Target: {display_url}")
    return progress_callback


def run_lfi_scanner():
    clear_screen()
    print(Fore.GREEN + Style.BRIGHT + "LFI Scanner\n" + Style.RESET_ALL)
    urls = get_urls()
    if not urls:
        return
    threads = get_threads()
    try:
        payloads = payload_loader.load_lfi_payloads()
        scanner.add_progress_callback(create_realtime_callback())
        results = scanner.scan_lfi(urls, payloads, threads=threads)
        display_results(results)
        save_report_prompt('LFI', results)
    except Exception as e:
        print(Fore.RED + f"[✗] Error: {e}")
    input(Fore.YELLOW + "\nPress Enter to continue...")


def run_or_scanner():
    clear_screen()
    print(Fore.GREEN + Style.BRIGHT + "Open Redirect Scanner\n" + Style.RESET_ALL)
    urls = get_urls()
    if not urls:
        return
    threads = get_threads()
    try:
        payloads = payload_loader.load_or_payloads()
        scanner.add_progress_callback(create_realtime_callback())
        results = scanner.scan_or(urls, payloads, threads=threads)
        display_results(results)
        save_report_prompt('Open Redirect', results)
    except Exception as e:
        print(Fore.RED + f"[✗] Error: {e}")
    input(Fore.YELLOW + "\nPress Enter to continue...")


def run_sql_scanner():
    clear_screen()
    print(Fore.GREEN + Style.BRIGHT + "SQL Injection Scanner\n" + Style.RESET_ALL)
    urls = get_urls()
    if not urls:
        return
    threads = get_threads()
    try:
        payloads = payload_loader.load_sqli_payloads()
        scanner.add_progress_callback(create_realtime_callback())
        results = scanner.scan_sqli(urls, payloads, threads=threads)
        display_results(results)
        save_report_prompt('SQLi', results)
    except Exception as e:
        print(Fore.RED + f"[✗] Error: {e}")
    input(Fore.YELLOW + "\nPress Enter to continue...")


def run_xss_scanner():
    clear_screen()
    print(Fore.GREEN + Style.BRIGHT + "XSS Scanner\n" + Style.RESET_ALL)
    urls = get_urls()
    if not urls:
        return
    threads = min(get_threads(), 3)
    try:
        payloads = payload_loader.load_xss_payloads()
        scanner.add_progress_callback(create_realtime_callback())
        results = scanner.scan_xss(urls, payloads, threads=threads)
        display_results(results)
        save_report_prompt('XSS', results)
    except Exception as e:
        print(Fore.RED + f"[✗] Error: {e}")
    input(Fore.YELLOW + "\nPress Enter to continue...")


def run_crlf_scanner():
    clear_screen()
    print(Fore.GREEN + Style.BRIGHT + "CRLF Injection Scanner\n" + Style.RESET_ALL)
    urls = get_urls()
    if not urls:
        return
    threads = get_threads()
    try:
        scanner.add_progress_callback(create_realtime_callback())
        results = scanner.scan_crlf(urls, threads=threads)
        display_results(results)
        save_report_prompt('CRLF', results)
    except Exception as e:
        print(Fore.RED + f"[✗] Error: {e}")
    input(Fore.YELLOW + "\nPress Enter to continue...")


def run_bola_scanner():
    clear_screen()
    print(Fore.GREEN + Style.BRIGHT + "BOLA / IDOR API Scanner\n" + Style.RESET_ALL)
    urls = get_urls()
    if not urls:
        return
    token_a = input(Fore.CYAN + "[?] User A Auth Token (Resource Owner): ").strip()
    token_b = input(Fore.CYAN + "[?] User B Auth Token (Attacker / Unauthorized): ").strip()
    threads = get_threads()
    try:
        scanner.add_progress_callback(create_realtime_callback())
        results = scanner.scan_bola(urls, token_a=token_a, token_b=token_b, threads=threads)
        display_results(results)
        save_report_prompt('BOLA', results)
    except Exception as e:
        print(Fore.RED + f"[✗] Error: {e}")
    input(Fore.YELLOW + "\nPress Enter to continue...")


def run_gateway_scanner():
    clear_screen()
    print(Fore.GREEN + Style.BRIGHT + "Fintech Gateway & Payment Webhook Scanner\n" + Style.RESET_ALL)
    urls = get_urls()
    if not urls:
        return
    threads = get_threads()
    try:
        scanner.add_progress_callback(create_realtime_callback())
        results = scanner.scan_gateway(urls, threads=threads)
        display_results(results)
        save_report_prompt('Gateway', results)
    except Exception as e:
        print(Fore.RED + f"[✗] Error: {e}")
    input(Fore.YELLOW + "\nPress Enter to continue...")


def display_exit_screen():
    clear_screen()
    exit_art = r"""
    ███████╗██╗  ██╗██╗████████╗
    ██╔════╝╚██╗██╔╝██║╚══██╔══╝
    █████╗   ╚███╔╝ ██║   ██║   
    ██╔══╝   ██╔██╗ ██║   ██║   
    ███████╗██╔╝ ██╗██║   ██║   
    ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   

    [cyan]"Ethical Hacking for a valuable future"[/cyan]
    """
    panel = Panel(exit_art, style="bold red", border_style="red", expand=False)
    rich_print(panel)
    sys.exit(0)


def run_scanner():
    """Main interactive scanner menu loop"""
    while True:
        try:
            display_menu()
            choice = input(f"\n{Fore.CYAN}[?] Select an option (1-8): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                run_lfi_scanner()
            elif choice == '2':
                run_or_scanner()
            elif choice == '3':
                run_sql_scanner()
            elif choice == '4':
                run_xss_scanner()
            elif choice == '5':
                run_crlf_scanner()
            elif choice == '6':
                run_bola_scanner()
            elif choice == '7':
                run_gateway_scanner()
            elif choice == '8':
                display_exit_screen()
            else:
                print(Fore.RED + "\n[!] Invalid option. Please choose 1-8.")
                input(Fore.YELLOW + "\nPress Enter to continue...")
        except KeyboardInterrupt:
            display_exit_screen()
        except Exception as e:
            print(Fore.RED + f"\n[!] Error: {e}")
            input(Fore.YELLOW + "\nPress Enter to continue...")


# ============================================================================
# DevSecOps Non-Interactive CI/CD Entrypoint
# ============================================================================

def run_ci_cd(args):
    """Execute scan in automated CI/CD pipeline mode with exit code enforcement"""
    targets = [args.target] if args.target else []
    if args.target_file and os.path.exists(args.target_file):
        with open(args.target_file, 'r', encoding='utf-8') as f:
            targets.extend([line.strip() for line in f if line.strip()])

    if not targets:
        console.print("[bold red][!] Error: No target URL or target file specified for CI/CD scan.[/bold red]")
        sys.exit(2)

    scan_type = args.scan_type.lower()
    threads = args.threads
    console.print(f"[bold cyan]=== GuardScan DevSecOps Automated Security Runner ===[/bold cyan]")
    console.print(f"[cyan]Target(s): {len(targets)} endpoint(s) | Type: {scan_type.upper()} | Threads: {threads}[/cyan]")

    scanner.add_progress_callback(create_realtime_callback())

    results = {
        'scan_type': scan_type.upper(),
        'results': [],
        'total_found': 0,
        'total_scanned': 0,
        'vulnerable_urls': []
    }

    if scan_type == 'lfi':
        payloads = payload_loader.load_lfi_payloads()
        results = scanner.scan_lfi(targets, payloads, threads=threads)
    elif scan_type == 'sqli':
        payloads = payload_loader.load_sqli_payloads()
        results = scanner.scan_sqli(targets, payloads, threads=threads)
    elif scan_type == 'xss':
        payloads = payload_loader.load_xss_payloads()
        results = scanner.scan_xss(targets, payloads, threads=threads)
    elif scan_type == 'or':
        payloads = payload_loader.load_or_payloads()
        results = scanner.scan_or(targets, payloads, threads=threads)
    elif scan_type == 'crlf':
        results = scanner.scan_crlf(targets, threads=threads)
    elif scan_type == 'bola':
        results = scanner.scan_bola(targets, token_a=args.token_a or '', token_b=args.token_b or '', threads=threads)
    elif scan_type == 'gateway':
        results = scanner.scan_gateway(targets, threads=threads)
    elif scan_type == 'all':
        for st in ['lfi', 'or', 'crlf', 'gateway']:
            p = get_scanner(st)
            if p:
                res = p.scan(targets, threads=threads)
                results['results'].extend(res.get('results', []))
                results['total_found'] += res.get('total_found', 0)
                results['total_scanned'] += res.get('total_scanned', 0)
                results['vulnerable_urls'].extend(res.get('vulnerable_urls', []))
    else:
        console.print(f"[bold red][!] Unknown scan type: {scan_type}[/bold red]")
        sys.exit(2)

    # Save outputs if requested
    if args.output_pdf:
        report_gen.pdf_generator.generate(scan_type, results, Path(args.output_pdf))
        console.print(f"[green][✓] PDF Report exported: {args.output_pdf}[/green]")
    if args.output_json:
        report_gen.save_report(report_gen.generate_json_report(scan_type, results), args.output_json, 'json')
        console.print(f"[green][✓] JSON Report exported: {args.output_json}[/green]")
    if args.output_html:
        report_gen.save_report(report_gen.generate_html_report(scan_type, results), args.output_html, 'html')
        console.print(f"[green][✓] HTML Report exported: {args.output_html}[/green]")

    # Check failure threshold
    fail_threshold = args.fail_on.lower() if args.fail_on else None
    severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

    highest_found_sev = 0
    for finding in results.get('results', []):
        if finding.get('vulnerable'):
            sev_str = finding.get('severity', 'Low').lower()
            val = severity_order.get(sev_str, 1)
            if val > highest_found_sev:
                highest_found_sev = val

    console.print(f"\n[bold]Scan completed: {results.get('total_found', 0)} vulnerabilities discovered.[/bold]")

    if fail_threshold and fail_threshold in severity_order:
        threshold_val = severity_order[fail_threshold]
        if highest_found_sev >= threshold_val:
            console.print(f"[bold red]❌ CI/CD BUILD FAILED: Vulnerabilities found exceeding threshold '{fail_threshold.upper()}'.[/bold red]")
            sys.exit(1)
        else:
            console.print(f"[bold green]✔ CI/CD BUILD PASSED: Findings below threshold '{fail_threshold.upper()}'.[/bold green]")
            sys.exit(0)

    sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GuardScan - Interactive & CI/CD Security Scanner")
    parser.add_argument("--ci", action="store_true", help="Run in non-interactive CI/CD mode")
    parser.add_argument("--target", type=str, help="Target URL to scan")
    parser.add_argument("--target-file", type=str, help="File containing list of URLs to scan")
    parser.add_argument("--scan-type", type=str, default="lfi", choices=['lfi', 'sqli', 'xss', 'or', 'crlf', 'bola', 'gateway', 'all'], help="Vulnerability scan type")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads")
    parser.add_argument("--token-a", type=str, help="User A Auth Token (for BOLA scan)")
    parser.add_argument("--token-b", type=str, help="User B Auth Token (for BOLA scan)")
    parser.add_argument("--fail-on", type=str, choices=['critical', 'high', 'medium', 'low'], default="high", help="Fail pipeline exit code if vulnerabilities of this severity or higher are found")
    parser.add_argument("--output-pdf", type=str, help="Path to write PDF remediation report")
    parser.add_argument("--output-json", type=str, help="Path to write JSON findings report")
    parser.add_argument("--output-html", type=str, help="Path to write HTML report")

    # If args passed, run CI/CD runner; else run interactive menu
    if len(sys.argv) > 1:
        cli_args = parser.parse_args()
        run_ci_cd(cli_args)
    else:
        run_scanner()
