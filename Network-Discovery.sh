#!/usr/bin/env bash
#==============================================================================
# Network Discovery Automation Suite
# Author: vetementsvmnts { Kitsana Thuekoh }
# Description: Comprehensive network discovery, enumeration, and reporting
#              for penetration testing engagements.
#==============================================================================

set -euo pipefail

# --- Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${SCRIPT_DIR}/config"
MODULES_DIR="${SCRIPT_DIR}/modules"
OUTPUT_BASE="${SCRIPT_DIR}/output"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ENGAGEMENT_ID=""
TARGETS=""
TARGET_FILE=""
RATE_LIMIT="1000"
TIMING="T4"
OUTPUT_FORMAT="all"
VERBOSE=0
QUIET=0

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Logging ---
LOG_FILE=""

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local color="$NC"
    
    case "$level" in
        INFO)  color="$GREEN" ;;
        WARN)  color="$YELLOW" ;;
        ERROR) color="$RED" ;;
        DEBUG) color="$CYAN" ;;
    esac
    
    [[ "$QUIET" -eq 0 ]] && echo -e "${color}[${timestamp}] [${level}]${NC} ${msg}"
    [[ -n "$LOG_FILE" ]] && echo "[${timestamp}] [${level}] ${msg}" >> "$LOG_FILE"
}

# --- Usage ---
usage() {
    cat << EOF
Network Discovery Automation Suite

USAGE:
    $0 -t <target> [OPTIONS]
    $0 -f <target_file> [OPTIONS]

REQUIRED:
    -t, --target <target>       Single target (IP, CIDR, range, or hostname)
    -f, --file <file>           File containing targets (one per line)

OPTIONS:
    -e, --engagement <id>       Engagement identifier (default: auto-generated)
    -r, --rate <limit>          Rate limit in packets/sec (default: 1000)
    -T, --timing <template>     Nmap timing template T1-T5 (default: T4)
    -o, --output <format>       Output format: json, md, html, all (default: all)
    -q, --quiet                 Suppress console output
    -v, --verbose               Enable verbose/debug output
    -h, --help                  Show this help message

EXAMPLES:
    # Single target
    $0 -t 192.168.1.0/24 -e "client-alpha"

    # Multiple targets from file
    $0 -f targets.txt -T5 -r 5000

    # Stealth scan with HTML report
    $0 -t 10.0.0.1/24 -T2 -o html

OUTPUT:
    Results are saved to: ./output/<engagement_id>/<timestamp>/
EOF
    exit 0
}

# --- Argument Parsing ---
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)    TARGETS="$2"; shift 2 ;;
            -f|--file)      TARGET_FILE="$2"; shift 2 ;;
            -e|--engagement) ENGAGEMENT_ID="$2"; shift 2 ;;
            -r|--rate)      RATE_LIMIT="$2"; shift 2 ;;
            -T|--timing)    TIMING="$2"; shift 2 ;;
            -o|--output)    OUTPUT_FORMAT="$2"; shift 2 ;;
            -q|--quiet)     QUIET=1; shift ;;
            -v|--verbose)   VERBOSE=1; shift ;;
            -h|--help)      usage ;;
            *) log ERROR "Unknown option: $1"; usage ;;
        esac
    done
    
    # Validate inputs
    if [[ -z "$TARGETS" && -z "$TARGET_FILE" ]]; then
        log ERROR "No target specified. Use -t or -f."
        usage
    fi
    
    if [[ -n "$TARGET_FILE" && ! -f "$TARGET_FILE" ]]; then
        log ERROR "Target file not found: $TARGET_FILE"
        exit 1
    fi
    
    # Auto-generate engagement ID if not provided
    if [[ -z "$ENGAGEMENT_ID" ]]; then
        ENGAGEMENT_ID="eng_${TIMESTAMP}"
    fi
    
    # Setup output directory
    OUTPUT_DIR="${OUTPUT_BASE}/${ENGAGEMENT_ID}/${TIMESTAMP}"
    mkdir -p "$OUTPUT_DIR"
    LOG_FILE="${OUTPUT_DIR}/discovery.log"
    
    log INFO "Engagement ID: $ENGAGEMENT_ID"
    log INFO "Output directory: $OUTPUT_DIR"
}

# --- Dependency Check ---
check_dependencies() {
    log INFO "Checking dependencies..."
    
    local deps=("nmap" "masscan" "fping" "jq")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log ERROR "Missing dependencies: ${missing[*]}"
        log INFO "Install with: sudo apt-get install nmap masscan fping jq"
        exit 1
    fi
    
    log INFO "All dependencies satisfied"
}

# --- Phase 1: Host Discovery ---
phase1_host_discovery() {
    log INFO "=== PHASE 1: Host Discovery ==="
    local output_file="${OUTPUT_DIR}/01_alive_hosts.txt"
    local target_input="${OUTPUT_DIR}/.targets.txt"
    
    # Prepare target list
    if [[ -n "$TARGET_FILE" ]]; then
        cp "$TARGET_FILE" "$target_input"
    else
        echo "$TARGETS" > "$target_input"
    fi
    
    log INFO "Running fping for ICMP host discovery..."
    fping -a -f "$target_input" 2>/dev/null | sort -u > "$output_file" || true
    
    local alive_count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    log INFO "Found $alive_count alive hosts"
    
    # If fping finds nothing, fall back to nmap ping sweep
    if [[ "$alive_count" -eq 0 ]]; then
        log WARN "No hosts found via ICMP. Trying ARP and TCP ping sweep..."
        nmap -sn -PE -PP -PM -PS22,80,443 -PA80,443 -PU53,161 \
             -iL "$target_input" -oG - 2>/dev/null | \
             grep "Host:" | awk '{print $2}' | sort -u > "$output_file"
        alive_count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
        log INFO "Nmap ping sweep found $alive_count hosts"
    fi
    
    echo "$output_file"
}

# --- Phase 2: Port Scanning ---
phase2_port_scan() {
    local alive_hosts="$1"
    log INFO "=== PHASE 2: Port Scanning ==="
    
    local masscan_out="${OUTPUT_DIR}/02_masscan_ports.json"
    local nmap_out="${OUTPUT_DIR}/02_nmap_scan.xml"
    local combined_out="${OUTPUT_DIR}/02_open_ports.txt"
    
    # Fast masscan for top ports
    log INFO "Running masscan (top 1000 ports)..."
    masscan -iL "$alive_hosts" --top-ports 1000 \
            --rate "$RATE_LIMIT" -oJ "$masscan_out" 2>/dev/null || {
        log WARN "Masscan failed or requires root. Skipping..."
        touch "$masscan_out"
    }
    
    # Detailed nmap scan
    log INFO "Running nmap detailed scan ($TIMING)..."
    nmap -sS -sV -sC -O --version-intensity 5 \
         -iL "$alive_hosts" \
         -"$TIMING" \
         --max-retries 2 \
         --max-rtt-timeout 300ms \
         --open \
         -oX "$nmap_out" \
         -oN "${OUTPUT_DIR}/02_nmap_human.txt" \
         2>/dev/null || log WARN "Nmap scan encountered issues"
    
    # Extract open ports for next phases
    if [[ -f "$nmap_out" ]]; then
        xq -r '.nmaprun.host[]? | 
               select(.ports.port) | 
               .address[]?.@addr + ":" + .ports.port[]?.@portid' \
               "$nmap_out" 2>/dev/null | sort -u > "$combined_out" || {
            # Fallback parsing
            grep -E "^[0-9]+/(tcp|udp)\s+open" "${OUTPUT_DIR}/02_nmap_human.txt" | \
            awk '{print $1}' > "$combined_out" 2>/dev/null || true
        }
    fi
    
    local port_count=$(wc -l < "$combined_out" 2>/dev/null || echo "0")
    log INFO "Discovered $port_count open ports"
    
    echo "$combined_out"
}

# --- Phase 3: Service Enumeration ---
phase3_service_enum() {
    local open_ports="$1"
    log INFO "=== PHASE 3: Service Enumeration ==="
    
    local enum_dir="${OUTPUT_DIR}/03_service_enum"
    mkdir -p "$enum_dir"
    
    # Parse nmap XML for service details
    local nmap_xml="${OUTPUT_DIR}/02_nmap_scan.xml"
    
    if [[ -f "$nmap_xml" ]]; then
        # Extract HTTP services for further enumeration
        log INFO "Identifying web services..."
        xq -r '.nmaprun.host[]? | 
               select(.ports.port[]?.service[]?.@name | contains("http")) |
               .address[]?.@addr + ":" + .ports.port[]?.@portid' \
               "$nmap_xml" 2>/dev/null | sort -u > "${enum_dir}/web_services.txt" || true
        
        # Extract SMB services
        log INFO "Identifying SMB services..."
        xq -r '.nmaprun.host[]? | 
               select(.ports.port[]?.service[]?.@name | contains("smb") or contains("microsoft-ds")) |
               .address[]?.@addr + ":" + .ports.port[]?.@portid' \
               "$nmap_xml" 2>/dev/null | sort -u > "${enum_dir}/smb_services.txt" || true
        
        # Extract SSH services
        xq -r '.nmaprun.host[]? | 
               select(.ports.port[]?.service[]?.@name | contains("ssh")) |
               .address[]?.@addr + ":" + .ports.port[]?.@portid' \
               "$nmap_xml" 2>/dev/null | sort -u > "${enum_dir}/ssh_services.txt" || true
        
        # Extract database services
        log INFO "Identifying database services..."
        xq -r '.nmaprun.host[]? | 
               select(.ports.port[]?.service[]?.@name | contains("mysql") or contains("postgresql") or contains("mssql") or contains("oracle")) |
               .address[]?.@addr + ":" + .ports.port[]?.@portid' \
               "$nmap_xml" 2>/dev/null | sort -u > "${enum_dir}/database_services.txt" || true
    fi
    
    log INFO "Service enumeration complete"
}

# --- Phase 4: Report Generation ---
phase4_generate_reports() {
    log INFO "=== PHASE 4: Report Generation ==="
    
    local nmap_xml="${OUTPUT_DIR}/02_nmap_scan.xml"
    local report_json="${OUTPUT_DIR}/report.json"
    local report_md="${OUTPUT_DIR}/report.md"
    local report_html="${OUTPUT_DIR}/report.html"
    
    # JSON Report
    if [[ -f "$nmap_xml" ]]; then
        log INFO "Generating JSON report..."
        xq '.' "$nmap_xml" > "$report_json" 2>/dev/null || {
            log WARN "xq not available for XML parsing, creating basic JSON"
            cat > "$report_json" << EOF
{
    "engagement_id": "$ENGAGEMENT_ID",
    "timestamp": "$TIMESTAMP",
    "targets": "$(cat ${OUTPUT_DIR}/.targets.txt | tr '\n' ', ')",
    "alive_hosts": $(wc -l < "${OUTPUT_DIR}/01_alive_hosts.txt" 2>/dev/null || echo 0),
    "output_directory": "$OUTPUT_DIR"
}
EOF
        }
    fi
    
    # Markdown Report
    if [[ "$OUTPUT_FORMAT" == "md" || "$OUTPUT_FORMAT" == "all" ]]; then
        log INFO "Generating Markdown report..."
        generate_markdown_report "$report_md"
    fi
    
    # HTML Report
    if [[ "$OUTPUT_FORMAT" == "html" || "$OUTPUT_FORMAT" == "all" ]]; then
        log INFO "Generating HTML report..."
        generate_html_report "$report_html"
    fi
    
    log INFO "Reports generated in: $OUTPUT_DIR"
}

# --- Markdown Report Generator ---
generate_markdown_report() {
    local output="$1"
    local alive_hosts="${OUTPUT_DIR}/01_alive_hosts.txt"
    local nmap_human="${OUTPUT_DIR}/02_nmap_human.txt"
    
    cat > "$output" << EOF
# Network Discovery Report

**Engagement ID:** $ENGAGEMENT_ID  
**Date:** $(date)  
**Command:** $0 $*

---

## Summary

| Metric | Value |
|--------|-------|
| Engagement ID | $ENGAGEMENT_ID |
| Timestamp | $TIMESTAMP |
| Alive Hosts | $(wc -l < "$alive_hosts" 2>/dev/null || echo "0") |
| Open Ports | $(wc -l < "${OUTPUT_DIR}/02_open_ports.txt" 2>/dev/null || echo "0") |

---

## Alive Hosts

$(cat "$alive_hosts" 2>/dev/null | sed 's/^/- /' || echo "No alive hosts found")

---

## Detailed Scan Results

$(cat "$nmap_human" 2>/dev/null || echo "No detailed scan results available")

---

## Service Breakdown

### Web Services (HTTP/HTTPS)
$(cat "${OUTPUT_DIR}/03_service_enum/web_services.txt" 2>/dev/null | sed 's/^/- /' || echo "None found")

### SMB Services
$(cat "${OUTPUT_DIR}/03_service_enum/smb_services.txt" 2>/dev/null | sed 's/^/- /' || echo "None found")

### SSH Services
$(cat "${OUTPUT_DIR}/03_service_enum/ssh_services.txt" 2>/dev/null | sed 's/^/- /' || echo "None found")

### Database Services
$(cat "${OUTPUT_DIR}/03_service_enum/database_services.txt" 2>/dev/null | sed 's/^/- /' || echo "None found")

---

*Generated by Network Discovery Automation Suite*
EOF
}

# --- HTML Report Generator ---
generate_html_report() {
    local output="$1"
    local alive_hosts="${OUTPUT_DIR}/01_alive_hosts.txt"
    
    cat > "$output" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Discovery Report - $ENGAGEMENT_ID</title>
    <style>
        :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --success: #3fb950; --warn: #d29922; --danger: #f85149; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: var(--accent); margin-bottom: 0.5rem; }
        .meta { color: #8b949e; margin-bottom: 2rem; font-size: 0.9rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; }
        .card h3 { font-size: 0.85rem; text-transform: uppercase; color: #8b949e; margin-bottom: 0.5rem; }
        .card .value { font-size: 2rem; font-weight: 700; color: var(--accent); }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
        th { background: var(--card); color: var(--accent); font-weight: 600; }
        tr:hover { background: rgba(88, 166, 255, 0.05); }
        .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
        .badge-http { background: rgba(63, 185, 80, 0.15); color: var(--success); }
        .badge-smb { background: rgba(210, 153, 34, 0.15); color: var(--warn); }
        .badge-ssh { background: rgba(88, 166, 255, 0.15); color: var(--accent); }
        .badge-db { background: rgba(248, 81, 73, 0.15); color: var(--danger); }
        pre { background: var(--card); padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; }
        .section { margin-bottom: 2rem; }
        .section h2 { color: var(--accent); margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Discovery Report</h1>
        <div class="meta">
            Engagement: <strong>$ENGAGEMENT_ID</strong> | 
            Generated: <strong>$(date)</strong>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>Alive Hosts</h3>
                <div class="value">$(wc -l < "$alive_hosts" 2>/dev/null || echo "0")</div>
            </div>
            <div class="card">
                <h3>Open Ports</h3>
                <div class="value">$(wc -l < "${OUTPUT_DIR}/02_open_ports.txt" 2>/dev/null || echo "0")</div>
            </div>
            <div class="card">
                <h3>Web Services</h3>
                <div class="value">$(wc -l < "${OUTPUT_DIR}/03_service_enum/web_services.txt" 2>/dev/null || echo "0")</div>
            </div>
            <div class="card">
                <h3>Duration</h3>
                <div class="value">~$(($(date +%s) - $(date -d "$(head -1 "$LOG_FILE" 2>/dev/null | grep -oP '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}')" +%s 2>/dev/null || echo $(date +%s))))s</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Alive Hosts</h2>
            <table>
                <tr><th>#</th><th>IP Address</th><th>Status</th></tr>
                $(cat "$alive_hosts" 2>/dev/null | nl -w2 -s'|' | sed 's/^/<tr><td>/; s/|/<\/td><td>/; s/$/<\/td><td><span class="badge badge-http">Alive<\/span><\/td><\/tr>/' || echo "<tr><td colspan=3>No hosts found</td></tr>")
            </table>
        </div>
        
        <div class="section">
            <h2>Web Services</h2>
            <table>
                <tr><th>Host:Port</th><th>Service</th></tr>
                $(cat "${OUTPUT_DIR}/03_service_enum/web_services.txt" 2>/dev/null | sed 's/^/<tr><td>/; s/$/<\/td><td><span class="badge badge-http">HTTP\/HTTPS<\/span><\/td><\/tr>/' || echo "<tr><td colspan=2>None found</td></tr>")
            </table>
        </div>
        
        <div class="section">
            <h2>SMB Services</h2>
            <table>
                <tr><th>Host:Port</th><th>Service</th></tr>
                $(cat "${OUTPUT_DIR}/03_service_enum/smb_services.txt" 2>/dev/null | sed 's/^/<tr><td>/; s/$/<\/td><td><span class="badge badge-smb">SMB<\/span><\/td><\/tr>/' || echo "<tr><td colspan=2>None found</td></tr>")
            </table>
        </div>
        
        <div class="section">
            <h2>SSH Services</h2>
            <table>
                <tr><th>Host:Port</th><th>Service</th></tr>
                $(cat "${OUTPUT_DIR}/03_service_enum/ssh_services.txt" 2>/dev/null | sed 's/^/<tr><td>/; s/$/<\/td><td><span class="badge badge-ssh">SSH<\/span><\/td><\/tr>/' || echo "<tr><td colspan=2>None found</td></tr>")
            </table>
        </div>
        
        <div class="section">
            <h2>Database Services</h2>
            <table>
                <tr><th>Host:Port</th><th>Service</th></tr>
                $(cat "${OUTPUT_DIR}/03_service_enum/database_services.txt" 2>/dev/null | sed 's/^/<tr><td>/; s/$/<\/td><td><span class="badge badge-db">Database<\/span><\/td><\/tr>/' || echo "<tr><td colspan=2>None found</td></tr>")
            </table>
        </div>
        
        <div class="section">
            <h2>Raw Nmap Output</h2>
            <pre>$(cat "${OUTPUT_DIR}/02_nmap_human.txt" 2>/dev/null | head -100 || echo "No scan data available")</pre>
        </div>
    </div>
</body>
</html>
EOF
}

# --- Main Execution ---
main() {
    parse_args "$@"
    check_dependencies
    
    log INFO "Starting Network Discovery Automation Suite"
    log INFO "Target: ${TARGETS:-$(cat $TARGET_FILE 2>/dev/null | head -5 | tr '\n' ', ')}"
    
    local alive_hosts
    alive_hosts=$(phase1_host_discovery)
    
    local open_ports
    open_ports=$(phase2_port_scan "$alive_hosts")
    
    phase3_service_enum "$open_ports"
    phase4_generate_reports
    
    log INFO "=== DISCOVERY COMPLETE ==="
    log INFO "Results: $OUTPUT_DIR"
    log INFO "  - Alive hosts: ${OUTPUT_DIR}/01_alive_hosts.txt"
    log INFO "  - Open ports: ${OUTPUT_DIR}/02_open_ports.txt"
    log INFO "  - Service enum: ${OUTPUT_DIR}/03_service_enum/"
    log INFO "  - Reports: ${OUTPUT_DIR}/report.*"
    
    # Print tree of output
    if command -v tree &> /dev/null; then
        tree "$OUTPUT_DIR" 2>/dev/null || ls -la "$OUTPUT_DIR"
    else
        find "$OUTPUT_DIR" -type f | sort
    fi
}

main "$@"
