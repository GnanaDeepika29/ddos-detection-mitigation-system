#!/bin/bash
# ============================================
# Traffic Collector Startup Script
# ============================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

COLLECTOR_MODE="packet"
INTERFACE="eth0"
BPF_FILTER=""
CONFIG_FILE="config/dev.yaml"
LOG_LEVEL="INFO"
DAEMONIZE=false
PID_FILE="/tmp/ddos_collector.pid"
FLOW_BUILDER_ENABLED=true
KAFKA_ENABLED=true
VERBOSE=false

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Start Traffic Collector for DDoS Detection System

Options:
    -m, --mode MODE      Collector mode (packet, cloud, flowlog) [default: packet]
    -i, --interface IFACE Network interface [default: eth0]
    -f, --filter FILTER  BPF filter for packet capture
    -c, --config FILE    Configuration file [default: config/dev.yaml]
    -l, --log-level LVL  Log level [default: INFO]
    -d, --daemonize      Run as daemon
    --no-flow-builder    Disable flow builder
    --no-kafka           Disable Kafka producer
    -v, --verbose        Verbose output
    --help               Show this help message
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -m|--mode)          COLLECTOR_MODE="$2"; shift 2 ;;
            -i|--interface)     INTERFACE="$2";       shift 2 ;;
            -f|--filter)        BPF_FILTER="$2";      shift 2 ;;
            -c|--config)        CONFIG_FILE="$2";     shift 2 ;;
            -l|--log-level)     LOG_LEVEL="$2";       shift 2 ;;
            -d|--daemonize)     DAEMONIZE=true;       shift ;;
            --no-flow-builder)  FLOW_BUILDER_ENABLED=false; shift ;;
            --no-kafka)         KAFKA_ENABLED=false;  shift ;;
            -v|--verbose)       VERBOSE=true; LOG_LEVEL="DEBUG"; shift ;;
            --help)             show_help; exit 0 ;;
            *) echo "Unknown option: $1"; show_help; exit 1 ;;
        esac
    done
}

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

check_prerequisites() {
    if ! command -v python3 &>/dev/null; then
        log_error "Python 3 is required"
        exit 1
    fi
    
    if [ ! -f "$PROJECT_ROOT/scripts/run_collector.py" ]; then
        log_error "run_collector.py not found"
        exit 1
    fi
}

main() {
    log_info "Starting DDoS Detection System Collector"

    parse_args "$@"
    check_prerequisites

    cd "$PROJECT_ROOT"

    # Run the collector using the Python script
    export COLLECTOR_MODE="${COLLECTOR_MODE}"
    export COLLECTOR_INTERFACE="${INTERFACE}"
    export LOG_LEVEL="${LOG_LEVEL}"
    export CAPTURE_FILTER="${BPF_FILTER}"
    
    if [[ "$DAEMONIZE" == "true" ]]; then
        log_info "Starting collector as daemon..."
        nohup python3 scripts/run_collector.py --interface "$INTERFACE" >> /var/log/ddos_collector.log 2>&1 &
        echo $! > "$PID_FILE"
        log_success "Collector started as daemon with PID $(cat $PID_FILE)"
    else
        log_info "Starting collector in foreground..."
        python3 scripts/run_collector.py --interface "$INTERFACE"
    fi
}

main "$@"