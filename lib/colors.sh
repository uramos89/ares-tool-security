# FullTestSec CLI Colors
# Usage: source lib/colors.sh

# Reset
reset='\033[0m'

# Foreground
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
white='\033[0;37m'
bold='\033[1m'
dim='\033[2m'

# Aliases
info="${cyan}"
ok="${green}"
warn="${yellow}"
error="${red}"
title="${bold}${magenta}"
label="${bold}${white}"
dimtext="${dim}${white}"

# Icons
icon_ok="✅"
icon_warn="⚠️"
icon_error="❌"
icon_info="ℹ️"
icon_critical="🔴"
icon_high="🟠"
icon_medium="🟡"
icon_low="🔵"
icon_arrow="→"
icon_star="⭐"

# Functions
print_banner() {
    echo -e "${title}"
    echo '  ███████╗████████╗███████╗███████╗███████╗██╗  ██╗'
    echo '  ██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝██║  ██║'
    echo '  █████╗     ██║   ███████╗█████╗  ███████╗███████║'
    echo '  ██╔══╝     ██║   ╚════██║██╔══╝  ╚════██║██╔══██║'
    echo '  ██║        ██║   ███████║██║     ███████║██║  ██║'
    echo '  ╚═╝        ╚═╝   ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝'
    echo -e "${dim}  🔐 Full Testing & Security Testing Suite${reset}"
    echo ""
}

print_section() {
    echo -e "\n${title}━━━ $1 ━━━${reset}"
}

print_result() {
    local severity=$1
    local message=$2
    local detail=$3
    case $severity in
        "ok") echo -e "  ${icon_ok} ${green}${message}${reset}" ;;
        "warn") echo -e "  ${icon_warn} ${yellow}${message}${reset} ${detail:+${dim}${detail}${reset}}" ;;
        "error") echo -e "  ${icon_error} ${red}${message}${reset} ${detail:+${dim}${detail}${reset}}" ;;
        "critical") echo -e "  ${icon_critical} ${red}${bold}${message}${reset} ${detail:+${dim}${detail}${reset}}" ;;
        "info") echo -e "  ${icon_info} ${blue}${message}${reset}" ;;
    esac
}
