#!/bin/bash
# Ares Tool Security — Full Testing & Security Testing Suite
# Entry point interactivo

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/colors.sh"

# Ensure reports dir
mkdir -p "$SCRIPT_DIR/reports"

main_menu() {
    while true; do
        clear
        print_banner
        echo -e "${cyan}Target:${reset} ${bold}$TARGET${reset}${dimtext} (use 'set' to change)${reset}"
        echo ""
        echo -e "  ${bold}[1]${reset}  🌐  ${label}Web Audit${reset}        — SSL, headers, stack, ports"
        echo -e "  ${bold}[2]${reset}  🔨  ${label}Brute Force Test${reset} — Rate limiting, lockout, 2FA"
        echo -e "  ${bold}[3]${reset}  🖥️   ${label}System Audit${reset}    — SSH, users, files, secrets"
        echo -e "  ${bold}[4]${reset}  🐳  ${label}Docker Audit${reset}     — Containers, images, mounts"
        echo -e "  ${bold}[5]${reset}  📋  ${label}Full Scan${reset}        — Todo en un solo comando"
        echo ""
        echo -e "  ${bold}[s]${reset}  ⚙️   ${label}Set Target${reset}      — Cambiar URL/IP objetivo"
        echo -e "  ${bold}[v]${reset}  📈  ${label}View Reports${reset}     — Ver reportes generados"
        echo -e "  ${bold}[q]${reset}  🚪  ${label}Quit${reset}"
        echo ""
        read -p "  $(echo -e ${cyan})❯${reset} " choice

        case $choice in
            1) run_module "web-audit" "🌐 Web Audit" ;;
            2) run_module "brute-force" "🔨 Brute Force Test" ;;
            3) run_module "system" "🖥️  System Audit" ;;
            4) run_module "docker" "🐳 Docker Audit" ;;
            5) run_full_scan ;;
            s|S) set_target ;;
            v|V) view_reports ;;
            q|Q) echo -e "\n${ok}Bye! 🔐${reset}" ; exit 0 ;;
            *) echo -e "${warn}Invalid option${reset}" ; sleep 1 ;;
        esac
    done
}

set_target() {
    read -p "  $(echo -e ${cyan})Target URL/IP: ${reset}" new_target
    if [ -n "$new_target" ]; then
        TARGET="$new_target"
        echo -e "${ok}Target set to: $TARGET${reset}"
    fi
    sleep 1
}

run_module() {
    local module=$1
    local label=$2
    clear
    print_banner
    echo -e "  ${label}\n"
    
    if [ -z "$TARGET" ]; then
        set_target
    fi
    
    if [ -f "$SCRIPT_DIR/modules/$module.py" ]; then
        python3 "$SCRIPT_DIR/modules/$module.py" "$TARGET"
    else
        echo -e "${warn}Module not yet implemented${reset}"
    fi
    
    echo ""
    read -p "  $(echo -e ${dim})Press enter to continue...${reset}"
}

run_full_scan() {
    clear
    print_banner
    echo -e "  ${bold}🔍 Full Scan — All modules${reset}\n"
    
    if [ -z "$TARGET" ]; then
        set_target
    fi
    
    for module in web-audit brute-force; do
        if [ -f "$SCRIPT_DIR/modules/$module.py" ]; then
            echo -e "\n${title}━━━ Running: $module ━━━${reset}"
            python3 "$SCRIPT_DIR/modules/$module.py" "$TARGET"
        fi
    done
    
    echo ""
    read -p "  $(echo -e ${dim})Press enter to continue...${reset}"
}

view_reports() {
    clear
    print_banner
    echo -e "  📈 Reports\n"
    
    reports=( "$SCRIPT_DIR"/reports/*.md )
    if [ ${#reports[@]} -eq 0 ] || [ ! -f "${reports[0]}" ]; then
        echo -e "  ${warn}No reports yet${reset}"
    else
        echo "  Select report to view:"
        local i=1
        for report in "${reports[@]}"; do
            echo -e "  ${bold}[$i]${reset} $(basename "$report")"
            ((i++))
        done
        echo ""
        read -p "  ❯ " r_choice
        if [[ "$r_choice" =~ ^[0-9]+$ ]] && [ "$r_choice" -ge 1 ] && [ "$r_choice" -le "${#reports[@]}" ]; then
            clear
            cat "${reports[$((r_choice-1))]}"
            echo ""
            read -p "  $(echo -e ${dim})Press enter to continue...${reset}"
        fi
    fi
    
    if [ ${#reports[@]} -eq 0 ]; then
        read -p "  $(echo -e ${dim})Press enter to continue...${reset}"
    fi
}

# Show banner on start
TARGET=""
clear
print_banner
echo ""
echo -e "  ${dim}Interactive security testing suite for systems and web apps.${reset}"
echo -e "  ${dim}Full Testing & Security Testing Suite v2.0${reset}"
echo ""
sleep 1
main_menu
