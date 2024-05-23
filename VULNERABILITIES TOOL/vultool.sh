#!/bin/bash

echo -e "\e[33m"
echo "╔══════════════════════════════╗"
echo "║         Welcome!!!           ║"
echo "╚══════════════════════════════╝"
echo -e "\e[0m"
sleep 1

#4.3 Allow the user to search inside the results.
function display_menu() {
    PS3='Please enter your choice: '
    options=("Looking at previous scans" "Conduct new scans" "Quit")
    while true; do
        echo "Are you interested in:"
        select opt in "${options[@]}"; do
            case $REPLY in
                1)
                    browse_previous_scans
                    break
                    ;;
                2)
                    setup_scan_environment
                    break
                    ;;
                3)
                    echo "Exiting..."
                    exit 0
                    ;;
                *)
                    echo "Invalid option. Try another one."
                    break
                    ;;
            esac
        done
        if [[ $REPLY != 3 ]]; then
            echo "Press Enter to return to the main menu..."
            read
        fi
    done
}

function browse_previous_scans() {
    echo "Available scan results:"
    dirs=(*/)
    if [ ${#dirs[@]} -eq 0 ]; then
        echo "No directories found."
        return
    fi
    select dir in "${dirs[@]}" "Conduct new scans" "Quit"; do
        case $dir in
            "Conduct new scans")
                setup_scan_environment
                break
                ;;
            "Quit")
                echo "Exiting..."
                exit 0
                ;;
            *)
                enter_directory "$dir"
                break
                ;;
        esac
    done
}

function enter_directory() {
    local dir=$1
    cd "$dir"
    echo "You are now in $(pwd)"
    while true; do
        echo "Files and directories in $(basename $(pwd)):"
        files=(*)
        select file in "${files[@]}" "Go Back" "Quit"; do
            case $file in
                "Go Back")
                    cd ..
                    break  
                    ;;
                "Quit")
                    echo "Exiting..."
                    exit 0
                    ;;
                *)
                    display_or_edit_file "$file"
                    break
                    ;;
            esac
        done
        if [[ "$file" == "Go Back" || "$file" == "Quit" ]]; then
            break
        fi
    done
}

function display_or_edit_file() {
    local file=$1
    if [[ -d "$file" ]]; then
        cd "$file"
        echo "Entering directory: $(pwd)"
    else
        echo "Contents of $file:"
        cat "$file"
        echo "Press any key to continue..."
        read -n 1
    fi
}

function generate_unique_dir() {
    local base_dir=$1
    local timestamp=$(date +%Y%m%d%H%M%S)
    local counter=0
    local unique_dir="${base_dir}/${timestamp}_${counter}"
    while [ -d "$unique_dir" ]; do
        ((counter++))
        unique_dir="${base_dir}/${timestamp}_${counter}"
    done
    mkdir -p "$unique_dir"
    echo $unique_dir
}

#1.Getting the User Input
#1.4 Make sure the input is valid.- checking the ip address..
function validate_ip() {
    local ip=$1
    IFS='.' read -ra octets <<< "$ip"
    if [ ${#octets[@]} -ne 4 ]; then
        echo "IP address format error: Incorrect number of octets."
        return 1
    fi
    for octet in "${octets[@]}"; do
        if [[ "$octet" == "*" ]]; then
            octet="0-255"  
        fi
        if [[ "$octet" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local lower=$(echo $octet | cut -d'-' -f1)
            local upper=$(echo $octet | cut -d'-' -f2)
            if ! [[ "$lower" =~ ^[0-9]+$ ]] || ! [[ "$upper" =~ ^[0-9]+$ ]] ||
               [ "$lower" -lt 0 ] || [ "$lower" -gt 255 ] ||
               [ "$upper" -lt 0 ] || [ "$upper" -gt 255 ] ||
               [ "$lower" -gt "$upper" ]; then
                echo "IP address format error: Octet range $octet is invalid."
                return 1
            fi
        elif ! [[ "$octet" =~ ^[0-9]+$ ]] || [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
            echo "IP address format error: Each octet must be a number between 0 and 255."
            return 1
        fi
    done
    return 0
}

#1.1 Get from the user a network to scan.

function setup_scan_environment() {
    echo "Please enter a network or specific address target to scan (e.g., 192.168.1.0/24, 1.1.1.0-255, 2.2.2.2):"
    while true; do
        read network
        network=$(echo $network | tr -d ' ' | sed 's/\*/0-255/g')
        if validate_network $network; then
            network_to_scan=$network
            echo "[+]Network to scan: $network_to_scan"
            break
        else
            echo "Invalid format. Please enter a valid IPv4 address, range, or CIDR notation."
        fi
    done
    request_directory_name
}

function validate_network() {
    local network=$1
    if [[ $network =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        local ip=$(echo $network | cut -d'/' -f1)
        local cidr=$(echo $network | cut -d'/' -f2)
        if validate_ip $ip && [[ $cidr -ge 0 && $cidr -le 32 ]]; then
            echo "You have entered a valid CIDR network: $network"
            return 0
        fi
    elif [[ $network =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local start_ip=$(echo $network | cut -d'-' -f1)
        local end_ip=$(echo $network | cut -d'-' -f2)
        if validate_ip $start_ip && validate_ip $end_ip; then
            echo "You have entered a valid IP range: $network"
            return 0
        fi
    elif validate_ip $network; then
        echo "You have entered a valid IP address or octet range: $network"
        return 0
    fi
    return 1
}

#1.2 Get from the user a name for the output directory.

function request_directory_name() {
    echo "Please enter a name for the output directory where the results will be saved:"
    read output_directory
    if [ ! -d "$output_directory" ]; then
        mkdir -p "$output_directory"
        echo "[+] Output directory '$output_directory' has been created."
    else
        echo "[+] Output directory '$output_directory' already exists."
    fi

    scan_directory=$(generate_unique_dir "$output_directory")
    echo "[+] Unique scan directory '$scan_directory' has been created for this scan session."
    install_required_tools
    select_scan_type
}

function install_required_tools() {
    local TOOLS=( "nmap" "masscan" )
    echo "[+]Installing tools required for the work. Existing tools will not be reinstalled."
    for package_name in "${TOOLS[@]}"; do
        dpkg -s "$package_name" >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "[*] Installing $package_name..."
            sudo apt-get install "$package_name" -y >/dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo "[#] $package_name installed on your machine."
            else
                echo "[-] Failed to install $package_name."
            fi
        else
            echo "[#] $package_name is already installed on your machine."
        fi
    done
}

#1.3 Allow the user to choose 'Basic' or 'Full'.

function select_scan_type() {
    echo "Please choose the scan type:"
    echo "1. Basic"
    echo "2. Full"
    while true; do
        read -p "Enter your choice (1 or 2): " choice
        case $choice in
        1)
            scan_type="Basic"
            conduct_scan "Basic"
            break
            ;;
        2)
            scan_type="Full"
            conduct_scan "Full"
            break
            ;;
        *)
            echo "[!]Invalid choice. Please enter 1 or 2."
            ;;
        esac
    done
}

#1.3.1 Basic: scans the network for TCP and UDP, including the service version and weak passwords.
#1.3.2 Full: include Nmap Scripting Engine (NSE), weak passwords, and vulnerability analysis.

function conduct_scan() {
    local scan_type=$1
    echo "[+]You have chosen the $scan_type scan."
    if [ "$scan_type" == "Basic" ]; then
        echo '[+]Scanning with nmap and masscan, this may take a few minutes...Go for a coffee break and come back'
        sudo nmap $network_to_scan -sn | grep 'Nmap scan report for' | awk '{print $5}' > "$scan_directory/hostsup.txt"
        sudo nmap -iL "$scan_directory/hostsup.txt" -p- -sV -T5 --script=ftp-brute.nse,ssh-brute.nse,telnet-brute.nse,rlogin-brute.nse,smb-brute.nse > "$scan_directory/basicscanres.txt"
        sudo masscan -pU:1-65535 -iL "$scan_directory/hostsup.txt" --rate 20000 >> "$scan_directory/basicscanres.txt" 2>&1
        echo "[+]Basic scan complete. Results saved."
        check_credentials "$scan_directory/basicscanres.txt"
    elif [ "$scan_type" == "Full" ]; then
        echo '[+]Scanning with nmap and masscan, this may take a few minutes...Go for a coffee break and come back'
        sudo nmap $network_to_scan -sn | grep 'Nmap scan report for' | awk '{print $5}' > "$scan_directory/hostsup.txt"
        sudo nmap -iL "$scan_directory/hostsup.txt" -p- -sV -T5 --script=ftp-brute.nse,ssh-brute.nse,telnet-brute.nse,rlogin-brute.nse,smb-brute.nse,vulners.nse --script-args mincvss=7.0 > "$scan_directory/fullscanres.txt"
        sudo masscan -pU:1-65535 -iL "$scan_directory/hostsup.txt" --rate 20000 >> "$scan_directory/fullscanres.txt" 2>&1
        echo "[+]Full scan complete. Results saved."
        check_credentials "$scan_directory/fullscanres.txt"
    fi
    run_hydra
}

#2. Weak Credentials
#2.1 Look for weak passwords used in the network for login services.- part of 1.3.1-1.3.2
#2.1.1 Have a built-in password.lst to check for weak passwords.-part of 1.3.1-1.3.2

function check_credentials() {
    local scan_file=$1
    echo "Checking for valid credentials found during the scan..."

        awk '
    {
        # Store current and the last two lines in an array
        lines[(NR % 3)] = $0
    }
    /Valid credentials/ {
        # Check the two preceding lines for the word "brute" and print them if they contain "brute"
        if (lines[((NR-2) % 3)] ~ /brute/)
            print lines[((NR-2) % 3)]
        if (lines[((NR-1) % 3)] ~ /brute/)
            print lines[((NR-1) % 3)]
        
        # Print the current line with "Valid credentials"
        print $0
    }
    ' "$scan_file" | while read -r line; do
        echo -e "\e[32m$line\e[0m"
    done
}

#2.1.2 Allow the user to supply their own password list.
#2.2 Login services to check include: SSH, RDP, FTP, and TELNET.

function run_hydra() {
    while true; do
    echo "Do you want to use Hydra to perform brute force attacks using your own username and password lists? (Y/N)"
    read use_hydra
    use_hydra=$(echo "$use_hydra" | tr '[:lower:]' '[:upper:]')  

    if [[ "$use_hydra" == "Y" ]]; then
        echo "Checking if Hydra is installed..."
        if ! which hydra > /dev/null; then
            echo "Hydra is not installed. Installing Hydra..."
            sudo apt-get install -y hydra
        else
            echo "Hydra is already installed."
        fi

        mkdir -p "$scan_directory/hydraresults"

        echo "Please write down the full location of the username file:"
        read username_file

        echo "Please write down the full location of the password file:"
        read password_file

        echo "[+]Running Hydra brute force attack on SSH, RDP, FTP, and TELNET..."
        for ip_address in $(cat "$scan_directory/hostsup.txt"); do
            result_file="$scan_directory/hydraresults/$ip_address.txt"
            echo "Results for $ip_address:" > "$result_file" 

            for service in ssh rdp ftp telnet; do
                temp_file="$scan_directory/hydraresults/temp_$service_$ip_address.txt"
                hydra -L "$username_file" -P "$password_file" $service://$ip_address \
                      -o "$temp_file" -b text >/dev/null 2>&1

                if [ -s "$temp_file" ]; then
                    echo "Successful $service login at $ip_address:" >> "$result_file"
                    cat "$temp_file" >> "$result_file"
                    rm "$temp_file" 
                fi
            done
        done

        echo "Hydra brute force attacks complete. Consolidated results saved in the output directory."
        break
    elif [[ "$use_hydra" == "N" ]]; then
        echo "Skipping Hydra brute force attack."
        break
    else
        echo "[!]Invalid input: $use_hydra. Please enter Y or N."
    fi
done

echo "[+]Results for your Hydra action:"
cat "$scan_directory/hydraresults/"* | grep -v "^# Hydra v" | grep -v "^Successful" | sed $'s/^/\033[0;32m/' | sed $'s/$/\033[0m/' &&
map_vulnerabilities
}

#3. Mapping Vulnerabilities
#3.1 Mapping vulnerabilities should only take place if Full was chosen.
#3.2 Display potential vulnerabilities via NSE and Searchsploit.

function map_vulnerabilities() {
    if [ "$scan_type" == "Full" ]; then
        echo "Mapping vulnerabilities based on the results of the full scan..."
        grep -a "CVE-" $scan_directory/fullscanres.txt >> $scan_directory/vulnerability_report.txt
        echo -e "\e[32m[+]Vulnerabilities and service details found:\e[0m"
        cat $scan_directory/vulnerability_report.txt
        echo -e "\e[0m" 
        echo "[+]Analyzing potential vulnerabilities using NSE and Searchsploit..."
        sleep 1
        echo "Searching for known exploits for identified vulnerabilities..."
        echo "Known exploits:" > $scan_directory/potential_vulners.txt

        grep -aoP 'CVE-\d{4}-\d+' $scan_directory/vulnerability_report.txt | sort | uniq | while read -r line; do
            local formatted_cve=$(echo "$line" | awk '{print tolower($0)}' | tr "-" " ")
            searchsploit --cve $formatted_cve | grep -v "No Results" >> $scan_directory/potential_vulners.txt
        done

        echo "Searchsploit analysis complete. Results saved in $scan_directory/potential_vulners.txt."
        cat $scan_directory/potential_vulners.txt
    fi
	consolidate_results
}


function consolidate_results() {
    echo "Consolidating all results into one file..."
    touch "$scan_directory/resultstogether.txt"

    find "$scan_directory" -type f -name '*.txt' ! -name 'resultstogether.txt' -exec cat {} + >> "$scan_directory/resultstogether.txt"

    echo "All your results have been saved to one file called resultstogether.txt where you can see all the results from running the tool."
    finalize_results
}

#4. Log Results
#4.1 During each stage, display the stage in the terminal.- displayed to the user
#4.2 At the end, show the user the found information. - All results are displayed to the user during the use of the tool and are also saved.
#4.3 Allow the user to search inside the results. - Appears at the start of the tool's startup.

#4.4 Allow to save all results into a Zip file.

function finalize_results() {
    echo "[+] Do you want to zip the results?"
    echo "1. Yes, zip the files."
    echo "2. No, do not zip, continue without zipping."

    read -p "Enter your choice (1 or 2): " zip_choice

    case $zip_choice in
        1)
            echo "Please enter the name for the zip file (without the .zip extension):"
            read zip_name
            if [[ -z "$zip_name" ]]; then
                zip_name="Your_Results"  
            fi
            echo -e "\033[0;32m[+] Zipping all the results into an archive named: '${zip_name}.zip' located at the same place where the script is run.\033[0m"
            zip -r "${zip_name}.zip" "$scan_directory" >/dev/null 2>&1
            chmod 777 "${zip_name}.zip"
            echo "[+]Zipping complete. Your results are in '${zip_name}.zip'."
            sleep 3
            echo -e "\e[33m"
			echo "╔══════════════════════════════╗"
			echo "║        BYE BYE!!!            ║"
			echo "╚══════════════════════════════╝"
			echo -e "\e[0m"
			sleep 3
			exit
            ;;
        2)
            echo "[+]Proceeding without zipping the files."
            sleep 3
            echo -e "\e[33m"
			echo "╔══════════════════════════════╗"
			echo "║        BYE BYE!!!            ║"
			echo "╚══════════════════════════════╝"
			echo -e "\e[0m"
			sleep 3
			exit
            ;;
        *)
            echo "[!] Invalid choice. Please enter 1 or 2."
            finalize_results
            ;;
    esac
}


# THE START IS HERE!!!
display_menu

