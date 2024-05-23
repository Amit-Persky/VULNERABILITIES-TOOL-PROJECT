VULNERABILITIES TOOL PROJECT - AMIT PERSKY

This project involves creating a script for comprehensive network device mapping, identifying ports, services, and vulnerabilities. The user defines the network range, after which the program deploys tools like nmap and masscan for scanning and mapping purposes, storing the data in a newly created directory. The script also probes for network vulnerabilities, employing nmap, searchsploit, hydra, and medusa to identify security gaps, such as weak passwords. Finally, the scan summary and findings are presented to the user.

In the VULNERABILITIES TOOL PROJECT.pdf, you can see how the script is working and behaving.

Here are the detailed instructions for using the network device mapping and vulnerability scanning tool:

---

### Comprehensive Network Device Mapping and Vulnerability Scanning Tool

#### Overview
This tool performs comprehensive network device mapping, identifying ports, services, and vulnerabilities. It uses tools such as `nmap`, `masscan`, `searchsploit`, `hydra`, and `medusa` for scanning and analysis. The tool provides a detailed summary of findings and saves the results for further inspection.

#### Instructions for Use

1. **Setup and Installation:**
   - Ensure you have the required tools installed on your system. The script will check for `nmap` and `masscan`, and install them if they are not already present.
   - Download the script file (`vultool.sh`) to your local machine.

2. **Running the Script:**
   - Open a terminal and navigate to the directory where the script is located.
   - Make the script executable by running: `chmod +x vultool.sh`
   - Execute the script: `sudo ./vultool.sh`

3. **Menu Options:**
   - Upon running the script, you will see a menu with the following options:
     - **Looking at previous scans**: View results of previously conducted scans.
     - **Conduct new scans**: Start a new scan session.
     - **Quit**: Exit the tool.

4. **Conducting a New Scan:**
   - **Enter Network to Scan**: Provide the network or specific address range (e.g., `192.168.1.0/24`, `1.1.1.0-255`, `2.2.2.2`).
   - **Name for Output Directory**: Specify a name for the output directory where the results will be stored. A unique sub-directory will be created for each scan session.
   - **Choose Scan Type**: 
     - **Basic Scan**: Scans the network for TCP and UDP services, including version detection and weak password checks.
     - **Full Scan**: Includes all features of the Basic scan plus additional vulnerability analysis using `nmap` Scripting Engine (NSE) and `searchsploit`.

5. **Checking for Weak Passwords:**
   - During the scan, the tool will check for weak passwords using a built-in password list.
   - **Custom Password List**: If you prefer to use your own lists, replace `userlist.txt` and `passlist.txt` with your files, ensuring they have the same names.

6. **Using Hydra for Brute Force Attacks:**
   - You will be prompted to use Hydra for brute force attacks. If you choose to proceed:
     - Ensure Hydra is installed (the script will prompt for installation if not found).
     - Provide the full paths to your custom username (`userlist.txt`) and password (`passlist.txt`) files.
     - The script will attempt brute force attacks on SSH, RDP, FTP, and TELNET services, and save the results.

7. **Mapping Vulnerabilities (Full Scan Only):**
   - The script identifies and logs known vulnerabilities.
   - It uses `searchsploit` to find available exploits for identified vulnerabilities and logs the details.

8. **Saving Results:**
   - Results are displayed in real-time and saved in the specified output directory.
   - Option to consolidate all results into a single file (`resultstogether.txt`).
   - Option to zip all results into an archive for easy transfer or storage.

9. **Ethical Usage and Responsibility:**
   - This tool is intended for ethical purposes only. Ensure you have proper authorization before scanning any network.
   - Use of this tool is at your own risk. The author is not responsible for any misuse or damage caused.

![1](https://github.com/Amit-Persky/VULNERABILITIES-TOOL-PROJECT/assets/159085398/5bf2b331-def8-44ca-8a07-906be3c80af5)
