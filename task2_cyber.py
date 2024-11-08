import pexpect

# Define connection parameters for SSH
ssh_params = {
    'ip': '192.168.56.101',
    'user': 'prne',
    'passwd': 'cisco123!',
    'enable_pass': 'class123!',
    'syslog_server_ip': '192.168.1.100',  # Syslog server IP
    'hardening_file': 'cisco_hardening_guidelines.txt'  # Hardening guidelines file path
}

# Attempt to establish SSH connection
try:
    print(f"Attempting SSH connection to {ssh_params['ip']}...")
    ssh_session = pexpect.spawn(f'ssh -o StrictHostKeyChecking=no {ssh_params["user"]}@{ssh_params["ip"]}', encoding='utf-8', timeout=60)

    # Enable session logging for debugging
    ssh_session.logfile = open("ssh_session_log.txt", "w")

    # Wait for the password prompt
    ssh_prompt = ssh_session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

    if ssh_prompt == 0:
        print("SSH password prompt detected. Sending password...")
        ssh_session.sendline(ssh_params['passwd'])
    elif ssh_prompt == 1:
        print(f"TIMEOUT: Unable to connect to {ssh_params['ip']}")
        ssh_session.close()
        exit()
    elif ssh_prompt == 2:
        print(f"--- ERROR! Failed to create SSH session for {ssh_params['ip']} (EOF received)")
        ssh_session.close()
        exit()

    # Wait for enable mode prompt
    ssh_session.expect(['>', pexpect.TIMEOUT])
    ssh_session.sendline('enable')
    ssh_session.expect(['Password:', pexpect.TIMEOUT])

    # Send enable password
    ssh_session.sendline(ssh_params['enable_pass'])
    ssh_session.expect(['#', pexpect.TIMEOUT])

    print(f"--- SUCCESS! Connected to: {ssh_params['ip']}")

except pexpect.exceptions.EOF as e:
    print(f"SSH Connection failed: {str(e)}")
    exit()

except pexpect.exceptions.TIMEOUT as e:
    print(f"SSH Timeout: {str(e)}")
    exit()

# Retrieve the running configuration
def get_running_config(ssh_session):
    """Fetches the running configuration from the device."""
    print("Fetching running config...")
    ssh_session.sendline('show running-config')
    index = ssh_session.expect([r'#', pexpect.TIMEOUT, pexpect.EOF])
    if index == 0:
        running_config = ssh_session.before.decode()
        return running_config
    else:
        print("Error: Unable to retrieve running config.")
        return None

# Load hardening guidelines
def load_hardening_guidelines(file_path):
    """Loads hardening guidelines from a file."""
    try:
        with open(file_path, 'r') as file:
            return file.read().splitlines()
    except Exception as e:
        print(f"Error loading hardening guidelines: {e}")
        return None

# Check compliance with hardening guidelines
def check_compliance(running_config, guidelines):
    """Compares running config to hardening guidelines."""
    if not running_config:
        print("No running config available to check.")
        return

    non_compliant = [line for line in guidelines if line not in running_config]

    if non_compliant:
        print("Non-compliant configurations found:")
        for item in non_compliant:
            print(f"- Missing: {item}")
    else:
        print("All configurations are compliant with hardening guidelines.")

# Configure syslog
def configure_syslog(ssh_session, syslog_ip):
    """Configures the device to send logs to a syslog server."""
    print(f"Configuring syslog to server {syslog_ip}...")
    syslog_commands = [
        "configure terminal",
        f"logging host {syslog_ip}",
        "logging trap informational",  # Sets logging level to informational
        "end",
        "write memory"  # Saves the config
    ]
    
    for command in syslog_commands:
        ssh_session.sendline(command)
        ssh_session.expect([r'#', pexpect.TIMEOUT])

    print(f"Syslog server {syslog_ip} configured successfully.")

# Retrieve the running configuration
running_config = get_running_config(ssh_session)

# Load the hardening guidelines
guidelines = load_hardening_guidelines(ssh_params['hardening_file'])

if guidelines:
    print("\nChecking compliance with Cisco hardening guidelines...")
    check_compliance(running_config, guidelines)

# Configure syslog to enable event logging and monitoring
print("\nConfiguring syslog on the device...")
configure_syslog(ssh_session, ssh_params['syslog_server_ip'])

# Close the SSH session
ssh_session.sendline('exit')
ssh_session.close()
