import pexpect
import time

# Define connection parameters for Telnet
telnet_params = {
    'ip': '192.168.56.101',
    'user': 'cisco',
    'passwd': 'cisco123!',
    'hostname_change': 'TelnetRouter',
    'config_file': 'telnet_running_config.txt'
}

# Initialize a Telnet session
telnet_session = pexpect.spawn(f'telnet {telnet_params["ip"]}', encoding='utf-8', timeout=20)
login_attempt = telnet_session.expect(['Username:', pexpect.TIMEOUT])

# Verify if the Telnet session was created successfully
if login_attempt != 0:
    print(f'--- ERROR! Failed to create session for: {telnet_params["ip"]}')
    exit()

# Input the username
telnet_session.sendline(telnet_params['user'])
telnet_session.expect(['Password:', pexpect.TIMEOUT])

# Verify username input success
if login_attempt != 0:
    print(f'--- ERROR! Failed to input username: {telnet_params["user"]}')
    exit()

# Input the password
telnet_session.sendline(telnet_params['passwd'])
telnet_session.expect(['#', pexpect.TIMEOUT])

# Verify password input success
if login_attempt != 0:
    print(f'--- ERROR! Failed to input password for: {telnet_params["user"]}')
    exit()

# Connection success message
print('------------------------------------------------------')
print('--- SUCCESS! Connected to:', telnet_params["ip"])
print('--- Username:', telnet_params["user"])
print('--- Password:', telnet_params["passwd"])
print('------------------------------------------------------')

# Enter configuration mode and update the hostname
telnet_session.sendline('configure terminal')
telnet_session.expect([r'\(config\)#', pexpect.TIMEOUT])
telnet_session.sendline(f'hostname {telnet_params["hostname_change"]}')
telnet_session.expect([rf'{telnet_params["hostname_change"]}\(config\)#', pexpect.TIMEOUT])

# Exit configuration mode
telnet_session.sendline('exit')
telnet_session.sendline('exit')

# Fetch and save the running configuration
telnet_session.sendline('show running-config')
telnet_session.expect([r'#', pexpect.TIMEOUT])
with open(telnet_params['config_file'], 'w') as file:
    file.write(telnet_session.before)

# Terminate the Telnet session
telnet_session.sendline('quit')
telnet_session.close()


# Define connection parameters for SSH
ssh_params = {
    'ip': '192.168.56.101',
    'user': 'prne',
    'passwd': 'cisco123!',
    'enable_pass': 'class123!',
    'syslog_server_ip': '192.168.1.100',  # Syslog server IP
    'hardening_file': 'cisco_hardening_guidelines.txt'  # Hardening guidelines file path
}

try:
    # Attempt to start the SSH session
    print(f"Attempting SSH connection to {ssh_params['ip']}...")
    ssh_session = pexpect.spawn(f'ssh -o StrictHostKeyChecking=no {ssh_params["user"]}@{ssh_params["ip"]}', encoding='utf-8', timeout=60)

    # Enable session logging for debugging
    ssh_session.logfile = open("ssh_session_log.txt", "w")

    # Wait for the password prompt
    ssh_prompt = ssh_session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])
    
    # Handle the SSH password prompt
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

except pexpect.exceptions.EOF as e:
    print(f"SSH Connection failed: {str(e)}")
    exit()

except pexpect.exceptions.TIMEOUT as e:
    print(f"SSH Timeout: {str(e)}")
    exit()

# Enter enable mode for SSH
ssh_session.expect(['>', pexpect.TIMEOUT])
ssh_session.sendline('enable')
ssh_session.expect(['Password:', pexpect.TIMEOUT])
ssh_session.sendline(ssh_params['enable_pass'])
ssh_session.expect(['#', pexpect.TIMEOUT])

# Success message for SSH connection
print(f"--- SUCCESS! Connected to: {ssh_params['ip']}")

# Function to load hardening guidelines
def load_hardening_guidelines(file_path):
    """Loads the hardening guidelines from a file."""
    try:
        with open(file_path, 'r') as file:
            return file.read().splitlines()
    except Exception as e:
        print(f"Error loading hardening guidelines: {e}")
        return None

# Function to check compliance against hardening guidelines
def check_compliance(running_config, guidelines):
    """Compares the running config to hardening guidelines."""
    non_compliant = [line for line in guidelines if line not in running_config]
    
    if non_compliant:
        print("Non-compliant configurations found:")
        for item in non_compliant:
            print(f"- Missing: {item}")
    else:
        print("All configurations are compliant with hardening guidelines.")

# Function to configure syslog
def configure_syslog(ssh_session, syslog_ip):
    """Configures the device to send logs to a syslog server."""
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

# Step 1: Retrieve the running configuration from the device
ssh_session.sendline('show running-config')
ssh_session.expect([r'#', pexpect.TIMEOUT])
running_config = ssh_session.before.decode().splitlines()

# Step 2: Load hardening guidelines
guidelines = load_hardening_guidelines(ssh_params['hardening_file'])

if guidelines:
    print("\nChecking compliance with Cisco hardening guidelines...")
    check_compliance(running_config, guidelines)

# Step 3: Configure syslog to enable event logging and monitoring
print("\nConfiguring syslog on the device...")
configure_syslog(ssh_session, ssh_params['syslog_server_ip'])

# Close the SSH session
ssh_session.close()
