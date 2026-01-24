import paramiko

FIREWALL_IP = '172.20.242.254'
USERNAME = 'admin'
PASSWORD = 'Bubbapaloalto632@'

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(FIREWALL_IP, username=USERNAME, password=PASSWORD, look_for_keys=False)

# Disable pagination first, then get policy
commands = "set cli pager off\nshow running security-policy\n"

stdin, stdout, stderr = client.exec_command(commands, timeout=30)
output = stdout.read().decode()

with open('palo_security_policy.txt', 'w') as f:
    f.write(output)

client.close()
print("Done")