import paramiko
import time

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('172.20.242.254', username='admin', password='Bubbapaloalto632@', look_for_keys=False)

shell = client.invoke_shell()
time.sleep(2)

shell.send('set cli pager off\n')
time.sleep(1)
shell.send('show running security-policy\n')
time.sleep(5)

output = shell.recv(65535).decode()

with open('palo_security_policy.txt', 'w') as f:
    f.write(output)

client.close()
print("Done")