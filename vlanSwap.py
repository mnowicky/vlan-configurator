import yaml
import re
from netmiko import ConnectHandler
from logger import Logger
from ciscoAPI import Cisco as cisco

# load config file for use globally
with open('config.yml', 'r') as cf:
    config = yaml.safe_load(cf)

def runVerbose(connection):
	i1 = input(f'Enter interface first number (GiX/0/1): ')
	i2 = input(f'Enter interface second number (Gi1/0/X):')
	dvl = config['configuration']['data_vlan']
	vvl = config['configuration']['voice_vlan']
	intType = config['configuration']['int_type']
	cisco.set_access_voice_vlans(connection, dvl, vvl, i1, i2, intType)

def runConfigMode(connection):
	return



def run(m):
	#ip = config['connection']['switch IP']
	creds = config['credentials']
	octets = config['configuration']['network_octets']
	mode = str(m)
	cf.close()

	swIP = input(f'Enter the host portion of the network address of switch: {octets} x')
	ip = str(octets+swIP)
	print(f'Connecting to switch at IP: {ip}')

	connection = cisco.connectSwitch(ip, creds)

	while True:
		if mode == 'v':
			runVerbose(connection)
		else:
			runConfigMode(connection)
		'''
		quit = input(f'Type q to quit, (c/v) to change modes, else run again...')
		if quit.lower() == 'q':
			print(f'Exiting...')
			break
		else:
			if quit:
				mode = quit.lower()
		'''



if __name__ == "__main__":
	#mode = input(f'Verbose or config mode? (type v or c, default is config mode):')
	mode = 'v'
	run(mode)
