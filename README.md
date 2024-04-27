Configure in the config file:
 - the first 3 octets of the network address on which your devices reside (str).
 - vlan number for access vlan you would like configured (int).
 - vlan number for the voice vlan you would like configured (int). 
 - login credentials (str).

Accepts as input:
 - the 4th octet of the network address for the device you'd like to connect to (allows for easy device switching each time you run).
 - the first number of the interface name for the interface you would like re-configured (ex. for interface GigabitEthernet 2/0/16, you would enter: 2; n where n == n/0/16).
 - the second number of the interface name for the interface you would like re-configured (ex. for interface GigabitEthernet 2/0/16, you would enter: 16; n where n == 2/0/n).


Simple script that runs a loop to re-configure interface voice and data vlans on cisco switches. To switch devices, ctrl + c to stop and re-run, specifying a new 4th octet of the configured network address. 
Offers option to save configuration after writing changes. 
