from netmiko import ConnectHandler
import re
import yaml
from logger import Logger as logger
import time



class Cisco(object):
    ''' custom-made api to interface with Cisco catalyst switches '''


    @staticmethod
    def connectSwitch(ip: str, creds: dict):
        ''' open ssh connection to a cisco switch, returns connected session '''
        #print(creds)
        
        for credential in creds:
            user = credential['username']
            passwd = credential['password']
            devType = 'cisco_ios'
            hostIP = ip
            logger.logAndPrint(f'Attempting to connect to switch {ip} with {user} and {passwd}...', 1)
            try:
                connectedSession = ConnectHandler(username=user, password=passwd, host=hostIP, device_type=devType)
                break
            except Exception as e:
                logger.logAndPrint(f'Failed to connect to switch {ip}.', 3)
                logger.logAndPrint(f'Error: {e}.', 3)
        return connectedSession
    
    @staticmethod
    def checkInterface(int:str):
        ''' Check mac table on starting/core switch to ensure mac table returns an interface for a given target MAC. '''
        if 'None' in int:
            logger.logAndPrint(f'MAC address does not exist in core switch mac table. MAC not found.', 3)
            return False
        else:
            logger.logAndPrint(f'MAC address returned valid interface {int} from core-switch mac table.', 1)
            return True
            
    @staticmethod
    def port_group_interfaces(interface: str, connection):
        ''' Queries and returns the member interfaces of a port-group, if a mac address is determined to be associated to a port-group. '''
        conn = connection
        # Splice the port-group number from the end of the interface argumnent
        pg_number = interface[-2:] 

        # Issue command to show interfaces comprising given a port channel
        pg_info = conn.send_command(f'show interface port-channel {pg_number}')
        # Regex to pull "Ethxx" interface names from results
        pg_interfaces = re.findall(r"Eth[\w\/]+?(?=[,\s])", pg_info, re.MULTILINE)

        # Remove incorrect 'EtherType' from results
        for item in pg_interfaces:
            if len(item) > 7:
                pg_interfaces.remove(item)
        
        # Count number of interfaces comprising port-group
        num_interfaces = len(pg_interfaces) 
        logger.logAndPrint(f'Discovered a total of {num_interfaces}  interfaces comprising associated port-channel {interface}, they are: {pg_interfaces}', 1)
        # Return interfaces as a list of port-group member interfaces
        return pg_interfaces


    @staticmethod
    def find_interfaces(mac: str, connection):
        ''' search mac table to identify interface leading to target MAC. Returns list containing interface(s), handles instances of port-groups.'''
        with open('config.yml', 'r') as file:
            config = yaml.safe_load(file)

        mac = Cisco.format_mac(mac)

        # pass connection
        conn = connection
        # Pull mac address table with interfaces associated to this mac
        mac_table = conn.send_command(f'sh mac address-table address {mac}')
        # Check to make sure the returned interface is not a port-group
        port_group_match = re.search(r"Po\d{2}", mac_table, re.MULTILINE)

        # If it is a port-group, send to port_group_interfaces() function to determine membber interfaces.
        if port_group_match:
            logger.logAndPrint(f'Port-group detected. Downlink switch is connected via multiple interfaces.', 1)
            pg = str(port_group_match.group())
            pg_interfaces = Cisco.port_group_interfaces(pg, conn)
            config['output']['current_int'] = pg_interfaces
            # Save the updated dictionary back to the YAML file
            with open('config.yml', 'w') as file:
                yaml.dump(config, file)
                time.sleep(2)
            file.close()
            return (pg_interfaces)

        # Check mac address-table for interface associated to mac
        matchInterface = re.findall(r"Eth[\w\/]+?(?=[,\s])", mac_table, re.MULTILINE)
        matchGigInterface = re.findall(r"Gi[\w\/]+?(?=[,\s])", mac_table, re.MULTILINE)
        matchVlan = re.findall(r"Vl\d+", mac_table, re.MULTILINE)

        if matchInterface:
            logger.logAndPrint(f'Mac address {mac} exists in mac table on interface {matchInterface}', 1)
            intString = str(matchInterface)
            config['output']['current_int'] = intString
            # Save the updated dictionary back to the YAML file
            with open('config.yml', 'w') as file:
                yaml.dump(config, file)
                time.sleep(2)
            file.close()
            return matchInterface
        elif matchGigInterface:
            logger.logAndPrint(f'Mac address {mac} exists in mac table on interface {matchInterface}', 1)
            intString = str(matchGigInterface)
            config['output']['current_int'] = intString
            # Save the updated dictionary back to the YAML file
            with open('config.yml', 'w') as file:
                yaml.dump(config, file)
                time.sleep(2)
            file.close()
            return matchGigInterface
        elif matchVlan:
            logger.logAndPrint(f'Mac address {mac} exists in mac table on interface {matchVlan}', 1)
            logger.logAndPrint(f'Mac address is likely local to this switch.', 1)
            intString = str(matchVlan)
            config['output']['current_int'] = intString
            # Save the updated dictionary back to the YAML file
            with open('config.yml', 'w') as file:
                yaml.dump(config, file)
                time.sleep(2)
            file.close()
            return matchVlan
        else:
            logger.logAndPrint(f'Mac address {mac} does not exist on mac table. ', 1)
            nonEth = ['None']
            config['output']['current_int'] = str(nonEth)
            with open('config.yml', 'w') as file:
                yaml.dump(config, file)
                time.sleep(2)
            file.close()
            return nonEth

    @staticmethod
    def format_mac(mac: str):
        # Convert MAC to consistent format, if required (xx:xx:xx:xx:xx:xx to xxxx.xxxx.xxxx):
        if ':' in mac:
            # Remove colons and convert to lowercase; insert dots at appropriate positions
            formatted_mac = mac.replace(":", "").lower()
            formatted_mac = formatted_mac[:4] + "." + formatted_mac[4:8] + "." + formatted_mac[8:]
            logger.logAndPrint(f'Formatted mac from {mac} to {formatted_mac}.', 1)
        elif '.' in mac:
            formatted_mac = mac
        else:
            result = ""
            for i, char in enumerate(mac):
                if i == 4 or i == 8:
                    result += '.'  # Insert '.' after every 4th character
                result += char
            print(result)
            formatted_mac = result
        
        return formatted_mac

    @staticmethod
    def check_mac_table(ip: str, mac: str, creds):
        conn = Cisco.connectSwitch(ip, creds)

        # Retrieve mac table
        mac_table = conn.send_command(f'show mac address-table address {mac}')

        # Convert MAC to consistent format, if required (xx:xx:xx:xx:xx:xx to xxxx.xxxx.xxxx):
        if ':' in mac:
            # Remove colons and convert to lowercase; insert dots at appropriate positions
            formatted_mac = mac.replace(":", "").lower()
            formatted_mac = formatted_mac[:4] + "." + formatted_mac[4:8] + "." + formatted_mac[8:]
            logger.logAndPrint(f'Formatted mac from {mac} to {formatted_mac}.', 1)
        elif '.' in mac:
            formatted_mac = mac
        else:
            result = ""
            for i, char in enumerate(mac):
                if i == 4 or i == 8:
                    result += '.'  # Insert '.' after every 4th character
                result += char
            print(result)
            formatted_mac = result

        if formatted_mac in str(mac_table):
            mac_exists = True

        if mac in str(mac_table):
            mac_exists = True
        
        mac_format_1 = re.search(r"(\S+/+\S+)$", mac_table, re.MULTILINE)
        mac_format_2 = re.findall(r'\b([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\b', mac_table, re.MULTILINE)
        int_port_group = re.search(r"Po\d{2}", mac_table, re.MULTILINE)
        int_eth = re.findall(r"Eth[\w\/]+?(?=[,\s])", mac_table, re.MULTILINE)
        mac_not_found = re.search(r"Invalid", mac_table, re.MULTILINE)
        if mac_exists:
            logger.logAndPrint(f'Disovered mac {mac} in mac table on device {ip}, this is your next hop.', 1)
            conn.disconnect()
            return True
        elif mac_format_1 or mac_format_2 or int_port_group or int_eth:
            logger.logAndPrint(f'Discovered mac {mac} in mac table on device {ip}, this is your next hop.', 1)
            conn.disconnect()
            return True
        elif mac_not_found:
            logger.logAndPrint(f'Mac {mac} does not exist on mac table for device {ip}, continue checking IPs of other interfaces.', 1)
            conn.disconnect()
            return False
        else:
            logger.logAndPrint(f'Match condition not met while checking IP: ({ip}) mac table for entries for mac: {mac} in mac table.', 3)
            logger.logAndPrint('Mac Table:', 3)
            logger.logAndPrint(mac_table, 3)
            conn.disconnect()
            return False

    @staticmethod      
    def return_switch_name_ip(connection):
        conn = connection
        ip_int_brief = conn.send_command(f'sh ip interface vlan 1')
        hname = conn.send_command(f'sh running-config | include hostname')
        hname = str(hname)
        ip_int_brief = str(ip_int_brief)
        pattern = re.findall(r"Internet address is.*?\n", ip_int_brief, re.MULTILINE)
        pattern2 = re.findall(r"pattern = r'IP address: (.*?)(?=,)", ip_int_brief, re.MULTILINE)
        print(ip_int_brief)
        print(pattern)
        if str(pattern):
            ipFound = True
            ip = str(pattern)
        elif str(pattern2):
            ipFound = True
            ip = str(pattern2)
        else:
            ipFound = False

        if hname:
            print(hname)
            hnameFound = True
        else:
            hnameFound = False
            
        if ipFound and hnameFound:
            return ip, hname
        else:
            return False, 'None'

    @staticmethod
    def set_access_voice_vlans(connection, d_vlan:str, v_vlan:str, interface_first:str, interface_second:str, intType:str):
        conn = connection           #Connection object
        int1 = interface_first      #first part of interface {x} eg. Gix/0/1
        int2 = interface_second     #second part of interface {x} eg. Gi1/0/x
        dvl = d_vlan
        vvl = v_vlan                   #vlan number
        intType = intType            #empty string to hold interface type (gig, tengig, eth)
        intFace = str(f'{intType}{int1}/0/{int2}')
        '''
        interfaces = conn.send_command(f'sh interface summary')
        interfaces = str(interfaces)

        matchGig = re.search(r'GigabitEthernet%s/0/%s' % (int1, int2), interfaces, re.MULTILINE)

        if matchGig:
            print(f'Gigabit ethernet interface detected: {str(matchGig)}')
            intTpe = 'GigabitEthernet'
            intFace = str(f'{intType}{int1}/0/{int2}')
        '''

        config_commands = [
            f"interface {intFace}",
            f"switchport access vlan {dvl}",
            f"switchport voice vlan {vvl}",
            "end",
        ]
        logger.logAndPrint(f'Wrote configuration change to {intFace}.', 1)
        # Send configuration commands
        output = conn.send_config_set(config_commands)
        print(f'Configuration applied: ')
        print(f'{output}')

        saveConfig = input('Would you like to save the config (y/n)?')

        if saveConfig == 'y':
            output += conn.save_config()
            print(f"\n{output}")
            print("\nConfiguration changes applied successfully:")
        else:
            print(f'Configuration changes not saved. Changes will be lost after reboot.')

    #@staticmethod
    #def print_interface_config(connection,




        


    
    @staticmethod
    def find_next_hop(interfaces: list, mac, creds, connection):
        ''' Determines the next hop device, returns IP '''
        conn = connection
        print(f'Function: find_next_hop... interfaces: {interfaces}, mac: {mac}')
        net = '10.101.100'

        with open('config.yml', 'r') as file:
            config = yaml.safe_load(file)


        # Handle instance of multiple interfaces being input, only one of these devices will contain target MAC in mac-table. (port-channel)
        if len(interfaces) > 1:
            mac_found = False # Set mac address found to false.
            ips = [] # List to contain IPs for each of the multiple interfaces detected
            for int in interfaces: # For each interface, determine IP address and append to ips list 
                int = str(int)
                ip_addr = Cisco.find_cdp_ip(int, conn)
                if ip_addr:
                    if net in str(ip_addr):
                        ips.append(ip_addr)
            
            # For each ip in port-channel, login to each switch and check that the mac exists in the mac table.
            if len(ips) > 1:
                for ip in ips:
                    ip = str(ip)
                    print(f'checking {ip}, mac table for presence of mac address {mac}...')
                    mac_found = Cisco.check_mac_table(ip, mac, creds)
                    
                    if mac_found == True:
                        next_hop_ip = str(ip)
                        logger.logAndPrint(f'Determined ip of next-hop switch to be {next_hop_ip}', 1)

                        config['output']['current_ip'] = next_hop_ip
                        config['output']['current_mac'] = mac
                        with open('config.yml', 'w') as file:
                            yaml.dump(config, file)
                            time.sleep(2)
                            file.close()
                        return True, next_hop_ip
                        
                    else:
                        logger.logAndPrint(f'No correct ip found for port-group connected next-hop switch {ip}', 3)
                        return False
            elif not len(ips):
                print(ips)
                ipadd = config['output']['current_ip']
                print(ipadd)
                return False, ipadd 

            else:
                next_hop_ip = str(ips[0])
                print(f'Next hop IP = {next_hop_ip}')

                if net not in next_hop_ip:
                    print(f'{next_hop_ip} not a part of network: {net}')
                    ipadd = config['output']['current_ip']
                    print(f'Local switch must be {ipadd}')
                    return False, ipadd


                logger.logAndPrint(f'Only IP {next_hop_ip} detected for port-group interfaces {interfaces}.', 1)
                config['output']['current_ip'] = next_hop_ip
                config['output']['current_mac'] = mac
                with open('config.yml', 'w') as file:
                    yaml.dump(config, file)
                    time.sleep(2)
                    file.close()
                return True, next_hop_ip
        elif len(interfaces) == 1:
            int = str(interfaces[0])
            next_hop = Cisco.find_cdp_ip(int, conn)
            if next_hop:
                config['output']['current_ip'] = next_hop
                config['output']['current_mac'] = mac
                with open('config.yml', 'w') as file:
                    yaml.dump(config, file)
                    time.sleep(2)
                file.close()
                return True, next_hop
            else:
                ipadd = config['output']['current_ip']
                print(ipadd)
                return False, ipadd 
        else:
            logger.logAndPrint(f'No interfaces detected, check local switch mac address table.')
            ipadd = config['output']['current_ip']
            print(ipadd)
            return False, ipadd 

    
    
    @staticmethod
    def find_cdp_ip(int: str, connection):
        ''' Returns IP address of cdp neighbor detected on interface passed as argument. '''
        conn = connection

        # determine the type of interface syntax used for this switch
        gigabitEth = 'Gi'
        tengigabitEth = 'Te'
        fastEth = 'Eth'
        Po = 'Po'

        #print(f'IP address being passed to function {ip}')
        #print(f'Interface being passed to function {int}')
        print('Interface being passed to find_cdp_ip function '+int)
        

        if fastEth in int:
            logger.logAndPrint(f'FastEthernet type adapter detected ({int}), use cdp command syntax A.', 1)
            raw_output_cdp = conn.send_command(f'sh cdp neighbors interface {int} detail')
        elif gigabitEth in int:
            slicedInt = int[2:]
            logger.logAndPrint(f'GigabitEthernet type adapter detected ({int}), use cdp command syntax B.', 1)
            raw_output_cdp = conn.send_command(f'sh cdp neighbors gigabitEthernet {slicedInt} detail')
        elif tengigabitEth in int:
            slicedInt = int[2:]
            logger.logAndPrint(f'TengigabitEthernet type adapter detected ({int}), use cdp command syntax C.', 1)
            raw_output_cdp = conn.send_command(f'sh cdp neighbors TenGigabitEthernet {slicedInt} detail')
        elif Po in int:
            logger.logAndPrint(f'Detected port-group {int}, re-processing port-group interfaces...', 1)
            pg = Cisco.port_group_interfaces(int, conn)
            print(pg)
            print('Where to from here?')
            return

        else:
            print('Neither interface types are matching')
            return

        with open('config.yml', 'r') as file:
            config = yaml.safe_load(file)
        # Pull network address from config file and check cdp neighbor exists on same network (as some voip phones show as neighbors).
        net = config['settings']['network']
        octets = net.split('.')
        net = '.'.join(octets[:3])
        file.close()
        

        # check cdp neighbor on target interface and obtain it's ip address. 
        match_cdp_ip = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", raw_output_cdp)
        #ip_addr = match_cdp_ip.group()



        if match_cdp_ip:
            print(match_cdp_ip)
            print(f'CDP neighbor ip detected: {match_cdp_ip}')
            if net not in match_cdp_ip[0]:
                logger.logAndPrint(f'CDP neighbor detected {match_cdp_ip} is not a network device (likely cisco voip phone), current switch is local.', 3)
                return False
            ip_addr = match_cdp_ip[0]
            return ip_addr
        elif not match_cdp_ip:
            print(f'No CDP neighbor IPs discovered for {int}')
            print(raw_output_cdp)
            return False
        else:
            logger.logAndPrint(f'No IP detected using regex in function find-cdp-ip, check output:', 3)
            logger.logAndPrint(raw_output_cdp, 3)
            return
