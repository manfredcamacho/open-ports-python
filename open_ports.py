import sys
import socket
import nmap
import netifaces
import json
import requests


POST_ENDPOINT = 'http://127.0.0.1/example/fake_url.php'


def get_network_info(interface_name):
    interface = netifaces.ifaddresses(interface_name)
    ip = interface[netifaces.AF_INET][0]['addr']
    netmask = interface[netifaces.AF_INET][0]['netmask']
    cidr = get_bits_netmask(netmask)
    network_ip = '.'.join(
        [str(int(ip.split('.')[i]) & int(netmask.split('.')[i])) for i in range(4)])
    return (network_ip, cidr)


def scan_ports(interface):
    network_ip, cidr = get_network_info(interface)
    scanner = nmap.PortScanner()

    print()
    print(f'Looking for hosts on {network_ip}/{cidr}... ')

    scanner.scan(hosts=f'{network_ip}/{cidr}', arguments='-sP')
    hosts_up = [x for x in scanner.all_hosts() if scanner[x]
                ['status']['state'] == 'up']

    print()
    print(f'Found {len(hosts_up)} hosts up...')
    print('Scanning ports...')

    output = {}

    try:
        scanner.scan(hosts=' '.join(hosts_up),
                     arguments='-sS -sU -v -sV -F --open')

        print(f'Found {len(scanner.all_hosts())} hosts with open ports...')
        print()

        for host in scanner.all_hosts():
            output[host] = {}
            print(f'IP {host}')
            print('=====================')

            if len(scanner[host].all_protocols()) == 0:
                print('\tNO OPEN PORTS FOUND...')
            else:
                for proto in scanner[host].all_protocols():
                    output[host][proto] = {}

                    print(f'\t{proto.upper()}:')
                    for port in scanner[host][proto]:
                        port_info = scanner[host][proto][port]
                        output[host][proto][port] = f"{port_info['name']} {port_info['product']} {port_info['version']}"
                        print(
                            f"\t\t{port}:\t{output[host][proto][port]}")
            print()
            print('---------------------')
            print()

        return output

    except nmap.PortScannerError as e:
        print(f'An error occurred during the scan: {e}')
        sys.exit(1)


def submit_data(data):
    try:
        response = requests.post(POST_ENDPOINT, data=data)
        print(f'Sending data to url {POST_ENDPOINT}...\t\t[OK]')
    except requests.exceptions.RequestException as e:
        print(f'Sending data to url {POST_ENDPOINT}...\t\t[FAIL]')


def save_as_json(data):
    try:
        with open('output.json', 'w') as f:
            json.dump(data, f, indent=4)
        print('Generating output.json file...\t\t[OK]')
    except Exception as e:
        print('Generating output.json file...\t\t[FAIL]')
        print(f'An error occurred while saving data: {e}')


def get_bits_netmask(netmask):
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])


def main():
    # Check if -h or --help option is present
    if '-h' in sys.argv or '--help' in sys.argv:
        print('Usage: python open_ports.py -i INTERFACE_NAME')
        print('Options:')
        print('  -i, --interface INTERFACE_NAME   Specify the name of the network interface to scan ports on')
        sys.exit()

    # Check if interface argument is present
    if '-i' in sys.argv:
        interface_index = sys.argv.index('-i')
    elif '--interface' in sys.argv:
        interface_index = sys.argv.index('--interface')
    else:
        print('Error: no interface argument provided.')
        sys.exit(1)

    # Get the interface name from the command line argument
    interface_name = sys.argv[interface_index + 1]

    try:
        socket.if_nametoindex(interface_name)
    except OSError:
        print(
            f'Error: the network interface "{interface_name}" does not exist.')
        sys.exit()

    output = scan_ports(interface_name)
    submit_data(output)
    save_as_json(output)
    print()
    print('Done.')


if __name__ == '__main__':
    main()
