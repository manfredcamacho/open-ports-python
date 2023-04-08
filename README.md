# Open Ports Scanner

This is a Python script that scans a network for hosts with open ports using the nmap library, and outputs the results in JSON format. It also allows the user to submit the results to a remote server via HTTP POST request.

## Usage

To use the script, run:

```console
foo@bar:~$ sudo python open_ports.py -i <INTERFACE_NAME>
```

where <INTERFACE_NAME> is the name of the network interface you want to scan ports on.

## Options

`-h, --help: Display the help message.`

`-i, --interface: Specify the name of the network interface to scan ports on.`

## Dependencies

- Python 3.x
- nmap library (python-nmap)
- netifaces library (python-netifaces)
- requests library (python-requests)

## Output

The output is a JSON file named output.json that contains the results of the scan. The JSON file has the following format:

```json
{
  "<host>": {
    "<protocol_a>": {
      "<port>": "<banner>"
    },
    "<protocol_b>": {
      "<port>": "<banner>"
    }
  }
}
```

<host>: the IP address of the host.
<protocol>: the protocol used by the open port (tcp or udp).
<port>: the number of the open port.
<banner>: the banner returned by the open port.

## Example console output
