# dnsspoofer
A simple DNS server that allows you to spoof lookups

## Usage
Spoof lookups of example.com and example.org, any other domain will be resolved as it normally would

    sudo ./dnsspoofer.py -s example.com 127.0.0.1 -s example.org 192.168.1.42

Spoof all domains to a specific IP

    sudo ./dnsspoofer.py -a 127.0.0.1

If both `-s` and `-a` switches are present, domains specified with `-s` will take precedence over the IP specified with `-a` 
