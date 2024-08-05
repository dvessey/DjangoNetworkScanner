from django.http import JsonResponse
from django.http import HttpResponse
from inventory.forms import ScanForm
from django.shortcuts import render, redirect
import json
import nmap

# Create your views here.
def index(request):


    return render(request, 'inventory/home.html')

def scan_input(request):
    if request.method == 'POST':
        form = ScanForm(request.POST)

        if form.is_valid():
            ip = form.cleaned_data['ip']
            
    else:
        form = ScanForm()

    return render(request, 'inventory/scan.html', {'form': form})



def scan(request):

    scanner = nmap.PortScanner()

    # Target IP or hostname
    target = request.POST['ip']
    print("Scanning against target: {}".format(target))

    # Nmap flags
    # -sS = TCP SYN scan (default scan)
    # -sU = UDP scan [SLOW!]
    # -O = OS detection
    # -p- = Scan all ports (1-65535) [SLOW!]
    #flags = "-sS -sU -O -p-"
    flags = "-sS -O -p-"

    # Run the scan
    scanner.scan(target, arguments=flags, sudo=True)

    total_devices = 0

    inventory = {}

    # Print the results of the scan
    for host in scanner.all_hosts():
        total_devices += 1
        print("Host: ", host)
        print("State: ", scanner[host].state())
   
        inventory[host] = {'hostname': 'Not Found', 'state': scanner[host].state(), 'ports': {} }

        if 'osmatch' in scanner[host]:
            for  osmatch in scanner[host]['osmatch']:
                print("Host Operating System: {}".format(osmatch['name']))
           
                if 'osclass' in osmatch:
                    for osclass in osmatch['osclass']:
                        print("Operating System Type: {}".format(osclass['type']))
                        print("Operating System Vendor: {}".format(osclass['vendor']))
                        print("Operating System Family: {}".format(osclass['osfamily']))
                        print("Operating System Generation: {}".format(osclass['osgen']))
                        print("Operating System Detection Accuracy: {}".format(osclass['accuracy']))
                inventory[host] = {'hostname': osmatch['name'], 'state': scanner[host].state(), 'type': osclass['type'], 'ports': {} }
            
        for proto in scanner[host].all_protocols():
            print("Protocol: ", proto)
            ports = scanner[host][proto].keys()
            for port in ports:
                print("Port: ", port, "State: ", scanner[host][proto][port]['state'])
                inventory[host]['ports'][port] = scanner[host][proto][port]['state']

    print("Total Devices Scanned: ", total_devices)

    print(inventory)

    json_data = json.dumps(inventory, indent=4)

    with open("hosts.json", "w") as outfile:
        outfile.write(json_data)

    outfile.closed

    return redirect('scan_results')
    



def scan_results(request):
    with open("hosts.json", "r") as f:
        parsed_data = json.load(f) 
    f.closed

    return JsonResponse(parsed_data)