
import nmap
import socket



class NetworkScanner:
    def __init__(self, network_range="192.168.1.0/24"):
        self.network_range = network_range
        self.nm = nmap.PortScanner()



    ### """Scanne le réseau et retourne les machines actives"""
    def scan_network(self):
        
        print(f"Scan du réseau {self.network_range}...")



        # Scan ping pour détecter les machines actives
        self.nm.scan(hosts=self.network_range, arguments='-sn')
        
        active_hosts = []
        for host in self.nm.all_hosts():
            if self.nm[host].state() == 'up':
                hostname = self.get_hostname(host)
                active_hosts.append({
                    'ip': host,
                    'hostname': hostname,
                    'status': 'active'
                })
        
        return active_hosts




    ### """Scanne les ports d'une machine spécifique"""
    def scan_ports(self, ip, ports="20-1000"):
        
        print(f"Scan des ports de {ip}...")
        
        try:
            self.nm.scan(ip, ports, arguments='-sV')
            open_ports = []
            
            if ip in self.nm.all_hosts():
                for proto in self.nm[ip].all_protocols():
                    ports_list = self.nm[ip][proto].keys()
                    for port in ports_list:
                        port_info = self.nm[ip][proto][port]
                        if port_info['state'] == 'open':
                            open_ports.append({
                                'port': port,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', '')
                            })
            
            return open_ports
        except Exception as e:
            print(f"Erreur lors du scan des ports: {e}")
            return []




    ### """Récupère le nom d'hôte d'une IP"""
    def get_hostname(self, ip):
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Inconnu"





    ### """Récupère toutes les informations du réseau"""
    def get_full_network_info(self):
        
        hosts = self.scan_network()
        
        for host in hosts:
            host['ports'] = self.scan_ports(host['ip'])
        
        return hosts