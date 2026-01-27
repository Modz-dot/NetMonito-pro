# Python-Monito

#Scanner Réseau (serveur)

import nmap
import socket

class NetworkScanner:
    def __init__(self, network_range="192.168.1.0/24"):
        self.network_range = network_range
        self.nm = nmap.PortScanner()
    
    def scan_network(self):
        """Scanne le réseau et retourne les machines actives"""
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
    
    def scan_ports(self, ip, ports="20-1000"):
        """Scanne les ports d'une machine spécifique"""
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
    
    def get_hostname(self, ip):
        """Récupère le nom d'hôte d'une IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Inconnu"
    
    def get_full_network_info(self):
        """Récupère toutes les informations du réseau"""
        hosts = self.scan_network()
        
        for host in hosts:
            host['ports'] = self.scan_ports(host['ip'])
        
        return hosts



#########################################

#Application Flask avec Dashboard

from flask import Flask, render_template, jsonify
from scanner import NetworkScanner
import threading
import time

app = Flask(__name__)

# Données globales pour stocker les informations du réseau
network_data = {
    'hosts': [],
    'last_scan': None
}

# Scanner réseau
scanner = NetworkScanner("192.168.1.0/24")

def scan_background():
    """Fonction pour scanner le réseau en arrière-plan"""
    global network_data
    while True:
        try:
            print("Démarrage du scan réseau...")
            hosts = scanner.get_full_network_info()
            network_data['hosts'] = hosts
            network_data['last_scan'] = time.strftime('%Y-%m-%d %H:%M:%S')
            print(f"Scan terminé. {len(hosts)} machines trouvées.")
        except Exception as e:
            print(f"Erreur pendant le scan: {e}")
        
        # Attendre 60 secondes avant le prochain scan
        time.sleep(60)

@app.route('/')
def index():
    """Page principale du dashboard"""
    return render_template('dashboard.html')

@app.route('/api/network-data')
def get_network_data():
    """API pour récupérer les données du réseau"""
    return jsonify(network_data)

@app.route('/api/scan-now')
def scan_now():
    """API pour lancer un scan immédiat"""
    try:
        hosts = scanner.get_full_network_info()
        network_data['hosts'] = hosts
        network_data['last_scan'] = time.strftime('%Y-%m-%d %H:%M:%S')
        return jsonify({'status': 'success', 'data': network_data})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    # Lancer le scan en arrière-plan
    scan_thread = threading.Thread(target=scan_background, daemon=True)
    scan_thread.start()
    
    # Lancer le serveur Flask
    print("Démarrage du serveur sur http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)




###############################

#Dashboard HTML (Interface Web)

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Réseau LAN</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .stats {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .stat-item {
            background: #f0f0f0;
            padding: 10px 15px;
            border-radius: 5px;
        }
        
        .scan-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
        }
        
        .scan-btn:hover {
            background: #5568d3;
        }
        
        .hosts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
        }
        
        .host-card {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .host-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }
        
        .host-ip {
            font-size: 20px;
            font-weight: bold;
            color: #333;
        }
        
        .status-badge {
            background: #10b981;
            color: white;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 12px;
        }
        
        .host-info {
            margin-bottom: 15px;
        }
        
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        
        .info-label {
            color: #666;
            font-size: 14px;
        }
        
        .info-value {
            color: #333;
            font-weight: 500;
        }
        
        .ports-section {
            margin-top: 15px;
        }
        
        .ports-title {
            font-weight: bold;
            color: #333;
            margin-bottom: 10px;
        }
        
        .port-item {
            background: #f9fafb;
            padding: 8px 12px;
            margin-bottom: 5px;
            border-radius: 5px;
            display: flex;
            justify-content: space-between;
        }
        
        .port-number {
            color: #667eea;
            font-weight: bold;
        }
        
        .port-service {
            color: #666;
            font-size: 14px;
        }
        
        .loading {
            text-align: center;
            color: white;
            font-size: 18px;
            padding: 40px;
        }
        
        .no-hosts {
            background: white;
            padding: 40px;
            border-radius: 10px;
            text-align: center;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 Dashboard Réseau LAN</h1>
            <div class="stats">
                <div class="stat-item">
                    <strong>Machines actives:</strong> <span id="active-count">0</span>
                </div>
                <div class="stat-item">
                    <strong>Dernier scan:</strong> <span id="last-scan">-</span>
                </div>
                <button class="scan-btn" onclick="scanNow()">🔄 Scanner maintenant</button>
            </div>
        </div>
        
        <div id="hosts-container" class="loading">
            Chargement des données réseau...
        </div>
    </div>

    <script>
        // Fonction pour charger les données du réseau
        function loadNetworkData() {
            fetch('/api/network-data')
                .then(response => response.json())
                .then(data => {
                    displayHosts(data);
                })
                .catch(error => {
                    console.error('Erreur:', error);
                    document.getElementById('hosts-container').innerHTML = 
                        '<div class="no-hosts">Erreur de chargement des données</div>';
                });
        }
        
        // Fonction pour afficher les machines
        function displayHosts(data) {
            const container = document.getElementById('hosts-container');
            const activeCount = document.getElementById('active-count');
            const lastScan = document.getElementById('last-scan');
            
            // Mettre à jour les statistiques
            activeCount.textContent = data.hosts.length;
            lastScan.textContent = data.last_scan || 'Jamais';
            
            // Si aucune machine trouvée
            if (data.hosts.length === 0) {
                container.innerHTML = '<div class="no-hosts">Aucune machine détectée sur le réseau</div>';
                return;
            }
            
            // Créer les cartes pour chaque machine
            let html = '<div class="hosts-grid">';
            
            data.hosts.forEach(host => {
                html += `
                    <div class="host-card">
                        <div class="host-header">
                            <div class="host-ip">${host.ip}</div>
                            <div class="status-badge">${host.status}</div>
                        </div>
                        
                        <div class="host-info">
                            <div class="info-row">
                                <span class="info-label">Nom d'hôte:</span>
                                <span class="info-value">${host.hostname}</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">Ports ouverts:</span>
                                <span class="info-value">${host.ports.length}</span>
                            </div>
                        </div>
                        
                        ${host.ports.length > 0 ? `
                            <div class="ports-section">
                                <div class="ports-title">📡 Ports ouverts:</div>
                                ${host.ports.map(port => `
                                    <div class="port-item">
                                        <span class="port-number">Port ${port.port}</span>
                                        <span class="port-service">${port.service}</span>
                                    </div>
                                `).join('')}
                            </div>
                        ` : ''}
                    </div>
                `;
            });
            
            html += '</div>';
            container.innerHTML = html;
        }
        
        // Fonction pour lancer un scan immédiat
        function scanNow() {
            document.getElementById('hosts-container').innerHTML = 
                '<div class="loading">Scan en cours...</div>';
            
            fetch('/api/scan-now')
                .then(response => response.json())
                .then(result => {
                    if (result.status === 'success') {
                        displayHosts(result.data);
                    } else {
                        alert('Erreur: ' + result.message);
                    }
                })
                .catch(error => {
                    console.error('Erreur:', error);
                    alert('Erreur lors du scan');
                });
        }
        
        // Charger les données au démarrage
        loadNetworkData();
        
        // Actualiser automatiquement toutes les 30 secondes
        setInterval(loadNetworkData, 30000);
    </script>
</body>
</html>






        
