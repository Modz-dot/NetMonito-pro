

from flask import Flask, render_template, jsonify, request
from scanner import CompletNetworkScanner
import threading
import time
from datetime import datetime

app = Flask(__name__)

# Donnees globales
network_data = {
    'active_hosts': [],
    'offline_hosts': [],
    'new_devices': [],
    'last_scan': None,
    'scan_info': {},
    'alerts': [],
    'statistics': {},
    'network_summary': {}
}

# Scanner
scanner = CompletNetworkScanner("192.168.1.0/24", max_workers=10)

# Etat du scan
scan_status = {
    'is_scanning': False,
    'progress': 0
}

def scan_background():
    """Scan automatique en arriere-plan"""
    global network_data, scan_status
    
    while True:
        try:
            scan_status['is_scanning'] = True
            scan_status['progress'] = 0
            
            print("\n" + "="*60)
            print(" SCAN AUTOMATIQUE DEMARRE")
            print("="*60)
            
            # Scanner le reseau
            scan_status['progress'] = 30
            result = scanner.get_full_network_info()
            
            scan_status['progress'] = 80
            
            # Mettre a jour les donnees
            network_data['active_hosts'] = result['active_hosts']
            network_data['offline_hosts'] = result['offline_hosts']
            network_data['new_devices'] = result['new_devices']
            network_data['scan_info'] = result['scan_info']
            network_data['alerts'] = result['alerts']
            network_data['last_scan'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Statistiques
            network_data['statistics'] = scanner.get_statistics()
            network_data['network_summary'] = scanner.get_network_summary(result['active_hosts'])
            
            scan_status['progress'] = 100
            
            print(f"✓ Scan termine: {len(result['active_hosts'])} actives, {len(result['offline_hosts'])} hors ligne")
            print(f"✓ Nouvelles machines: {len(result['new_devices'])}")
            print(f"✓ Alertes: {len(result['alerts'])}")
            print("="*60 + "\n")
            
        except Exception as e:
            print(f" Erreur scan: {e}")
        finally:
            scan_status['is_scanning'] = False
            scan_status['progress'] = 0
        
        # Attendre 60 secondes
        time.sleep(60)

@app.route('/')
def index():
    """Page principale"""
    return render_template('dashboard.html')

@app.route('/api/network-data')
def get_network_data():
    """API: Toutes les donnees"""
    return jsonify(network_data)

@app.route('/api/active-hosts')
def get_active_hosts():
    """API: Machines actives uniquement"""
    return jsonify({
        'hosts': network_data['active_hosts'],
        'count': len(network_data['active_hosts'])
    })

@app.route('/api/offline-hosts')
def get_offline_hosts():
    """API: Machines hors ligne"""
    return jsonify({
        'hosts': network_data['offline_hosts'],
        'count': len(network_data['offline_hosts'])
    })

@app.route('/api/alerts')
def get_alerts():
    """API: Alertes"""
    return jsonify({
        'alerts': network_data['alerts'],
        'count': len(network_data['alerts'])
    })

@app.route('/api/statistics')
def get_statistics():
    """API: Statistiques"""
    return jsonify(network_data['statistics'])

@app.route('/api/network-summary')
def get_network_summary():
    """API: Resume du reseau"""
    return jsonify(network_data['network_summary'])

@app.route('/api/scan-now')
def scan_now():
    """API: Lancer un scan immediat"""
    try:
        if scan_status['is_scanning']:
            return jsonify({
                'status': 'error',
                'message': 'Un scan est deja en cours'
            })
        
        print("\n SCAN MANUEL DEMARRE\n")
        
        result = scanner.get_full_network_info()
        
        network_data['active_hosts'] = result['active_hosts']
        network_data['offline_hosts'] = result['offline_hosts']
        network_data['new_devices'] = result['new_devices']
        network_data['scan_info'] = result['scan_info']
        network_data['alerts'] = result['alerts']
        network_data['last_scan'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        network_data['statistics'] = scanner.get_statistics()
        network_data['network_summary'] = scanner.get_network_summary(result['active_hosts'])
        
        return jsonify({
            'status': 'success',
            'data': network_data
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/api/scan-status')
def get_scan_status():
    """API: Statut du scan en cours"""
    return jsonify(scan_status)

@app.route('/api/host/<ip>')
def get_host_details(ip):
    """API: Details d'un hote specifique"""
    # Chercher dans actives
    host = next((h for h in network_data['active_hosts'] if h['ip'] == ip), None)
    
    # Si pas trouve, chercher dans offline
    if not host:
        host = next((h for h in network_data['offline_hosts'] if h['ip'] == ip), None)
    
    if host:
        return jsonify(host)
    return jsonify({'error': 'Host not found'}), 404

@app.route('/api/clear-alerts')
def clear_alerts():
    """API: Effacer les alertes"""
    scanner.alerts = []
    network_data['alerts'] = []
    return jsonify({'status': 'success', 'message': 'Alertes effacees'})

if __name__ == '__main__':
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║                                                        ║
    ║                 ⚡ NETMONITO PRO ⚡                   ║
    ║                                                        ║
    ║     Advanced Network Monitoring & Security System      ║
    ║                                                        ║
    ╚════════════════════════════════════════════════════════╝
    
       FONCTIONNALITES:
    ✅ Scan parallele haute performance
    ✅ Detection machines actives/inactives
    ✅ Analyse de securite en temps reel
    ✅ Systeme d'alertes intelligent
    ✅ Historique et statistiques
    ✅ Detection de nouvelles machines
    ✅ Identification ports dangereux
    ✅ Dashboard moderne et responsive
    
     Serveur: http://0.0.0.0:5000
     Auto-scan: Toutes les 60 secondes
     
    
    >>> Appuyez sur Ctrl+C pour arreter <<<
    """)
    
    # Lancer le thread de scan automatique
    scan_thread = threading.Thread(target=scan_background, daemon=True)
    scan_thread.start()
    
    # Lancer le serveur
    app.run(host='0.0.0.0', port=5000, debug=False)