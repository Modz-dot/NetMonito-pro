
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


## """Fonction pour scanner le réseau en arrière-plan"""
def scan_background():
    
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





## Routes (Endpoints)(api)
## """Page principale du dashboard"""
@app.route('/')
def index():
    return render_template('dashboard.html')


## """API pour récupérer les données du réseau"""
@app.route('/api/network-data')
def get_network_data():
    return jsonify(network_data)


## """API pour lancer un scan immédiat"""
@app.route('/api/scan-now')
def scan_now():
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
    
    
    ### Lancer le serveur Flask
    print("Démarrage du serveur sur http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)