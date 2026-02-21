

import nmap
import socket
import json
import os
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import hashlib

class CompletNetworkScanner:
    """Scanner reseau complet avec toutes les fonctionnalites"""
    
    def __init__(self, network_range="192.168.1.0/24", max_workers=10):
        self.network_range = network_range
        self.max_workers = max_workers
        self.nm = nmap.PortScanner()
        
        # Fichiers de donnees
        self.history_file = "network_history.json"
        self.stats_file = "network_stats.json"
        
        # Charger l'historique
        self.known_hosts = self.load_history()
        self.scan_history = self.load_stats()
        
        # Configuration du logging
        self.setup_logging()
        
        # Ports dangereux
        self.dangerous_ports = {
            21: {'name': 'FTP', 'risk': 'high', 'reason': 'Protocole non securise'},
            23: {'name': 'Telnet', 'risk': 'critical', 'reason': 'Aucun chiffrement'},
            69: {'name': 'TFTP', 'risk': 'high', 'reason': 'Protocole trivial'},
            135: {'name': 'RPC', 'risk': 'high', 'reason': 'Vulnerable'},
            139: {'name': 'NetBIOS', 'risk': 'medium', 'reason': 'Exposition SMB'},
            445: {'name': 'SMB', 'risk': 'high', 'reason': 'Cible ransomware'},
            3389: {'name': 'RDP', 'risk': 'high', 'reason': 'Acces distant'},
            5900: {'name': 'VNC', 'risk': 'medium', 'reason': 'Controle distant'},
            3306: {'name': 'MySQL', 'risk': 'medium', 'reason': 'Base exposee'},
            5432: {'name': 'PostgreSQL', 'risk': 'medium', 'reason': 'Base exposee'},
            6379: {'name': 'Redis', 'risk': 'high', 'reason': 'Cache sans auth'},
            27017: {'name': 'MongoDB', 'risk': 'high', 'reason': 'NoSQL exposee'}
        }
        
        # Alertes
        self.alerts = []
    
    def setup_logging(self):
        """Configure le logging"""
        logging.basicConfig(
            filename='network_scanner.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('NetworkScanner')
    
    def load_history(self):
        """Charge l'historique"""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_history(self):
        """Sauvegarde l'historique"""
        with open(self.history_file, 'w') as f:
            json.dump(self.known_hosts, f, indent=2)
    
    def load_stats(self):
        """Charge les statistiques"""
        if os.path.exists(self.stats_file):
            try:
                with open(self.stats_file, 'r') as f:
                    data = json.load(f)
                    # Garder seulement les 50 derniers scans
                    if len(data.get('scans', [])) > 50:
                        data['scans'] = data['scans'][-50:]
                    return data
            except:
                return {'scans': [], 'total_scans': 0}
        return {'scans': [], 'total_scans': 0}
    
    def save_stats(self):
        """Sauvegarde les statistiques"""
        with open(self.stats_file, 'w') as f:
            json.dump(self.scan_history, f, indent=2)
    
    def scan_network_fast(self):
        """Scan rapide pour trouver les machines actives"""
        self.logger.info(f"Scan rapide: {self.network_range}")
        
        try:
            self.nm.scan(hosts=self.network_range, arguments='-sn -T4')
            active_ips = [host for host in self.nm.all_hosts() if self.nm[host].state() == 'up']
            return active_ips
        except Exception as e:
            self.logger.error(f"Erreur scan reseau: {e}")
            return []
    
    def scan_single_host(self, ip):
        """Scanne une seule machine avec tous les details"""
        try:
            nm_local = nmap.PortScanner()
            
            # Scan des ports
            nm_local.scan(ip, arguments='-T4 --top-ports 100 -sV')
            
            hostname = self.get_hostname(ip)
            ports = []
            
            if ip in nm_local.all_hosts():
                for proto in nm_local[ip].all_protocols():
                    for port in nm_local[ip][proto].keys():
                        port_info = nm_local[ip][proto][port]
                        if port_info['state'] == 'open':
                            ports.append({
                                'port': port,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', '')
                            })
            
            return {
                'ip': ip,
                'hostname': hostname,
                'ports': ports,
                'status': 'active'
            }
        except Exception as e:
            self.logger.error(f"Erreur scan {ip}: {e}")
            return {
                'ip': ip,
                'hostname': 'Error',
                'ports': [],
                'status': 'error'
            }
    
    def get_hostname(self, ip):
        """Recupere le hostname"""
        try:
            socket.setdefaulttimeout(1)
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"
    
    def analyze_security(self, host):
        """Analyse la securite d'un hote"""
        score = 100
        risks = []
        recommendations = []
        
        for port_info in host.get('ports', []):
            port = port_info['port']
            
            if port in self.dangerous_ports:
                danger = self.dangerous_ports[port]
                risk_points = {'critical': 30, 'high': 20, 'medium': 10}.get(danger['risk'], 5)
                score -= risk_points
                
                risks.append({
                    'port': port,
                    'service': danger['name'],
                    'level': danger['risk'],
                    'reason': danger['reason']
                })
                
                recommendations.append(
                    f"Fermer port {port} ({danger['name']}) ou securiser"
                )
        
        # Bonus SSH
        if any(p['port'] == 22 for p in host.get('ports', [])):
            score += 5
        
        # Penalite trop de ports
        open_ports = len(host.get('ports', []))
        if open_ports > 10:
            score -= (open_ports - 10) * 2
            recommendations.append(f"Reduire ports ouverts ({open_ports})")
        
        score = max(0, min(100, score))
        
        if score >= 80:
            level, color = 'excellent', '#00ff88'
        elif score >= 60:
            level, color = 'good', '#ffa500'
        elif score >= 40:
            level, color = 'moderate', '#ff6b6b'
        else:
            level, color = 'poor', '#ff0000'
        
        return {
            'score': score,
            'level': level,
            'color': color,
            'risks': risks,
            'recommendations': recommendations
        }
    
    def detect_changes(self, current_hosts):
        """Detecte les changements: nouvelles machines, machines disparues"""
        current_time = datetime.now().isoformat()
        current_ips = {h['ip'] for h in current_hosts}
        known_ips = set(self.known_hosts.keys())
        
        # Nouvelles machines
        new_ips = current_ips - known_ips
        new_devices = [h for h in current_hosts if h['ip'] in new_ips]
        
        # Machines disparues
        offline_ips = known_ips - current_ips
        offline_devices = []
        
        for ip in offline_ips:
            old_info = self.known_hosts[ip]
            last_seen = old_info.get('last_seen', current_time)
            
            try:
                last_seen_dt = datetime.fromisoformat(last_seen)
                offline_duration = (datetime.now() - last_seen_dt).total_seconds()
                offline_hours = offline_duration / 3600
            except:
                offline_hours = 0
            
            offline_devices.append({
                'ip': ip,
                'hostname': old_info.get('hostname', 'Unknown'),
                'status': 'offline',
                'last_seen': last_seen,
                'offline_hours': round(offline_hours, 1),
                'ports': old_info.get('ports', [])
            })
        
        # Generer alertes
        for device in new_devices:
            self.create_alert(
                'NEW_DEVICE',
                f"Nouvelle machine: {device['ip']} ({device['hostname']})",
                'info'
            )
        
        for device in offline_devices:
            if device['offline_hours'] < 1:  # Recemment hors ligne
                self.create_alert(
                    'DEVICE_OFFLINE',
                    f"Machine hors ligne: {device['ip']} ({device['hostname']})",
                    'warning'
                )
        
        return new_devices, offline_devices
    
    def create_alert(self, alert_type, message, severity='info'):
        """Cree une alerte"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'message': message,
            'severity': severity
        }
        self.alerts.append(alert)
        self.logger.info(f"ALERT [{severity.upper()}] {message}")
    
    def get_full_network_info(self):
        """Scan complet avec toutes les fonctionnalites"""
        start_time = time.time()
        current_time = datetime.now().isoformat()
        
        self.logger.info("=== DEBUT SCAN COMPLET ===")
        
        # 1. Trouver machines actives
        active_ips = self.scan_network_fast()
        print(f"✓ {len(active_ips)} machines actives")
        
        # 2. Scanner en parallele
        active_hosts = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_single_host, ip): ip for ip in active_ips}
            
            for future in as_completed(futures):
                result = future.result()
                active_hosts.append(result)
                print(f"  ✓ {result['ip']} ({len(result['ports'])} ports)")
        
        # 3. Analyser securite
        for host in active_hosts:
            host['security'] = self.analyze_security(host)
            host['last_seen'] = current_time
            host['first_seen'] = self.known_hosts.get(host['ip'], {}).get('first_seen', current_time)
            
            # Alertes securite
            if host['security']['score'] < 40:
                self.create_alert(
                    'SECURITY_LOW',
                    f"Score securite bas: {host['ip']} ({host['security']['score']}/100)",
                    'critical'
                )
            
            for risk in host['security']['risks']:
                if risk['level'] == 'critical':
                    self.create_alert(
                        'CRITICAL_PORT',
                        f"Port critique: {host['ip']}:{risk['port']} ({risk['service']})",
                        'critical'
                    )
        
        # 4. Detecter changements
        new_devices, offline_devices = self.detect_changes(active_hosts)
        
        # 5. Mettre a jour historique
        for host in active_hosts:
            self.known_hosts[host['ip']] = host
        self.save_history()
        
        # 6. Statistiques
        duration = time.time() - start_time
        scan_record = {
            'timestamp': current_time,
            'duration': round(duration, 2),
            'active_hosts': len(active_hosts),
            'offline_hosts': len(offline_devices),
            'new_hosts': len(new_devices),
            'total_ports': sum(len(h['ports']) for h in active_hosts),
            'avg_security_score': round(
                sum(h['security']['score'] for h in active_hosts) / len(active_hosts)
                if active_hosts else 0, 1
            )
        }
        
        self.scan_history['scans'].append(scan_record)
        self.scan_history['total_scans'] = len(self.scan_history['scans'])
        self.save_stats()
        
        self.logger.info(f"=== SCAN TERMINE ({duration:.2f}s) ===")
        
        return {
            'active_hosts': active_hosts,
            'offline_hosts': offline_devices,
            'new_devices': new_devices,
            'scan_info': scan_record,
            'alerts': self.alerts[-20:]  # 20 dernieres alertes
        }
    
    def get_statistics(self):
        """Retourne les statistiques"""
        scans = self.scan_history.get('scans', [])
        
        if not scans:
            return {
                'total_scans': 0,
                'timeline': []
            }
        
        return {
            'total_scans': len(scans),
            'timeline': scans[-20:],
            'avg_active_hosts': round(
                sum(s['active_hosts'] for s in scans) / len(scans), 1
            ),
            'avg_scan_duration': round(
                sum(s['duration'] for s in scans) / len(scans), 2
            ),
            'total_alerts': len(self.alerts)
        }
    
    def get_network_summary(self, hosts):
        """Resume du reseau"""
        if not hosts:
            return {}
        
        return {
            'total_hosts': len(hosts),
            'total_ports': sum(len(h['ports']) for h in hosts),
            'avg_security_score': round(
                sum(h['security']['score'] for h in hosts) / len(hosts), 1
            ),
            'critical_hosts': len([h for h in hosts if h['security']['score'] < 40]),
            'secure_hosts': len([h for h in hosts if h['security']['score'] >= 80]),
            'hosts_with_risks': len([h for h in hosts if h['security']['risks']])
        }