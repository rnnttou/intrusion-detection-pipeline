"""Correspondance famille d'attaque -> technique MITRE ATT&CK (Enterprise).

Faite à la main, au niveau de la famille : elle indique à l'analyste où chercher, elle ne
remplace pas sa qualification. Une anomalie sans classe connue n'a pas de technique.
"""

MITRE = {
    "DoS": {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
    "DDoS": {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "PortScan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "BruteForce": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "WebAttack": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "Bot": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
}


def technique(family: str):
    return MITRE.get(family)


def url(technique_id: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique_id}/"
