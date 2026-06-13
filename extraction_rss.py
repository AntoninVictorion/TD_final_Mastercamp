"""
Etape 1 : Extraction des flux RSS
"""


import os
import json
from datetime import datetime

# Les chemins vers les dossiers de données
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) #__permet de remonter vers la racine du dossier
DIR_ALERTES = os.path.join(BASE_DIR, "data", "alertes")
DIR_AVIS = os.path.join(BASE_DIR, "data", "Avis")

"""
Chargement des fichiers json et transforme en dictionnaire
et récupération et formatage des dates + gestions de potentiels erreurs 
"""
def charger_json(chemin_fichier : str) -> dict:
    with open(chemin_fichier, "r", encoding="utf-8") as f:
        return json.load(f)

def extraire_date_publication(revisions : list) -> str :
    if not revisions:
        return "Inconnue"
    try:
        premiere_date = revisions[0]["revision_date"]
        dt = datetime.fromisoformat(premiere_date)
        return dt.strftime("%Y-%m-%d")
    except (KeyError, ValueError):
        return "Inconnue"

"""
Lire les bulletins, extraire les informations importantes et les ranger proprement dans un dict
- get permet de recuperer une cle dans un dictionnaire
- on recupere a la fin un dictionnaire propre sous le format suivant :
    {
   "id": "...",
   "type": "...",
   "title": "...",
   "summary": "...",
   "date": "...",
   "link": "https://...",
   "risks": [...],
   "cves": [...]
}
"""


def extraire_bulletin(bulletin_id :str, type_bulletin : str, dossier : str) -> dict:
    chemin = os.path.join(dossier, bulletin_id)
    data = charger_json(chemin)

    date_pub = extraire_date_publication(data.get("revisions", [])) # appel de la fonction au dessus

    base_url = "https://www.cert.ssi.gouv.fr"
    if type_bulletin == "Alerte":
        lien = f"{base_url}/alerte/{bulletin_id}/"
    else:
        lien = f"{base_url}/avis/{bulletin_id}/"

    risks = [r["description"] for r in data.get("risks", []) if "description" in r]
    cves = data.get("cves", [])

    return {
        "id"     :  data.get("reference", bulletin_id),
        "type"   :  type_bulletin,
        "title"  :  data.get("title", "Sans titre"),
        "summary":  data.get("summary", "")[:300],
        "date"   :  date_pub,
        "link"   :  lien,
        "risks"  :  risks,
        "cves"   :  cves,
    }


"""
- La fonction du dessu traite un bulletin, tandis que celle du dessous en faisant appel à la fonction du dessus traite tous
les bulletins, alertes et avis + gestion des erreurs 
"""

def extraire_tous_les_bulletins() -> list[dict]:
    bulletins = []

    ids_alertes = sorted(os.listdir(DIR_ALERTES))
    print(f"[Etape 1] {len(ids_alertes)} alertes trouvees")

    for bulletin_id in ids_alertes:
        try:
            b = extraire_bulletin(bulletin_id, "Alerte", DIR_ALERTES)
            bulletins.append(b)
        except Exception as e:
            print(f"Erreur sur {bulletin_id} : {e}")

    ids_avis = sorted(os.listdir(DIR_AVIS))
    print(f"[Etape 1] {len(ids_avis)} avis trouvees")

    for bulletin_id in ids_avis:
        try:
            b = extraire_bulletin(bulletin_id, "Avis", DIR_AVIS)
            bulletins.append(b)
        except Exception as e:
            print(f"Erreur sur {bulletin_id} : {e}")

    print(f"[Etape 1] {len(bulletins)} bulletins extraits au total \n")
    return bulletins

if __name__ == "__main__":
    bulletins = extraire_tous_les_bulletins()

    for b in bulletins[:3]:
        print("-" * 60)
        print(f"ID        :  {b['id']}")
        print(f"Type      :  {b['type']}")
        print(f"Title     :  {b['title']}")
        print(f"Titre     :  {b['title']}")
        print(f"Date      :  {b['date']}")
        print(f"CVE       :  {[c['name']for c in b['cves']]}")

