import re
from extraction_rss import extraire_tous_les_bulletins

def extraire_cves_bulletin(bulletin: dict) -> list[str]:
    cve_ids = set()

    for cve in bulletin.get("cves", []):
        nom = cve.get("name", "")
        if nom.startswith("CVE-"):
            cve_ids.add(nom)

    pattern = r"CVE-\d{4}-\d{4,7}"
    cve_ids.update(re.findall(pattern, bulletin.get("summary", "")))

    return list(cve_ids)

def extraire_toutes_les_cves(bulletins: list[dict]) -> list[dict]:

    resultats = []

    for bulletin in bulletins:
        cve_ids = extraire_cves_bulletin(bulletin)

        if not cve_ids:
            continue

        for cve_id in cve_ids:
            resultats.append({
                "bulletin_id": bulletin["id"],
                "type"         : bulletin["type"],
                "titre"        : bulletin["title"],
                "date"         : bulletin["date"],
                "lien"         : bulletin["link"],
                "cve_id"     : cve_id,
            })

    print(f"[Etape 2] {len(resultats)} praires (bulletin, CVE) extraites")
    return resultats

if __name__ == "__main__":
    bulletin = extraire_tous_les_bulletins()
    paires = extraire_toutes_les_cves(bulletin)

    nb_alertes = sum(1 for p in paires if p["type"] == "Alerte")
    nb_avis    = sum(1 for p in paires if p["type"] == "Avis")
    cves_uniques = len(set(p["cve_id"] for p in paires))

    print("=" * 60)
    print("RÉSUMÉ ÉTAPE 2 — Extraction des CVE")
    print("=" * 60)
    print(f"  Paires totales        : {len(paires)}")
    print(f"  Dont depuis alertes   : {nb_alertes}")
    print(f"  Dont depuis avis      : {nb_avis}")
    print(f"  CVE uniques           : {cves_uniques}")
    print("=" * 60)

    # Aperçu des 5 premières
    print("\nAperçu des 5 premières paires :")
    for p in paires[:5]:
        print(f"  [{p['type']:6}] {p['bulletin_id']} → {p['cve_id']}  ({p['date']})")