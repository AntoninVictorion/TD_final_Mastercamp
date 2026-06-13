import os
import json
from extraction_rss import extraire_tous_les_bulletins
from extraction_cve import extraire_toutes_les_cves

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DIR_MITRE  = os.path.join(BASE_DIR, "data", "mitre")
DIR_FIRST  = os.path.join(BASE_DIR, "data", "first")

def charger_json_local(dossier: str, cve_id: str) -> dict:
    chemin = os.path.join(dossier, cve_id)
    if not os.path.exists(chemin):
        return {}
    with open(chemin, "r", encoding="utf-8") as f:
        return json.load(f)
    

def enrichir_mitre(cve_id: str) -> dict:
    data = charger_json_local(DIR_MITRE, cve_id)
    if not data:
        return {
            "description": None, "cvss_score": None,
            "cvss_severity": None, "cwe_id": None,
            "cwe_desc": None, "vendor": None,
            "produit": None, "versions_affectees": None,
        }

    cna = data.get("containers", {}).get("cna", {})

    # Description
    descriptions = cna.get("descriptions", [])
    description = descriptions[0].get("value") if descriptions else None

    # Score CVSS : cherche dans cna d'abord, puis dans chaque conteneur adp
    cvss_score, cvss_severity = None, None

    # Tous les conteneurs possibles : cna + liste adp
    adp_list = data.get("containers", {}).get("adp", [])
    conteneurs = [cna] + adp_list

    for conteneur in conteneurs:
        for metric in conteneur.get("metrics", []):
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                if key in metric:
                    cvss_score    = metric[key].get("baseScore")
                    cvss_severity = metric[key].get("baseSeverity")
                    break
            if cvss_score:
                break
        if cvss_score:
            break

    # CWE : cherche dans cna puis adp
    cwe_id, cwe_desc = None, None
    for conteneur in conteneurs:
        problem_types = conteneur.get("problemTypes", [])
        if problem_types:
            descs = problem_types[0].get("descriptions", [])
            if descs:
                cwe_id   = descs[0].get("cweId")
                cwe_desc = descs[0].get("description")
                # Ignore les "n/a"
                if cwe_id == "n/a":
                    cwe_id = None
                if cwe_desc == "n/a":
                    cwe_desc = None
                if cwe_id:
                    break

    # Produits affectés
    vendors, produits, versions = [], [], []
    for prod in cna.get("affected", []):
        v = prod.get("vendor", "")
        p = prod.get("product", "")
        if v != "n/a":
            vendors.append(v)
        if p != "n/a":
            produits.append(p)
        vers = [v["version"] for v in prod.get("versions", [])
                if v.get("status") == "affected"]
        versions.extend(vers)

    return {
        "description"       : description,
        "cvss_score"        : cvss_score,
        "cvss_severity"     : cvss_severity,
        "cwe_id"            : cwe_id,
        "cwe_desc"          : cwe_desc,
        "vendor"            : ", ".join(vendors) if vendors else None,
        "produit"           : ", ".join(produits) if produits else None,
        "versions_affectees": ", ".join(versions) if versions else None,
    }

def enrichir_epss(cve_id: str) -> dict:
    data= charger_json_local(DIR_FIRST, cve_id)
    if not data:
        return {"epss_score": None, "epss_percentile": None}

    epss_data = data.get("data", [])
    if epss_data:
        return {
            "epss_score"      : float(epss_data[0].get("epss", 0)),
            "epss_percentile" : float(epss_data[0].get("percentile", 0)),
        }
    return {"epss_score": None, "epss_percentile": None}

def enrichir_toutes_les_paires(paires: list[dict]) -> list[dict]:
    resultats = []
    cves_vues = {}

    for i, paire in enumerate(paires):
        cve_id = paire["cve_id"]

        if cve_id not in cves_vues:
            mitre = enrichir_mitre(cve_id)
            epss  = enrichir_epss(cve_id)
            cves_vues[cve_id] = {**mitre, **epss}

        resultats.append({**paire, **cves_vues[cve_id]})

        if (i + 1) % 10000 == 0:
            print(f"  [{i+1}/{len(paires)}] enrichies...")

    print(f"[Etape 3] {len(resultats)} lignes enrichies")
    return resultats

if __name__ == "__main__":
    bulletins = extraire_tous_les_bulletins()
    paires    = extraire_toutes_les_cves(bulletins)
    enrichies = enrichir_toutes_les_paires(paires)

    # Aperçu
    for ligne in enrichies[:2]:
        print("-" * 60)
        for k, v in ligne.items():
            print(f"{k:20}: {v}")