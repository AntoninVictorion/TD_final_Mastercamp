# consolidation.py
import pandas as pd
import os
from extraction_rss import extraire_tous_les_bulletins
from extraction_cve import extraire_toutes_les_cves
from enrichissement import enrichir_toutes_les_paires

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def construire_dataframe(lignes: list[dict]) -> pd.DataFrame:

    df = pd.DataFrame(lignes)

    # --- Renommage des colonnes ---
    df = df.rename(columns={
        "bulletin_id"       : "ID_ANSSI",
        "type"              : "Type",
        "titre"             : "Titre",
        "date"              : "Date",
        "lien"              : "Lien",
        "cve_id"            : "CVE",
        "description"       : "Description",
        "cvss_score"        : "CVSS_Score",
        "cvss_severity"     : "CVSS_Severity",
        "cwe_id"            : "CWE_ID",
        "cwe_desc"          : "CWE_Description",
        "vendor"            : "Vendor",
        "produit"           : "Produit",
        "versions_affectees": "Versions",
        "epss_score"        : "EPSS_Score",
        "epss_percentile"   : "EPSS_Percentile",
    })

    # --- Typage des colonnes ---
    df["Date"]           = pd.to_datetime(df["Date"], errors="coerce")
    df["CVSS_Score"]     = pd.to_numeric(df["CVSS_Score"], errors="coerce")
    df["EPSS_Score"]     = pd.to_numeric(df["EPSS_Score"], errors="coerce")
    df["EPSS_Percentile"]= pd.to_numeric(df["EPSS_Percentile"], errors="coerce")

    # --- Nettoyage des "n/a" résiduels ---
    df = df.replace("n/a", None)

    # --- Suppression des doublons exacts ---
    df = df.drop_duplicates(subset=["ID_ANSSI", "CVE"])

    # --- Réordonnancement des colonnes ---
    colonnes = [
        "ID_ANSSI", "Type", "Titre", "Date", "CVE",
        "CVSS_Score", "CVSS_Severity", "CWE_ID", "CWE_Description",
        "EPSS_Score", "EPSS_Percentile",
        "Vendor", "Produit", "Versions",
        "Description", "Lien",
    ]
    df = df[colonnes]

    return df


def sauvegarder_csv(df: pd.DataFrame, nom_fichier: str = "data_anssi.csv"):
    chemin = os.path.join(BASE_DIR, nom_fichier)
    df.to_csv(chemin, index=False, encoding="utf-8-sig")
    print(f"[Etape 4] CSV sauvegardé : {chemin}")


def afficher_resume(df: pd.DataFrame):
    print("\n" + "=" * 60)
    print("RÉSUMÉ ÉTAPE 4 — DataFrame consolidé")
    print("=" * 60)
    print(f"  Lignes totales         : {len(df)}")
    print(f"  CVE uniques            : {df['CVE'].nunique()}")
    print(f"  Bulletins uniques      : {df['ID_ANSSI'].nunique()}")
    print(f"  Alertes / Avis         : {(df['Type']=='Alerte').sum()} / {(df['Type']=='Avis').sum()}")
    print(f"  Avec CVSS score        : {df['CVSS_Score'].notna().sum()}")
    print(f"  Avec EPSS score        : {df['EPSS_Score'].notna().sum()}")
    print(f"  CVSS Score moyen       : {df['CVSS_Score'].mean():.2f}")
    print(f"  EPSS Score moyen       : {df['EPSS_Score'].mean():.4f}")
    print("=" * 60)
    print("\nAperçu des 5 premières lignes :")
    print(df[["ID_ANSSI", "Type", "CVE", "CVSS_Score",
              "CVSS_Severity", "EPSS_Score", "Vendor"]].head())
    print("\nTypes des colonnes :")
    print(df.dtypes)


if __name__ == "__main__":
    bulletins = extraire_tous_les_bulletins()
    paires    = extraire_toutes_les_cves(bulletins)
    enrichies = enrichir_toutes_les_paires(paires)

    df = construire_dataframe(enrichies)
    afficher_resume(df)
    sauvegarder_csv(df)

