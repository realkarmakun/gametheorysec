import requests
from stix2 import MemoryStore, Filter
from stix2.v21 import AttackPattern


def get_data_from_branch(domain):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or
    'ics-attack'. Branch should typically be master."""
    stix_json = requests.get(
        f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])


def get_techniques_or_subtechniques(thesrc, include="both"):
    """Filter Techniques or Sub-Techniques from ATT&CK Enterprise Domain.
    include argument has three options: "techniques", "subtechniques", or "both"
    depending on the intended behavior."""
    if include == "techniques":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', False),
            Filter('revoked', '=', False)
        ])
    elif include == "subtechniques":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', True)
        ])
    elif include == "both":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern')
        ])
    else:
        raise RuntimeError("Unknown option %s!" % include)

    return query_results


def get_mitigation_by_id(thesrc, mitigation_id):
    return thesrc.query([
        Filter('type', '=', 'course-of-action'),
        Filter('id', '=', mitigation_id)
    ])


def get_mitigations_by_ids(thesrc, migitation_ids):
    return thesrc.query([
        Filter('type', '=', 'course-of-action'),
        Filter('id', 'in', migitation_ids)
    ])


def get_techniques_by_ids(thesrc, techniques_ids):
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', techniques_ids)
    ])


def get_tactics_by_ids(thesrc, tactics_ids):
    return thesrc.query([
        Filter('type', '=', 'x-mitre-tactic'),
        Filter('id', 'in', tactics_ids)
    ])


def get_techniques_by_tactics(thesrc, tactics):
    # double checking the kill chain is MITRE ATT&CK
    # note: kill_chain_name is different for other domains:
    #    - enterprise: "mitre-attack"
    #    - mobile: "mitre-mobile-attack"
    #    - ics: "mitre-ics-attack"
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('x_mitre_is_subtechnique', '=', False),
        Filter('kill_chain_phases.phase_name', 'in', tactics),
        Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack')
    ])


def get_mitigations(thesrc):
    return thesrc.query([
        Filter('type', '=', 'course-of-action'),
        # Filter('x_mitre_deprecated', '=', True)
    ])


def remove_revoked_deprecated(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )


def get_tactics(thesrc):
    return thesrc.query([
        Filter('type', '=', 'x-mitre-tactic')
    ])


def debug_dataframe_attack_pattern(df):
    """
    Utility function for debugging DataFrames. Streamlit doesn't handle some of the STIX objects when showing data,
    so we preprocess it to remove incompatible rows. We lose data when running this, so use it only when need to
    inspect dataframe in streamlit UI.
    """
    return df.loc[:, ~df.columns.isin(['kill_chain_phases', 'external_references'])]
