import streamlit as st

import requests
from stix2 import MemoryStore, Filter
import pandas as pd

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
            Filter('x_mitre_is_subtechnique', '=', False)
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


def get_mitigations(thesrc):
    return thesrc.query(['type', '=', 'course-of-action'])

def remove_revoked_deprecated(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False or x.get("revoked", False) is False,
            stix_objects
        )
    )


src = get_data_from_branch("enterprise-attack")

subtechniques = get_techniques_or_subtechniques(src, "both")
subtechniques = remove_revoked_deprecated(subtechniques)

mitigations = get_mitigations(src)

#st.write(subtechniques)
df = pd.DataFrame(mitigations)
st.dataframe(df)