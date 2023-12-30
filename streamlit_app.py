import streamlit as st

import requests
from stix2 import MemoryStore, Filter
from stix2.v21 import AttackPattern
import numpy as np
import matplotlib.pyplot as plt
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


def get_mitigations(thesrc):
    return thesrc.query([
        Filter('type', '=', 'course-of-action'),
        Filter('x_mitre_deprecated', '=', False)
    ])


def get_tactics(thesrc):
    return thesrc.query([
        Filter('type', '=', 'x-mitre-tactic')
    ])

src = get_data_from_branch("enterprise-attack")

techniques = get_techniques_or_subtechniques(src, include="techniques")

st.write("### Данные атак Mitre ATT&CK")

techniques_data = [dict(t) for t in techniques]

techniques_df = pd.DataFrame(techniques_data)
st.dataframe(techniques_df.loc[:, ~techniques_df.columns.isin(['kill_chain_phases', 'external_references'])])

mitigations = get_mitigations(src)

st.write("### Данные митигаций Mitre ATT&CK")

mitigations_data = [dict(m) for m in mitigations]

mitigations_df = pd.DataFrame(mitigations)
st.dataframe(mitigations_df.loc[:, ~mitigations_df.columns.isin(['external_references'])])

tactics = get_tactics(src)

st.write("### Данные тактик Mitre ATT&CK")

tactics_data = [ta for ta in tactics]

tactics_df = pd.DataFrame(tactics)
st.dataframe(tactics_df)

st.write("### Матрица")

matrix = np.random.rand(3, 3)

fig, ax = plt.subplots()

ax.grid()

plt.matshow(matrix, fig, cmap='cividis')

st.pyplot(fig)
