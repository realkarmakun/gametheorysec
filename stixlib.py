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


def get_related(thesrc, src_type, rel_type, target_type, reverse=False):
    """build relationship mappings
       params:
         thesrc: MemoryStore to build relationship lookups for
         src_type: source type for the relationships, e.g "attack-pattern"
         rel_type: relationship type for the relationships, e.g "uses"
         target_type: target type for the relationship, e.g "intrusion-set"
         reverse: build reverse mapping of target to source
    """

    relationships = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type),
        Filter('revoked', '=', False),
    ])

    # See section below on "Removing revoked and deprecated objects"
    relationships = remove_revoked_deprecated(relationships)

    # stix_id => [ { relationship, related_object_id } for each related object ]
    id_to_related = {}

    # build the dict
    for relationship in relationships:
        if src_type in relationship.source_ref and target_type in relationship.target_ref:
            if (relationship.source_ref in id_to_related and not reverse) or (
                    relationship.target_ref in id_to_related and reverse):
                # append to existing entry
                if not reverse:
                    id_to_related[relationship.source_ref].append({
                        "relationship": relationship,
                        "id": relationship.target_ref
                    })
                else:
                    id_to_related[relationship.target_ref].append({
                        "relationship": relationship,
                        "id": relationship.source_ref
                    })
            else:
                # create a new entry
                if not reverse:
                    id_to_related[relationship.source_ref] = [{
                        "relationship": relationship,
                        "id": relationship.target_ref
                    }]
                else:
                    id_to_related[relationship.target_ref] = [{
                        "relationship": relationship,
                        "id": relationship.source_ref
                    }]
    # all objects of relevant type
    if not reverse:
        targets = thesrc.query([
            Filter('type', '=', target_type),
            Filter('revoked', '=', False)
        ])
    else:
        targets = thesrc.query([
            Filter('type', '=', src_type),
            Filter('revoked', '=', False)
        ])

    # build lookup of stixID to stix object
    id_to_target = {}
    for target in targets:
        id_to_target[target.id] = target

    # build final output mappings
    output = {}
    for stix_id in id_to_related:
        value = []
        for related in id_to_related[stix_id]:
            if not related["id"] in id_to_target:
                continue  # targeting a revoked object
            value.append({
                "object": id_to_target[related["id"]],
                "relationship": related["relationship"]
            })
        output[stix_id] = value
    return output


# technique:mitigation
def mitigation_mitigates_techniques(thesrc):
    """return mitigation_id => {technique, relationship} for each technique mitigated by the mitigation."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=False)


def technique_mitigated_by_mitigations(thesrc):
    """return technique_id => {mitigation, relationship} for each mitigation of the technique."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=True)


def is_technique_mitigated_by_mitigations_specified(relations, technique_id, mitigations):
    result = False
    if technique_id in relations.keys():
        for relation in relations[technique_id]:
            if relation.get("object").get("id") in mitigations:
                result = True
    return result


def does_mitigation_mitigates_technique(relations, technique_id, mitigation_id):
    result = False
    if mitigation_id in relations.keys():
        for relation in relations[mitigation_id]:
            if relation.get("object").get("id") == technique_id:
                result = True
    return result


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
