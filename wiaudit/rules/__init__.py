"""Audit rules. Each rule function yields Finding objects."""

RULES = {
    # identity / Entra side
    "WIA001": "GitHub trust uses a mutable, name-based subject",
    "WIA002": "Flexible credential uses wildcards without binding repository_id",
    "WIA003": "Identity trusts pull_request workflows",
    "WIA004": "Federated identity holds broad privileged role",
    "WIA005": "Non-default audience on federated credential",
    "WIA006": "Trust points to a GitHub repository that no longer exists",
    "WIA007": "Trust points to a renamed GitHub repository",
    "WIA008": "Identity close to the federated credential limit",
    "WIA009": "Federated credential from an unrecognized issuer",
    "WIA010": "Trust to a GitHub repository outside your organizations",
    "WIA011": "GitHub owners trusted in this tenant (review list)",
    # workflow side
    "WIA101": "pull_request_target workflow can request OIDC tokens",
    "WIA102": "id-token: write granted to every job in the workflow",
    "WIA103": "azure/login uses a client secret instead of OIDC",
    "WIA104": "azure/login OIDC step without id-token: write",
    # doctor
    "WIA201": "No federated credential matches the subject this job will send",
}
