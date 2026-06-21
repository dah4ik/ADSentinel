from api.server import FINDINGS_CACHE


def update_cache(findings):

    FINDINGS_CACHE.clear()

    for finding in findings:

        FINDINGS_CACHE.append(
            finding.to_dict()
        )