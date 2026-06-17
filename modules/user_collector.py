from core.logger import logger


class UserCollector:

    def __init__(self, ldap_client):
        self.ldap_client = ldap_client

    def collect(self):

        users = self.ldap_client.get_users()

        logger.info(
            f"UserCollector received {len(users)} users"
        )

        return users