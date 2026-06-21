from ldap3 import Server
from ldap3 import Connection
from ldap3 import ALL
from ldap3 import SUBTREE

from config.settings import settings
from core.logger import logger


class LDAPClient:

    def __init__(self):
        self.server = None
        self.connection = None

    def connect(self):

        logger.info(
            f"Connecting to LDAP server {settings.LDAP_SERVER}"
        )

        self.server = Server(
            settings.LDAP_SERVER,
            get_info=ALL
        )

        self.connection = Connection(
            self.server,
            user=settings.LDAP_USERNAME,
            password=settings.LDAP_PASSWORD,
            auto_bind=True
        )

        logger.info("LDAP authentication successful")

        return self.connection

    def disconnect(self):

        if self.connection:
            self.connection.unbind()

            logger.info(
                "LDAP connection closed"
            )

    def get_domain_policy(self):
        logger.info("Collecting domain password and lockout policy")

        self.connection.search(
            search_base=settings.BASE_DN,
            search_filter="(objectClass=domainDNS)",
            search_scope=SUBTREE,
            attributes=[
                "minPwdLength",
                "maxPwdAge",
                "pwdHistoryLength",
                "lockoutThreshold",
                "lockoutDuration"
            ]
        )

        if not self.connection.entries:
            logger.warning("Domain policy was not found")
            return None

        logger.info("Domain policy collected successfully")

        return self.connection.entries[0]


    def get_users(self):

        logger.info(
            "Collecting Active Directory users"
        )

        self.connection.search(
            search_base=settings.BASE_DN,
            search_filter="(&(objectCategory=person)(objectClass=user))",
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName",
                "displayName",
                "distinguishedName",
                "userAccountControl",
                "lastLogonTimestamp",
                "pwdLastSet",
                "memberOf",
                "description",
                "servicePrincipalName"
            ]
        )

        logger.info(
            f"Collected {len(self.connection.entries)} users"
        )

        return self.connection.entries

    def get_computers(self):

        self.connection.search(
            search_base=settings.BASE_DN,
            search_filter="(objectClass=computer)",
            search_scope=SUBTREE,
            attributes=[
                "name",
                "operatingSystem",
                "operatingSystemVersion",
                "userAccountControl",
                "lastLogonTimestamp"
            ]
        )
        return self.connection.entries

    def get_gpos(self):
        logger.info("Collecting Group Policy Objects")

        gpo_dn = f"CN=Policies,CN=System,{settings.BASE_DN}"

        self.connection.search(
            search_base=gpo_dn,
            search_filter="(objectClass=groupPolicyContainer)",
            search_scope=SUBTREE,
            attributes=[
                "displayName",
                "gPCFileSysPath",
                "description"
            ]
        )

        logger.info(
            f"Collected {len(self.connection.entries)} GPO objects"
        )

        return self.connection.entries