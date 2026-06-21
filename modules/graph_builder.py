from datetime import datetime
import json
import os

from config.settings import settings
from core.logger import logger


class GraphBuilder:

    def __init__(self, users, ldap_client):
        self.users = users
        self.ldap_client = ldap_client
        self.nodes = []
        self.edges = []
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def build(self):
        logger.info("Building BloodHound Lite graph")

        self.add_domain_node()
        self.add_user_nodes()
        self.add_group_edges()
        self.add_computer_nodes()

        logger.info(
            f"Graph built with {len(self.nodes)} nodes and {len(self.edges)} edges"
        )

        return {
            "nodes": self.nodes,
            "edges": self.edges
        }

    def add_domain_node(self):
        domain_name = settings.BASE_DN.replace("DC=", "").replace(",", ".")

        self.nodes.append(
            {
                "id": domain_name,
                "label": domain_name,
                "type": "Domain"
            }
        )

    def add_user_nodes(self):
        for user in self.users:
            username = self.safe_get(user, "sAMAccountName")
            distinguished_name = self.safe_get(user, "distinguishedName")

            if not username:
                continue

            self.nodes.append(
                {
                    "id": username,
                    "label": username,
                    "type": "User",
                    "dn": distinguished_name
                }
            )

    def add_group_edges(self):
        for user in self.users:
            username = self.safe_get(user, "sAMAccountName")
            member_of = self.safe_get(user, "memberOf")

            if not username or not member_of:
                continue

            for group_dn in member_of:
                group_name = self.extract_cn(str(group_dn))

                if not group_name:
                    continue

                self.add_group_node(group_name)

                self.edges.append(
                    {
                        "from": username,
                        "to": group_name,
                        "relationship": "MemberOf"
                    }
                )

    def add_computer_nodes(self):
        try:
            computers = self.ldap_client.get_computers()
        except Exception as e:
            logger.warning(
                f"Could not collect computers for graph: {e}"
            )
            return

        domain_name = settings.BASE_DN.replace("DC=", "").replace(",", ".")

        for computer in computers:
            computer_name = self.safe_get(computer, "name")

            if not computer_name:
                continue

            self.nodes.append(
                {
                    "id": computer_name,
                    "label": computer_name,
                    "type": "Computer"
                }
            )

            self.edges.append(
                {
                    "from": computer_name,
                    "to": domain_name,
                    "relationship": "JoinedTo"
                }
            )

    def add_group_node(self, group_name):
        for node in self.nodes:
            if node["id"] == group_name:
                return

        self.nodes.append(
            {
                "id": group_name,
                "label": group_name,
                "type": "Group"
            }
        )

    def extract_cn(self, distinguished_name):
        try:
            first_part = distinguished_name.split(",")[0]

            if first_part.startswith("CN="):
                return first_part.replace("CN=", "")

            return None

        except Exception:
            return None

    def safe_get(self, obj, attribute):
        try:
            value = obj[attribute].value

            if value is None:
                return None

            return value

        except Exception:
            return None

    def save_json(self):
        os.makedirs(
            settings.OUTPUT_JSON_DIR,
            exist_ok=True
        )

        graph = self.build()

        file_path = (
            f"{settings.OUTPUT_JSON_DIR}/"
            f"adsentinel_graph_{self.timestamp}.json"
        )

        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(
                graph,
                file,
                indent=4,
                ensure_ascii=False
            )

        logger.info(
            f"Graph JSON saved: {file_path}"
        )

        return file_path