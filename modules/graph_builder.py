from datetime import datetime
import json
import os

from jinja2 import Environment
from jinja2 import FileSystemLoader

from config.settings import settings
from core.logger import logger


class GraphBuilder:

    NODE_COLORS = {
        "Domain": "#dc2626",
        "User": "#2563eb",
        "Group": "#16a34a",
        "Computer": "#ea580c"
    }

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
        domain_name = self.get_domain_name()

        self.add_node(
            node_id=domain_name,
            label=domain_name,
            node_type="Domain"
        )

    def add_user_nodes(self):
        for user in self.users:
            username = self.safe_get(user, "sAMAccountName")
            distinguished_name = self.safe_get(user, "distinguishedName")

            if not username:
                continue

            self.add_node(
                node_id=username,
                label=username,
                node_type="User",
                extra={
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

                self.add_node(
                    node_id=group_name,
                    label=group_name,
                    node_type="Group"
                )

                self.add_edge(
                    source=username,
                    target=group_name,
                    relationship="MemberOf"
                )

    def add_computer_nodes(self):
        try:
            computers = self.ldap_client.get_computers()
        except Exception as e:
            logger.warning(
                f"Could not collect computers for graph: {e}"
            )
            return

        domain_name = self.get_domain_name()

        for computer in computers:
            computer_name = self.safe_get(computer, "name")
            operating_system = self.safe_get(computer, "operatingSystem")

            if not computer_name:
                continue

            self.add_node(
                node_id=computer_name,
                label=computer_name,
                node_type="Computer",
                extra={
                    "operating_system": operating_system
                }
            )

            self.add_edge(
                source=computer_name,
                target=domain_name,
                relationship="JoinedTo"
            )

    def add_node(
            self,
            node_id,
            label,
            node_type,
            extra=None
    ):
        for node in self.nodes:
            if node["id"] == node_id:
                return

        node = {
            "id": node_id,
            "label": label,
            "type": node_type,
            "color": self.NODE_COLORS.get(node_type, "#6b7280")
        }

        if extra:
            node.update(extra)

        self.nodes.append(node)

    def add_edge(
            self,
            source,
            target,
            relationship
    ):
        edge = {
            "from": source,
            "to": target,
            "label": relationship,
            "relationship": relationship
        }

        if edge not in self.edges:
            self.edges.append(edge)

    def extract_cn(self, distinguished_name):
        try:
            first_part = distinguished_name.split(",")[0]

            if first_part.startswith("CN="):
                return first_part.replace("CN=", "")

            return None

        except Exception:
            return None

    def get_domain_name(self):
        return settings.BASE_DN.replace("DC=", "").replace(",", ".")

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

    def save_html(self):
        os.makedirs(
            settings.OUTPUT_HTML_DIR,
            exist_ok=True
        )

        graph = self.build()

        file_path = (
            f"{settings.OUTPUT_HTML_DIR}/"
            f"adsentinel_graph_{self.timestamp}.html"
        )

        env = Environment(
            loader=FileSystemLoader("reports/templates")
        )

        template = env.get_template("graph.html")

        html_content = template.render(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            nodes=json.dumps(graph["nodes"], ensure_ascii=False),
            edges=json.dumps(graph["edges"], ensure_ascii=False)
        )

        with open(file_path, "w", encoding="utf-8") as file:
            file.write(html_content)

        logger.info(
            f"Graph HTML saved: {file_path}"
        )

        return file_path