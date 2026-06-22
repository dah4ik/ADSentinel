import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    LDAP_SERVER = os.getenv("LDAP_SERVER")
    LDAP_USERNAME = os.getenv("LDAP_USERNAME")
    LDAP_PASSWORD = os.getenv("LDAP_PASSWORD")
    BASE_DN = os.getenv("BASE_DN")

    INACTIVE_DAYS = int(os.getenv("INACTIVE_DAYS", 90))
    OLD_PASSWORD_DAYS = int(os.getenv("OLD_PASSWORD_DAYS", 180))

    OUTPUT_HTML_DIR = "output/html"
    OUTPUT_CSV_DIR = "output/csv"
    OUTPUT_JSON_DIR = "output/json"

    API_USERNAME = os.getenv("API_USERNAME", "admin")
    API_PASSWORD = os.getenv("API_PASSWORD", "admin123")

    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-secret-key")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", 60))


settings = Settings()