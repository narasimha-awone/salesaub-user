from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Database
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/saleshub"
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_echo: bool = False

    # JWT – verification (public key; used by saleshub_core on every request)
    jwt_public_key: str = ""
    jwt_algorithm: str = "RS256"
    jwt_audience: str | None = None

    # JWT – minting (private key; used by select-campaign to issue access tokens)
    jwt_private_key: str = ""

    # Temporary token key pair (login → campaign-selection handoff)
    temporary_token_private_key: str = ""
    temporary_token_public_key: str = ""

    # App
    app_title: str = "SalesHub User Service"
    app_version: str = "0.1.0"
    debug: bool = False

    # Webex Interact SMS gateway (phone OTP)
    webex_interact_auth_key: str = ""
    webex_interact_sender_id: str = ""
    webex_interact_api_url: str = "https://apis.webexinteract.com/v3/messaging"
    webex_interact_timeout: float = 10.0


settings = Settings()
