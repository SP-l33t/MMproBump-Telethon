from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_ignore_empty=True)

    API_ID: int = None
    API_HASH: str = None
    GLOBAL_CONFIG_PATH: str = "TG_FARM"

    FARM_TIME: int = 21600                # 6 hours
    TAPS_COUNT: list[int] = [100000, 500000]
    MOON_BONUS: int = 1000000
    BUY_BOOST: bool = True
    AUTO_TASK: bool = True
    CLAIM_MOON: bool = True
    DEFAULT_BOOST: str = "x5"
    BOOSTERS: dict = {
        "x2": 4000000,
        "x3": 30000000,
        "x5": 200000000
    }

    RANDOM_DELAY_IN_RUN: int = 30
    REF_ID: str = ""

    SESSIONS_PER_PROXY: int = 1
    USE_PROXY_FROM_FILE: bool = True
    USE_PROXY_CHAIN: bool = False

    DEVICE_PARAMS: bool = False

    DEBUG_LOGGING: bool = False


settings = Settings()


