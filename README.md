[![Static Badge](https://img.shields.io/badge/Telegram-Bot%20Link-Link?style=for-the-badge&logo=Telegram&logoColor=white&logoSize=auto&color=blue)](https://t.me/MMproBump_bot?start=ref_525256526)

## Recommendation before use

# 🔥🔥 Use PYTHON 3.10 🔥🔥

> 🇷 🇺 README in russian available [here](README-RU.md)

## Features  
|                 Feature                 | Supported |
|:---------------------------------------:|:---------:|
|             Multithreading              |     ✅     |
|        Proxy binding to session         |     ✅     |
|              Auto-farming               |     ✅     |
|                Auto-taps                |     ✅     |
|  Collect bonus in every farming cycle   |     ✅     |
|        Auto-tasks (twitter only)        |     ✅     |
|               Auto-boost                |     ✅     |
|               Auto-daily                |     ✅     |
| Supports telethon AND pyrogram .session |     ✅     |

_Script searches for session files in the following folders:_
* /sessions
* /sessions/pyrogram
* /session/telethon


## [Settings](https://github.com/SP-l33t/MMproBump-Telethon/blob/master/.env-example/)
|         Settings          |                                                                                                                  Description                                                                                                                  |
|:-------------------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|   **API_ID / API_HASH**   |                                                                                  Platform data from which to run the Telegram session (by default - android)                                                                                  |
|  **GLOBAL_CONFIG_PATH**   | Specifies the global path for accounts_config, proxies, sessions. <br/>Specify an absolute path or use an environment variable (default environment variable: **TG_FARM**) <br/>If no environment variable exists, uses the script directory. |
|       **FIX_CERT**        |                                                                                           Try to fix  SSLCertVerificationError ( True / **False** )                                                                                           |
|      **TAPS_COUNT**       |                                                                                  How much clicks bot will get in farm cycle (by default - [100000, 500000])                                                                                   |
|      **CLAIM_MOON**       |                                                                                                 Collecting a farm bonus  (by default - True)                                                                                                  |
|      **MOON_BONUS**       |                                                                                                    Moon-Bonus count (by default - 1000000)                                                                                                    |
|       **BUY_BOOST**       |                                                                                                      Buying a boost (by default - True)                                                                                                       |
|     **DEFAULT_BOOST**     |                                                                                                Boost type ("x2"/"x3"/"x5") (by default - "x5")                                                                                                |
|       **AUTO_TASK**       |                                                                                                  Auto tasks (Twitter only) (default - True)                                                                                                   |
|  **SESSION_START_DELAY**  |                                                                      Random seconds delay for each session to start from 1 to this value (default : **30**, means 1..30)                                                                      |
|        **REF_ID**         |                                                                Will allow you to automatically referral your alts to main (default - None, please write here your telegram id)                                                                |
|  **SESSIONS_PER_PROXY**   |                                                                                            Amount of sessions, that can share same proxy ( **1** )                                                                                            |
|  **USE_PROXY_FROM_FILE**  |                                                                                Whether to use a proxy from the bot/config/proxies.txt file (**True** / False)                                                                                 |
| **DISABLE_PROXY_REPLACE** |                                                                      Disable automatic checking and replacement of non-working proxies before startup (True / **False**)                                                                      |
|     **DEVICE_PARAMS**     |                                                                          Enter device settings to make the telegram session look more realistic  (True / **False**)                                                                           |
|     **DEBUG_LOGGING**     |                                                                                     Whether to log error's tracebacks to /logs folder (True / **False**)                                                                                      |

## Quick Start 📚

To fast install libraries and run bot - open run.bat on Windows or run.sh on Linux

## Prerequisites
Before you begin, make sure you have the following installed:
- [Python](https://www.python.org/downloads/) **version 3.10**

## Obtaining API Keys
1. Go to my.telegram.org and log in using your phone number.
2. Select "API development tools" and fill out the form to register a new application.
3. Record the API_ID and API_HASH provided after registering your application in the .env file.

## Installation
You can download the [**repository**](https://github.com/SP-l33t/MMproBump-Telethon) by cloning it to your system and installing the necessary dependencies:
```shell
git clone https://github.com/SP-l33t/MMproBump-Telethon.git
cd MMproBump-Telethon
```

Then you can do automatic installation by typing:

Windows:
```shell
run.bat
```

Linux:
```shell
run.sh
```

# Linux manual installation
```shell
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
cp .env-example .env
nano .env  # Here you must specify your API_ID and API_HASH, the rest is taken by default
python3 main.py
```

You can also use arguments for quick start, for example:
```shell
~/MMproBump-Telethon >>> python3 main.py --action (1/2)
# Or
~/MMproBump-Telethon >>> python3 main.py -a (1/2)

# 1 - Run clicker
# 2 - Creates a session
```

# Windows manual installation
```shell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env-example .env
# Here you must specify your API_ID and API_HASH, the rest is taken by default
python main.py
```

You can also use arguments for quick start, for example:
```shell
~/MMproBump-Telethon >>> python main.py --action (1/2)
# Or
~/MMproBump-Telethon >>> python main.py -a (1/2)

# 1 - Run clicker
# 2 - Creates a session
```

### Contacts

For support or questions, you can contact me

[![Static Badge](https://img.shields.io/badge/Telegram-Channel-Link?style=for-the-badge&logo=Telegram&logoColor=white&logoSize=auto&color=blue)](https://t.me/desforge_crypto)