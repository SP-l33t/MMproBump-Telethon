import aiohttp
import asyncio
import hashlib
import os
import random
from urllib.parse import unquote
from aiocfscrape import CloudflareScraper
from aiohttp_proxy import ProxyConnector
from better_proxy import Proxy
from datetime import timedelta
from time import time

from opentele.tl import TelegramClient
from telethon.errors import *
from telethon.types import InputPeerUser
from telethon.functions import messages, contacts

from .headers import *
from bot.config import settings
from bot.utils import logger, log_error, proxy_utils, config_utils, AsyncInterProcessLock, CONFIG_PATH
from bot.exceptions import InvalidSession


def generate_time_hash():
    curr_time = str(time())[0:9] + '0'
    return hashlib.sha256(curr_time.encode()).hexdigest()


class Tapper:
    def __init__(self, tg_client: TelegramClient):
        self.session_name, _ = os.path.splitext(os.path.basename(tg_client.session.filename))
        self.tg_client = tg_client
        self.lock = AsyncInterProcessLock(
            os.path.join(os.path.dirname(CONFIG_PATH), 'lock_files',  f"{self.session_name}.lock"))
        self.headers = headers

        session_config = config_utils.get_session_config(self.session_name, CONFIG_PATH)

        if not all(key in session_config for key in ('api', 'user_agent')):
            logger.critical(self.log_message('CHECK accounts_config.json as it might be corrupted'))
            exit(-1)

        user_agent = session_config.get('user_agent')
        self.headers['user-agent'] = user_agent
        self.headers.update(**get_sec_ch_ua(user_agent))

        self.proxy = session_config.get('proxy')
        if self.proxy:
            proxy = Proxy.from_str(self.proxy)
            proxy_dict = proxy_utils.to_telethon_proxy(proxy)
            self.tg_client.set_proxy(proxy_dict)

        self._webview_data = None

    def log_message(self, message) -> str:
        return f"<ly>{self.session_name}</ly> | {message}"

    async def initialize_webview_data(self):
        if not self._webview_data:
            while True:
                try:
                    resolve_result = await self.tg_client(contacts.ResolveUsernameRequest(username='MMproBump_bot'))
                    user = resolve_result.users[0]
                    peer = InputPeerUser(user_id=user.id, access_hash=user.access_hash)
                    self._webview_data = {'peer': peer, 'bot': user.username}
                    break
                except FloodWaitError as fl:
                    fls = fl.seconds

                    logger.warning(self.log_message(f"FloodWait {fl}. Waiting {fls}s"))
                    await asyncio.sleep(fls + 3)

                except (UnauthorizedError, AuthKeyUnregisteredError):
                    raise InvalidSession(f"{self.session_name}: User is unauthorized")
                except (UserDeactivatedError, UserDeactivatedBanError, PhoneNumberBannedError):
                    raise InvalidSession(f"{self.session_name}: User is banned")

    async def get_tg_web_data(self) -> [str | None, str | None]:
        if self.proxy and not self.tg_client._proxy:
            logger.critical(self.log_message('Proxy found, but not passed to TelegramClient'))
            exit(-1)

        data = None, None
        async with self.lock:
            try:
                if not self.tg_client.is_connected():
                    await self.tg_client.connect()
                await self.initialize_webview_data()
                await asyncio.sleep(random.uniform(1, 2))

                ref_id = settings.REF_ID if random.randint(0, 100) <= 85 else "ref_525256526"

                start_state = False
                async for message in self.tg_client.iter_messages('MMproBump_bot'):
                    if r'/start' in message.text:
                        start_state = True
                        break
                await asyncio.sleep(random.uniform(0.5, 1))
                if not start_state:
                    await self.tg_client(messages.StartBotRequest(bot=self._webview_data.get('peer'),
                                                                  peer=self._webview_data.get('peer'),
                                                                  start_param=ref_id))
                await asyncio.sleep(random.uniform(1, 2))

                web_view = await self.tg_client(messages.RequestWebViewRequest(
                    **self._webview_data,
                    platform='android',
                    from_bot_menu=False,
                    url="https://mmbump.pro/",
                    start_param=ref_id
                ))

                auth_url = web_view.url
                tg_web_data = unquote(
                    string=unquote(
                        string=auth_url.split('tgWebAppData=', maxsplit=1)[1].split('&tgWebAppVersion', maxsplit=1)[0]))

                user_id = tg_web_data.split('"id":')[1].split(',"first_name"')[0]
                data = tg_web_data, user_id

            except InvalidSession:
                raise

            except Exception as error:
                log_error(self.log_message(f"Unknown error during Authorization: {type(error).__name__}"))
                await asyncio.sleep(delay=3)

            finally:
                if self.tg_client.is_connected():
                    await self.tg_client.disconnect()
                    await asyncio.sleep(15)

        return data

    async def login(self, http_client: aiohttp.ClientSession, tg_web_data: str, retry=0):
        try:
            response = await http_client.post('https://api.mmbump.pro/v1/loginJwt', json={'initData': tg_web_data})
            response.raise_for_status()

            response_json = await response.json()

            response_ver = await http_client.get('https://mmbump.pro/version.json')
            response_ver.raise_for_status()
            return response_json

        except Exception as error:
            log_error(self.log_message(f"Unknown error when Logining: {error}"))
            await asyncio.sleep(delay=3)
            retry = retry + 1
            logger.info(self.log_message(f"Attempt №{retry} to login"))
            if retry < 3:
                return await self.login(http_client, tg_web_data, retry)

    async def get_info_data(self, http_client: aiohttp.ClientSession):
        try:
            response = await http_client.post('https://api.mmbump.pro/v1/farming')
            response.raise_for_status()

            response_json = await response.json()
            return response_json

        except Exception as error:
            log_error(self.log_message(f"Unknown error when getting farming data: {error}"))
            await asyncio.sleep(delay=random.randint(3, 7))

    async def check_proxy(self, http_client: aiohttp.ClientSession) -> bool:
        proxy_conn = http_client.connector
        if proxy_conn and not hasattr(proxy_conn, '_proxy_host'):
            logger.info(self.log_message(f"Running Proxy-less"))
            return True
        try:
            response = await http_client.get(url='https://ifconfig.me/ip', timeout=aiohttp.ClientTimeout(15))
            logger.info(self.log_message(f"Proxy IP: {await response.text()}"))
            return True
        except Exception as error:
            proxy_url = f"{proxy_conn._proxy_type}://{proxy_conn._proxy_host}:{proxy_conn._proxy_port}"
            log_error(self.log_message(f"Proxy: {proxy_url} | Error: {type(error).__name__}"))
            return False

    async def refresh(self, http_client: aiohttp.ClientSession):
        try:
            response = await http_client.post('https://api.mmbump.pro/v1/auth/refresh')
            response.raise_for_status()

            response_json = await response.json()

            response_ver = await http_client.get('https://mmbump.pro/version.json')
            response_ver.raise_for_status()
            return response_json

        except Exception as error:
            log_error(self.log_message(f"Unknown error while refreshing auth: {error}"))
            await asyncio.sleep(delay=3)

    async def processing_tasks(self, http_client: aiohttp.ClientSession):
        try:
            hash_data = generate_time_hash()
            response = await http_client.post('https://api.mmbump.pro/v1/task-list', json={'hash': hash_data})
            response.raise_for_status()
            response_json = await response.json()

            tasks = response_json
            for task in tasks:
                if (task['status'] == 'possible' and task['is_active'] == 1 and
                        ((task['type'] == "twitter" or "Twitter" in task['name'])
                         or (task['type'] == "youtube" or "YouTube" in task['name']))):  # only Twitter & YouTube tasks

                    random_hash = generate_time_hash()
                    json_data = {
                        'id': task['id'],
                        'hash': random_hash
                    }
                    logger.info(self.log_message(f"Processing task: <y>{task['id']}</y>"))
                    complete_resp = await http_client.post('https://api.mmbump.pro/v1/task-list/complete',
                                                           json=json_data)
                    complete_resp.raise_for_status()
                    complete_json = await complete_resp.json()
                    task_json = complete_json['task']
                    if task_json['status'] == 'granted':
                        logger.success(self.log_message(f"Task <e>{task['name']}</e> - Completed | "
                                       f"Granted <c>{task['grant']}</c> | Balance: <e>{complete_json['balance']}</e>"))
                        await asyncio.sleep(delay=random.randint(3, 7))

        except Exception as error:
            log_error(self.log_message(f"Unknown error when completing tasks: {error}"))
            await asyncio.sleep(delay=3)

    async def claim_daily(self, http_client: aiohttp.ClientSession):
        try:
            response = await http_client.post('https://api.mmbump.pro/v1/grant-day/claim',
                                              json={'hash': generate_time_hash()})
            response.raise_for_status()
            response_json = await response.json()

            new_balance = response_json['balance']
            day_grant_day = response_json['day_grant_day']
            logger.success(self.log_message(
                f"Daily Claimed! | New Balance: <e>{new_balance}</e> | Day count: <g>{day_grant_day}</g>"))

        except Exception as error:
            log_error(self.log_message(f"Unknown error when Daily Claiming: {error}"))
            await asyncio.sleep(delay=3)

    async def reset_daily(self, http_client: aiohttp.ClientSession):
        try:
            response = await http_client.post('https://api.mmbump.pro/v1/grant-day/reset')
            response.raise_for_status()
            logger.info(self.log_message(f"Reset Daily Reward"))

        except Exception as error:
            log_error(self.log_message(f"Unknown error when resetting Daily Reward: {error}"))
            await asyncio.sleep(delay=3)

    async def start_farming(self, http_client: aiohttp.ClientSession, token_time: int):
        try:
            json_data = {
                'status': "inProgress",
                'hash': generate_time_hash()
            }
            response = await http_client.post('https://api.mmbump.pro/v1/farming/start', json=json_data)
            response.raise_for_status()
            response_json = await response.json()

            status = response_json['status']
            if status == "inProgress":
                logger.success(self.log_message(f"Start farming"))
                if settings.CLAIM_MOON:
                    moon_time = response_json['moon_time']
                    sleep_time = moon_time - time()
                    if sleep_time < time() - token_time:
                        logger.info(self.log_message(
                            f"Sleep <light-yellow>{int(sleep_time)}</light-yellow> seconds before moon claiming"))
                        await asyncio.sleep(delay=sleep_time)
                        await self.moon_claim(http_client=http_client)
            else:
                logger.warning(self.log_message(f"Can't start farming | Status: <r>{status}</r>"))

        except Exception as error:
            log_error(self.log_message(f"Unknown error when Start Farming: {error}"))
            await asyncio.sleep(delay=3)

    async def finish_farming(self, http_client: aiohttp.ClientSession, boost: str):
        try:
            taps = random.randint(settings.TAPS_COUNT[0], settings.TAPS_COUNT[1])
            if boost is not None:
                taps *= int(boost.split("x")[1])

            json_data = {
                'tapCount': taps,
                'hash': generate_time_hash()
            }
            response = await http_client.post('https://api.mmbump.pro/v1/farming/finish',
                                              json=json_data)
            response.raise_for_status()
            if response.content_length is None:
                logger.success(self.log_message(
                    f"Finished farming | Added taps: <light-yellow>{taps}</light-yellow>"))
                return True

            else:
                response_json = await response.json()
                new_balance = response_json['balance']
                session_json = response_json['session']
                added_amount = session_json['amount']
                taps = session_json['taps']
                logger.success(self.log_message(
                    f"Finished farming | Got <light-yellow>{added_amount + taps}</light-yellow> "
                    f"points | New balance: <e>{new_balance}</e>"))
            return True

        except Exception as error:
            log_error(self.log_message(f"Unknown error when Stop Farming: {error}"))
            await asyncio.sleep(delay=3)
            return False

    async def moon_claim(self, http_client: aiohttp.ClientSession, retry: int = 0):
        try:
            await asyncio.sleep(random.randint(3, 5))
            refresh_data = await self.refresh(http_client=http_client)

            if refresh_data:
                http_client.headers["Authorization"] = refresh_data["type"] + " " + refresh_data["access_token"]
            else:
                return

            random_hash = generate_time_hash()
            response = await http_client.post('https://api.mmbump.pro/v1/farming/moon-claim', json={'hash': random_hash})
            if response.status == 401 and retry < 3:
                logger.warning(self.log_message(f"UnAuthorized error when Moon Claiming. Attempt {retry}..."))
                retry += 1
                await self.moon_claim(http_client=http_client, retry=retry)
            else:
                response.raise_for_status()
                if response.content_length is None:
                    logger.success(self.log_message("Moon bonus claimed"))
                else:
                    response_json = await response.json()
                    new_balance = response_json['balance']
                    logger.success(self.log_message(f"Moon bonus claimed | Balance: <e>{new_balance}</e>"))

        except Exception as error:
            log_error(self.log_message(f"Unknown error when Moon Claiming: {error}"))
            await asyncio.sleep(delay=3)

    async def buy_boost(self, http_client: aiohttp.ClientSession, balance: int):
        try:
            boost_costs = settings.BOOSTERS[settings.DEFAULT_BOOST]
            if boost_costs > balance:
                logger.warning(self.log_message(f"Can't buy boost, not enough points | Balance: <e>{balance}</e> "
                               f"| Boost costs: <r>{boost_costs}</r>"))
                return
            response = await http_client.post('https://api.mmbump.pro/v1/product-list/buy',
                                              json={'id': settings.DEFAULT_BOOST})
            response.raise_for_status()
            response_json = await response.json()

            new_balance = response_json['balance']
            boost_id = response_json['id']
            logger.success(self.log_message(
                f"Bought boost <light-yellow>{boost_id}</light-yellow> | Balance: <e>{new_balance}</e>"))

        except Exception as error:
            log_error(self.log_message(f"Unknown error when Moon Claiming: {error}"))
            await asyncio.sleep(delay=3)

    async def run(self) -> None:
        random_delay = random.uniform(1, settings.RANDOM_DELAY_IN_RUN)
        logger.info(self.log_message(f"Bot will start in <ly>{int(random_delay)}s</ly>"))
        await asyncio.sleep(random_delay)

        access_token_created_time = 0
        tg_web_data = None

        next_claim_time = 0

        proxy_conn = {'connector': ProxyConnector.from_url(self.proxy)} if self.proxy else {}
        async with CloudflareScraper(headers=self.headers, timeout=aiohttp.ClientTimeout(60), **proxy_conn) as http_client:
            while True:
                if not await self.check_proxy(http_client=http_client):
                    logger.warning(self.log_message('Failed to connect to proxy server. Sleep 5 minutes.'))
                    await asyncio.sleep(300)
                    continue

                try:
                    token_live_time = random.randint(3500, 3600)
                    if time() - access_token_created_time >= token_live_time:
                        tg_web_data, user_id = await self.get_tg_web_data()

                        if not tg_web_data:
                            logger.warning(self.log_message('Failed to get webview URL'))
                            await asyncio.sleep(300)
                            continue

                        http_client.headers["User_auth:"] = user_id
                        login_data = await self.login(http_client=http_client, tg_web_data=tg_web_data)

                        if login_data:
                            http_client.headers["Authorization"] = f'{login_data["type"]} {login_data["access_token"]}'
                        else:
                            await asyncio.sleep(300)
                            continue

                        access_token_created_time = time()

                        info_data = await self.get_info_data(http_client=http_client)
                        balance = info_data['balance']
                        logger.info(self.log_message(f"Balance: <e>{balance}</e>"))
                        day_grant_first = info_data['day_grant_first']
                        day_grant_day = info_data['day_grant_day']
                        system_time = info_data['system_time']

                        if day_grant_first is None:
                            await self.claim_daily(http_client=http_client)
                        else:
                            next_claim_time = day_grant_first + timedelta(days=1).total_seconds() * day_grant_day
                            if next_claim_time < system_time:
                                # check if daily need to reset
                                if next_claim_time + timedelta(days=1).total_seconds() < system_time:
                                    await self.reset_daily(http_client=http_client)
                                    await asyncio.sleep(delay=3)

                                await self.claim_daily(http_client=http_client)

                        if settings.AUTO_TASK:
                            await asyncio.sleep(delay=random.randint(3, 5))
                            await self.processing_tasks(http_client=http_client)

                    await asyncio.sleep(delay=random.randint(3, 10))
                    info_data = await self.get_info_data(http_client=http_client)

                    # boost flow
                    if settings.BUY_BOOST:
                        if info_data['info'].get('boost') is None or info_data['info']['active_booster_finish_at'] < time():
                            await asyncio.sleep(delay=random.randint(3, 8))
                            await self.buy_boost(http_client=http_client, balance=info_data['balance'])

                    # farm flow
                    session = info_data['session']
                    status = session['status']

                    sleep_time = token_live_time
                    if status == "await":
                        await self.start_farming(http_client=http_client, token_time=access_token_created_time)

                    if status == "inProgress":
                        moon_time = session['moon_time']
                        delta_time = moon_time - time()
                        start_at = session['start_at']
                        finish_at = start_at + settings.FARM_TIME
                        time_left = finish_at - time()

                        if settings.CLAIM_MOON and delta_time > 0:
                            if delta_time < token_live_time + access_token_created_time - time():
                                logger.info(self.log_message(
                                    f"Sleep <light-yellow>{int(delta_time)}</light-yellow> seconds before moon claiming"))
                                await asyncio.sleep(delay=delta_time)
                                await self.moon_claim(http_client=http_client)
                            else:
                                logger.info(self.log_message(
                                    f"<light-yellow>{int(delta_time)}</light-yellow> seconds before moon claiming"))

                        if time_left < 0:
                            resp_status = await self.finish_farming(http_client=http_client,
                                                                    boost=info_data['info'].get('boost'))
                            if resp_status:
                                await asyncio.sleep(delay=random.randint(3, 5))
                                await self.start_farming(http_client=http_client, token_time=access_token_created_time)
                        else:
                            sleep_time = sleep_time if time_left > 3600 else time_left
                            logger.info(self.log_message(
                                f"Farming in progress, <ly>{round(time_left / 60, 1)}</ly> min before end"))

                    await asyncio.sleep(delay=sleep_time)

                except InvalidSession as error:
                    raise error

                except Exception as error:
                    log_error(self.log_message(f"Unknown error: {error}"))
                    await asyncio.sleep(delay=3)


async def run_tapper(tg_client: TelegramClient):
    runner = Tapper(tg_client=tg_client)
    try:
        await runner.run()
    except InvalidSession as e:
        log_error(runner.log_message(f"Invalid Session: {e}"))
