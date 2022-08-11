"""
Component to integrate with xiaomi cloud.

For more details about this component, please refer to
https://github.com/fineemb/xiaomi-cloud
"""
import asyncio
import json
import datetime
import random
import time
import logging
import re
import base64
import hashlib
import math
import traceback
from threading import Thread
from selenium import webdriver
from selenium.webdriver import DesiredCapabilities
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support import expected_conditions as EC
from homeassistant.core import Config, HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.components.device_tracker import (
    DOMAIN as DEVICE_TRACKER,
)
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_SCAN_INTERVAL
)
from .const import (
    DOMAIN,
    UNDO_UPDATE_LISTENER,
    COORDINATOR,
)

_LOGGER = logging.getLogger(__name__)
huawei_host = 'https://cloud.huawei.com'
token_list = {}


async def async_setup(hass: HomeAssistant, config: Config) -> bool:
    """Set up configured xiaomi cloud."""
    hass.data[DOMAIN] = {"devices": set(), "unsub_device_tracker": {}}
    return True


async def async_setup_entry(hass, config_entry) -> bool:
    """Set up xiaomi cloud as config entry."""
    username = config_entry.data[CONF_USERNAME]
    password = config_entry.data[CONF_PASSWORD]
    selenium_host = config_entry.data['selenium_host']
    scan_interval = config_entry.options.get(CONF_SCAN_INTERVAL, 60)
    coordinator = XiaomiCloudDataUpdateCoordinator(hass, username, password, selenium_host, scan_interval)
    await coordinator.async_refresh()
    if not coordinator.last_update_success:
        raise ConfigEntryNotReady

    undo_listener = config_entry.add_update_listener(update_listener)

    hass.data[DOMAIN][config_entry.entry_id] = {
        COORDINATOR: coordinator,
        UNDO_UPDATE_LISTENER: undo_listener,
    }
    hass.async_create_task(
        hass.config_entries.async_forward_entry_setup(config_entry, DEVICE_TRACKER)
    )

    async def services(call):
        """Handle the service call."""
        imei = call.data.get("imei")
        service = call.service
        if service == "noise":
            await coordinator._send_command({'service': 'noise', 'data': {'imei': imei}})
        elif service == "find":
            await coordinator._send_command({'service': 'find', 'data': {'imei': imei}})

    hass.services.async_register(DOMAIN, "noise", services)
    hass.services.async_register(DOMAIN, "find", services)
    return True


async def async_unload_entry(hass, config_entry):
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_forward_entry_unload(config_entry, DEVICE_TRACKER)
    hass.data[DOMAIN][config_entry.entry_id][UNDO_UPDATE_LISTENER]()
    if unload_ok:
        hass.data[DOMAIN].pop(config_entry.entry_id)

    try:
        hass.data[DOMAIN][config_entry.entry_id][COORDINATOR]._driver.quit()
    except:
        _LOGGER.error(traceback.format_exc())

    return unload_ok


async def update_listener(hass, config_entry):
    """Update listener."""
    await hass.config_entries.async_reload(config_entry.entry_id)


class XiaomiCloudDataUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching XiaomiCloud data API."""

    def __init__(self, hass, user, password, selenium_host, scan_interval):
        """Initialize."""
        self._username = user
        self._password = password
        self._selenium_host = selenium_host
        self._token = token_list.get(user, {})
        self._last_time = None
        self._is_login = False
        self._last_data = []
        self._driver = None
        self._device_info = {}
        self._scan_interval = scan_interval
        self.service_data = None
        self.csrfToken = None
        self.session = async_get_clientsession(hass)
        self.service = None
        # update_interval = (datetime.timedelta(minutes=self._scan_interval))
        update_interval = (datetime.timedelta(milliseconds=30*1000))
        super().__init__(hass, _LOGGER, name=DOMAIN, update_interval=update_interval)

    async def post(self, path, data, headers={}):
        await self.wait()
        r = await self.session.post(huawei_host + path, data=data, cookies=self._token, headers=headers)
        _LOGGER.debug(f'{self._username}, path:{path}, data:{data}, cookies:{self._token}')
        response = await r.json()
        _LOGGER.debug(f'{self._username}, path:{path}, data:{data}, cookies:{self._token}, response: {response}')
        return response

    async def get(self, path):
        await self.wait()
        _LOGGER.debug(f'{self._username},path:{path}, cookies:{self._token}')
        r = await self.session.get(huawei_host + path, cookies=self._token)
        response = await r.json()
        _LOGGER.debug(f"{self._username},path:{path}, cookies:{self._token}, response:{response}")
        return response

    async def update_device_info(self):
        # 自己的手机
        response = await self.post('/findDevice/getMobileDeviceList',
                                   data={"traceId": "01100_02_1658381855_85554532"})
        for i in response['deviceList']:
            self._device_info[i['deviceId']] = i

        # 分享的手机
        # response = await self.post('/findDevice/getShareGrantInfo',
        #                            data={"traceId": "01100_02_1658381855_85554532"})
        # for i in response['shareGrantInfoList']:
        #     self._device_info[i['senderDeviceId']] = {'deviceType': i['senderDeviceType'],
        #                                               'deviceAliasName': i['senderName'],
        #                                               'senderUserId': i['senderUserId'],
        #                                               'relationType': i['relationType'],
        #                                               'romVersion': i['terminalType'],
        #                                               'activeTime': i['shareStartTime'],
        #                                               'deviceId': i['senderDeviceId']}

    async def get_device_info(self, device_id):
        if device_id not in self._device_info:
            if device_id not in self._device_info:
                raise TypeError('错误的设备id')
        return self._device_info[device_id]

    def refresh_token(self):
        self._driver.get(huawei_host)
        self.csrfToken = self._driver.get_cookie('CSRFToken')['value']

    def refresh_driver(self):
        t = Thread(target=self.refresh_token)
        t.setDaemon(True)
        t.start()

    def start_driver(self, num=0):
        if num > 3:
            raise TypeError('重试3次还未加载')
        try:
            chrome_options = Options()
            chrome_options.add_experimental_option("excludeSwitches", ["enable-logging"])
            chrome_options.add_argument('ignore-certificate-errors')
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--blink-settings=imagesEnabled=true')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--proxy-excludeSwitcher=enable-automation')
            _LOGGER.debug(f'启动driver({self._username})')
            if self._driver is None:
                self._driver = webdriver.Remote(command_executor=self._selenium_host, options=chrome_options,
                                          desired_capabilities=DesiredCapabilities.CHROME)
            try:
                _LOGGER.info(f'开始登录({self._username})华为云')
                self._driver.get(huawei_host)
                self._driver.save_screenshot('/home/pi/1.jpg')
                self._driver.switch_to.frame(1)
                self.get_element(self._driver, (By.CSS_SELECTOR, ".userAccount")).send_keys(self._username)
                self.get_element(self._driver, (By.CSS_SELECTOR, ".hwid-input-pwd")).send_keys(self._password)
                elem = self.get_element(self._driver, (By.CSS_SELECTOR, ".hwid-btn"))
                self._driver.execute_script("arguments[0].click()", elem)
                self.get_element(self._driver, (By.CSS_SELECTOR, ".featuresText"))
                csrfToken = self._driver.get_cookie('CSRFToken')
                if csrfToken is not None:
                    self.csrfToken = ['value']
                token_list[self._username] = {'token': self._driver.get_cookie('token')['value'],
                                              'loginID': self._driver.get_cookie('loginID')['value']}
            except Exception:
                _LOGGER.error(f'{self._username}启动失败, 异常日志:{traceback.format_exc()}')
                csrfToken = self._driver.get_cookie('CSRFToken')
                if csrfToken is not None:
                    self.csrfToken = ['value']
                if self._driver.get_cookie('token')['value'] is not None:
                    token_list[self._username] = {'token': self._driver.get_cookie('token')['value'],
                                   'loginID': self._driver.get_cookie('loginID')['value']}
				
            # self._driver.delete_all_cookies()
        except:
            _LOGGER.error(f"{self._username}启动失败, 异常日志:{traceback.format_exc()}")
            self.start_driver(num+1)
        self._is_login = False
        self._token = token_list[self._username]
        _LOGGER.info(f'{self._username}登录华为云成功， {self._token}')

    def get_element(self, driver, find):
        return WebDriverWait(driver, 10, 0.2).until(EC.visibility_of_element_located(find))

    async def check_active(self):
        if self._is_login is True:
            raise TypeError('正在登录，当前更新取消')
        try:
            return await self.update_device_info()
        except Exception:
            return await self.update_token()
        # path = f'/heartbeatCheck?checkType=1&traceId=07100_02_{int(time.time())}_{random.randint(10000000, 99999999)}'
        # response = await self.get(path)
        # if response['code'] != 0:

    async def update_token(self, num=0):
        _LOGGER.debug(f'({self._username})token失效，开始登录， 异常:{traceback.format_exc()}')
        if num > 3:
            raise TypeError(f'({self._username})更新token失败')
        t = Thread(target=self.start_driver)
        t.setDaemon(True)
        t.start()
        self._is_login = True
        await self.wait()
        try:
            return await self.update_device_info()
        except:
            return self.update_token(num+1)

    async def wait(self):
        for i in range(12):
            if self._is_login is False:
                break
            await asyncio.sleep(5)

    async def find(self, imei):
        device_info = await self.get_device_info(imei)
        vin_info = self._device_info[imei]
        device_type = device_info['deviceType']
        
        # 更新位置
        data = {
            "cptList": "",
            "deviceId": imei,
            "deviceType": device_type,
            "perDeviceType": device_info["perDeviceType"],
            "traceId": f"01001_02_1659590663_75983514_{device_info['appVersion']}_{device_info['romVersion']}",
        }
        response = await self.post('/findDevice/locate', data=data)
        
        
        # 查询位置
        
        data = {
            'deviceId': imei,
            'deviceType': device_type
        }
        if 'senderUserId' in device_info:
            data['senderUserId'] = device_info['senderUserId']
            data['relationType'] = device_info['relationType']
        response = await self.post('/findDevice/queryLocateResult', data=data)
        
        device_info = {
            'model': vin_info["deviceAliasName"],
            'version': vin_info["romVersion"],
            'last_update': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())),
            'imei': imei,
        }
        if self._last_time is not None:
            device_info['last_time'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self._last_time)),
        
        if (response['exeResult'] != '-1') or ('code' in response and response['code'] == '0' and 'info' in response and response['info'] == 'Success.'):
            locateInfo = json.loads(response['locateInfo'])
            device_info.update({"latitude": locateInfo['latitude_WGS'],
                                "location_accuracy": locateInfo.get('accuracy', 0),
                                "longitude": locateInfo['longitude_WGS'],
                                "battery_level": int(json.loads(locateInfo['batteryStatus'])['percentage']),
                                "networkInfo":json.loads(locateInfo['networkInfo'])['name'],
                                "simInfo": json.loads(locateInfo['simInfo'])['no'],
                                })
            
        else:
            device_info.update({'accuracy': 0, 'battery': 0, 'latitude': 0, 'longitude': 0, 'simInfo': -1, 'networkInfo': -1, 'battery_level': -1})
        device_info['state'] = f"{device_info['networkInfo']}({device_info['battery_level']})"
        return device_info

    async def portal_bell(self, device_id):
        device_type = (await self.get_device_info(device_id))['deviceType']
        data = {'deviceId': device_id, 'deviceType': device_type}
        headers = {'CSRFToken': self.csrfToken}
        return await self.post('/findDevice/portalBellReq', data=data, headers=headers)

    async def _send_lost_command(self, session):
        flag = True
        imei = self.service_data['imei']
        content = self.service_data['content']
        phone = self.service_data['phone']
        message = {"content": content, "phone": phone}
        onlinenotify = self.service_data['onlinenotify']
        url = 'https://i.mi.com/find/device/{}/lost'.format(
            imei)
        _send_lost_command_header = {
            'Cookie': 'userId={};serviceToken={}'.format(self.userId, self._Service_Token)}
        data = {'userId': self.userId, 'imei': imei,
                'deleteCard': 'false', 'channel': 'web', 'serviceToken': self._Service_Token,
                'onlineNotify': onlinenotify, 'message': json.dumps(message)}
        try:
            # with async_timeout.timeout(15, loop=self.hass.loop):
            #     r = await session.post(url, headers=_send_lost_command_header, data=data)
            r = await session.post(url, headers=_send_lost_command_header, data=data)
            _LOGGER.debug("lost res: %s", await r.json())
            if r.status == 200:
                flag = True
                self.service = None
                self.service_data = None
            else:
                flag = False
                self.login_result = False
        except BaseException as e:
            _LOGGER.warning(e.args[0])
            self.login_result = False
            flag = False
        return flag

    async def _send_clipboard_command(self, session):
        flag = True
        text = self.service_data['text']
        url = 'https://i.mi.com/clipboard/lite/text'
        _send_clipboard_command_header = {
            'Cookie': 'userId={};serviceToken={}'.format(self.userId, self._Service_Token)}
        data = {'text': text, 'serviceToken': self._Service_Token}
        try:
            # with async_timeout.timeout(15, loop=self.hass.loop):
            #     r = await session.post(url, headers=_send_clipboard_command_header, data=data)
            r = await session.post(url, headers=_send_clipboard_command_header, data=data)
            _LOGGER.debug("clipboard res: %s", await r.json())
            if r.status == 200:
                flag = True
                self.service = None
                self.service_data = None
            else:
                flag = False
                self.login_result = False
        except BaseException as e:
            _LOGGER.warning(e.args[0])
            self.login_result = False
            flag = False
        return flag

    async def _send_command(self, data):
        self.service_data = data['data']
        self.service = data['service']
        await self.async_refresh()

    async def _get_device_location(self):
        devices_info = []
        for imei in self._device_info:
            devices_info.append(await self.find(imei))
        return devices_info

    async def _async_update_data(self):
        """Update data via library."""
        _LOGGER.debug(f"{self._username},service: {self.service}, data:{self.data}", )
        # if self.data
        await self.check_active()
        if self.service == "noise":
            self.service = None
            await self.portal_bell(self.service_data['imei'])
        if self.service == "find":
            self.service = None
            response = await self.find(self.service_data['imei'])
            self._last_time = time.time()
        elif self._last_time is None or time.time() - self._last_time > self._scan_interval:
            response = await self._get_device_location()
            self._last_data = response
            self._last_time = time.time()
        elif time.time() - self._last_time <= self._scan_interval:
            # self._driver.get(huawei_host)
            self.refresh_driver()
            response = self._last_data
        else:
            response = self._last_data
        _LOGGER.debug(f'return:{response}')
        return response
