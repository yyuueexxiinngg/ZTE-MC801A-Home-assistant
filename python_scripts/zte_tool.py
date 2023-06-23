import requests
import hashlib
from datetime import datetime
import binascii
import urllib.parse
import json
import sys
import os
import time
import pickle

ROUTER_IP = "192.168.8.1"
USERNAME = "admin"
PASSWORD = "PASSWORD"

gsm = ("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
       "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ`¿abcdefghijklmnopqrstuvwxyzäöñüà")
ext = ("````````````````````^```````````````````{}`````\\````````````[~]`"
       "|````````````````````````````````````€``````````````````````````")


def get_sms_time():
    return datetime.now().strftime("%y;%m;%d;%H;%M;%S;+2")


def gsm_encode(plaintext):
    res = bytearray()
    for c in plaintext:
        res.append(0)
        idx = gsm.find(c)
        if idx != -1:
            res.append(idx)
            continue
        idx = ext.find(c)
        if idx != -1:
            res.append(27)
            res.append(idx)
    return binascii.hexlify(res)


def get_md5_hash(text):
    return hashlib.md5(text.encode()).hexdigest()


def get_sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


class ZteRouter:

    def __init__(self, ip, user, password):
        self.ip = ip
        self.referer = f"http://{self.ip}/"
        self.password = password
        self.user = user

        script_path = os.path.abspath(sys.argv[0])
        script_dir = os.path.dirname(script_path)

        self.session = requests.Session()
        self.session.headers.update({"Referer": self.referer})
        self.cookie_file_path = script_dir + "/cookie.pkl"
        self.get_cookie()

    def get_req(self, payload):
        payload["isTest"] = "false"
        return self.session.get(self.referer + f"goform/goform_get_cmd_process", params=payload)

    def get_req_post(self, payload):
        payload["isTest"] = "false"
        return self.session.post(self.referer + f"goform/goform_get_cmd_process", data=payload)

    def set_req(self, payload):
        payload["isTest"] = "false"
        return self.session.post(self.referer + f"goform/goform_set_cmd_process", data=payload)

    def get_version(self):
        payload = {"cmd": "wa_inner_version"}
        r = self.get_req(payload)
        return r.json()["wa_inner_version"]

    def get_cr_version(self):
        payload = {"cmd": "cr_version"}
        r = self.get_req(payload)
        return r.json()["cr_version"]

    def get_ld(self):
        payload = {"cmd": "LD"}
        r = self.get_req(payload)
        return r.json()["LD"].upper()

    def get_ad(self):
        a = get_md5_hash(self.get_version())
        u = self.get_rd()
        ad = get_md5_hash(a + u)
        return ad

    def get_user(self):
        payload = {
            "cmd": "user,admin_password_changed,web_current_account,web_username1,web_username2",
            "multi_data": "1"
        }
        r = self.get_req(payload)
        return r.json()

    def get_cookie(self):
        if os.path.exists(self.cookie_file_path):
            with open(self.cookie_file_path, 'rb') as f:
                self.session.cookies.update(pickle.load(f))
            if self.get_user()["user"] != '':
                return

        ld = self.get_ld()
        hash_password = get_sha256_hash(self.password).upper()
        zte_pass = get_sha256_hash(hash_password + ld).upper()
        payload = {"goformId": "LOGIN_MULTI_USER", "user": self.user, "password": zte_pass}
        self.set_req(payload)
        with open(self.cookie_file_path, 'wb') as f:
            pickle.dump(self.session.cookies, f)

    def get_rd(self):
        payload = {"cmd": "RD"}
        r = self.get_req_post(payload)
        return r.json()["RD"]

    def send_sms(self):
        ad = self.get_ad()
        payload = {"goformId": "SEND_SMS", "notCallback": "true", "Number": phoneNumberEncoded,
                   "sms_time": getsmstimeEncoded, "MessageBody": outputmessage, "ID": "-1",
                   "encode_type": "GSM7_default", "AD": ad}
        r = self.set_req(payload)
        return r.status_code

    def zte_info(self):
        payload = {
            "cmd": "wa_inner_version,network_type,rssi,rscp,rmcc,rmnc,enodeb_id,lte_rsrq,lte_rsrp,Z5g_snr,Z5g_rsrp,"
                   "ZCELLINFO_band,Z5g_dlEarfcn,lte_ca_pcell_arfcn,lte_ca_pcell_band,lte_ca_scell_band,"
                   "lte_ca_pcell_bandwidth,lte_ca_scell_info,lte_ca_scell_bandwidth,wan_lte_ca,lte_pci,Z5g_CELL_ID,"
                   "Z5g_SINR,cell_id,wan_lte_ca,lte_ca_pcell_band,lte_ca_pcell_bandwidth,lte_ca_scell_band,"
                   "lte_ca_scell_bandwidth,lte_ca_pcell_arfcn,lte_ca_scell_arfcn,lte_multi_ca_scell_info,"
                   "wan_active_band,nr5g_pci,nr5g_action_band,nr5g_cell_id,lte_snr,ecio,wan_active_channel,"
                   "nr5g_action_channel,ngbr_cell_info,monthly_tx_bytes,monthly_rx_bytes,lte_pci,lte_pci_lock,"
                   "lte_earfcn_lock,wan_ipaddr,wan_apn,pm_sensor_mdm,pm_modem_5g,nr5g_pci,nr5g_action_channel,"
                   "nr5g_action_band,Z5g_SINR,Z5g_rsrp,wan_active_band,wan_active_channel,wan_lte_ca,"
                   "lte_multi_ca_scell_info,cell_id,dns_mode,prefer_dns_manual,standby_dns_manual,network_type,rmcc,"
                   "rmnc,lte_rsrq,lte_rssi,lte_rsrp,lte_snr,wan_lte_ca,lte_ca_pcell_band,lte_ca_pcell_bandwidth,"
                   "lte_ca_scell_band,lte_ca_scell_bandwidth,lte_ca_pcell_arfcn,lte_ca_scell_arfcn,wan_ipaddr,"
                   "static_wan_ipaddr,opms_wan_mode,opms_wan_auto_mode,ppp_status,loginfo,realtime_rx_bytes,"
                   "realtime_tx_bytes,realtime_rx_thrpt,realtime_tx_thrpt",
            "multi_data": "1"
        }
        response = self.get_req(payload)
        print(response.text)

    def zte_sms_info(self):
        payload = {"cmd": "sms_capacity_info"}
        response = self.get_req(payload)
        return response.text

    def zte_reboot(self):
        ad = self.get_ad()
        payload = {"goformId": "REBOOT_DEVICE", "notCallback": "true", "AD": ad}
        r = self.set_req(payload)
        return r.status_code

    def delete_sms(self, msg_id):
        ad = self.get_ad()
        payload = {"goformId": "DELETE_SMS", "msg_id": msg_id, "AD": ad}
        r = self.set_req(payload)
        return r.status_code

    def parse_sms(self):
        payload = {"cmd": "sms_data_total", "page": "0", "data_per_page": "5000", "mem_store": "1", "tags": "10",
                   "order_by": "order by id desc"}
        r = self.get_req_post(payload)
        response_text = r.text

        # Find and replace the string
        modified_response_text = response_text.replace('HRTelekom', 'HR Telekom')
        response_json = json.loads(modified_response_text)
        value = response_json['messages']

        def hex2utf(string):
            length = len(string) // 4
            result = ''
            for i in range(length):
                result += chr(int(string[i * 4:i * 4 + 4], 16))
            return result

        # Load the JSON data from a file
        smslist = response_json

        # Convert the hexadecimal code points in the 'content' field to Unicode characters
        for item in smslist['messages']:
            item['content'] = hex2utf(item['content'])

        # Write the modified JSON data to a new file
        # with open('smslist_converted.json', 'w') as f:
        # json.dump(smslist, f, indent=2)
        return json.dumps(smslist, indent=2)


getsmstime = get_sms_time()
getsmstimeEncoded = urllib.parse.quote(getsmstime, safe="")
phoneNumber = '13909'  # enter phone number here
phoneNumberEncoded = urllib.parse.quote(phoneNumber, safe="")
message = 'BRZINA'  # enter your message here
messageEncoded = gsm_encode(message)
outputmessage = messageEncoded.decode()

zteInstance = ZteRouter(ROUTER_IP, USERNAME, PASSWORD)
ha_select = int(sys.argv[1])

if ha_select == 1:
    time.sleep(2)
    zteInstance.parse_sms()
    result = zteInstance.parse_sms()
    json_str = json.dumps(result)
    test = json.loads(result)
    first_message = test["messages"][0]
    first_message_json = json.dumps(first_message)
    print(first_message_json)
elif ha_select == 2:
    zteInstance.send_sms()
elif ha_select == 3:
    time.sleep(1)
    zteInstance.zte_info()
elif ha_select == 4:
    zteInstance.zte_reboot()
elif ha_select == 5:
    zteInstance.parse_sms()
    result = zteInstance.parse_sms()
    data = json.loads(result)
    keys = data.keys()  # ['key']
    ids = [message['id'] for message in data['messages']]
    formatted_ids = ";".join(ids)
    print(formatted_ids)
    zteInstance.delete_sms(formatted_ids)
elif ha_select == 6:
    time.sleep(6)
    json_string = zteInstance.zte_sms_info()
    totalztememory = 100
    dictionary = json.loads(json_string)
    nv_rev_total = int(dictionary['sms_nv_rev_total'])
    nv_send_total = int(dictionary['sms_nv_send_total'])
    total = nv_rev_total + nv_send_total
    totalremaining = totalztememory - total
    # print(totalremaining)
    print(f"You have {totalremaining} messages left of 100")

else:
    print("ELSE")