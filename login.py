#!/usr/bin/python3
import json
import requests
import time
import re
import hmac
import hashlib
import math
import os


username = '202412492138'+'@campus'
password = 'jzy000925.'
get_ip_api='http://10.32.2.6/cgi-bin/rad_user_info?callback=jQuery'
init_url="http://10.32.2.6"
get_challenge_api="http://10.32.2.6/cgi-bin/get_challenge"
srun_portal_api="http://10.32.2.6/cgi-bin/srun_portal"
sleeptime = 600


if username == '':
    username = os.getenv('USERNAME').strip()
if password == '':
    password = os.getenv('PASSWORD').strip()
if init_url == '':
    init_url = os.getenv('init_url').strip()
if get_challenge_api == '':
    get_challenge_api = os.getenv('get_challenge_api').strip()
if srun_portal_api == '':
    srun_portal_api = os.getenv('srun_portal_api').strip()
if get_ip_api == '':
    get_ip_api = os.getenv('get_ip_api').strip()

header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36'
}

n = '200'
type = '1'
ac_id = '5'
enc = "srun_bx1"

_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"


def _getbyte(s, i):
    x = ord(s[i])
    if x > 255:
        print("{0} INVALID_CHARACTER_ERR: DOM Exception 5".format(
            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))), flush=True)
        exit(0)
    return x


def get_base64(s):
    r = []
    x = len(s) % 3
    if x:
        s = s + '\0' * (3 - x)
    for i in range(0, len(s), 3):
        d = s[i:i + 3]
        a = ord(d[0]) << 16 | ord(d[1]) << 8 | ord(d[2])
        r.append(_ALPHA[a >> 18])
        r.append(_ALPHA[a >> 12 & 63])
        r.append(_ALPHA[a >> 6 & 63])
        r.append(_ALPHA[a & 63])
    if x == 1:
        r[-1] = '='
        r[-2] = '='
    if x == 2:
        r[-1] = '='
    return ''.join(r)


def get_md5(password, token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


def force(msg):
    ret = []
    for w in msg:
        ret.append(ord(w))
    return bytes(ret)


def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i) | ordat(msg, i + 1) << 8 | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24)
    if key:
        pwd.append(l)
    return pwd


def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(0, l):
        msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
            msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
    if key:
        return "".join(msg)[0:ll]
    return "".join(msg)


def get_xencode(msg, key):
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)


def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()


def get_chksum():
    chkstr = token + username
    chkstr += token + hmd5
    chkstr += token + ac_id
    chkstr += token + ip
    chkstr += token + n
    chkstr += token + type
    chkstr += token + i
    return chkstr


def get_info():
    info_temp = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": ac_id,
        "enc_ver": enc
    }
    i = re.sub("'", '"', str(info_temp))
    i = re.sub(" ", '', i)
    return i

# 用户在线信息 '/cgi-bin/rad_user_info
def init_getip():
    global ip
    res = requests.get(get_ip_api)
    print(res.text)
    # jQuery({"ServerFlag": 4294967040, "add_time": 1751548792, "all_bytes": 3254576481, "billing_name": "免费",
    #         "bytes_in": 852341472, "bytes_out": 177270078, "checkout_date": 0, "domain": "campus", "error": "ok",
    #         "group_id": "5", "keepalive_time": 1751599061, "online_device_total": "3", "online_ip": "10.44.215.20",
    #         "online_ip6": "::", "package_id": "0", "products_id": "16", "products_name": "研究生", "real_name": "",
    #         "remain_bytes": 0, "remain_seconds": 0, "sum_bytes": 61360830351, "sum_seconds": 249229,
    #         "sysver": "1.01.20211028", "user_balance": 0, "user_charge": 0, "user_mac": "80:af:ca:b5:2c:a7",
    #         "user_name": "202412492138", "wallet_balance": 0})

    # [7:-1]是为了去掉前面的 jQuery( 和后面的 )
    data = json.loads(res.text[7:-1])


    ip = data.get('client_ip') or data.get('online_ip')
    # print("{0} ip:".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))) + ip, flush=True)
    print("{0} ✅ip:{1} MAC地址:{2} user_name:{3} 在线设备总数:{4}".format(
        time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
        ip,
        data.get('user_mac'),
        data.get('user_name'),
        data.get('online_device_total')
    ), flush=True)
    return ip


def get_token():
    # print("{0} 获取token".format(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))), flush=True)
    global token
    get_challenge_params = {
        "callback": "jQuery112404953340710317169_" + str(int(time.time() * 1000)),
        "username": username,
        "ip": ip,
        "_": int(time.time() * 1000),
    }
    test = requests.Session()
    get_challenge_res = test.get(get_challenge_api, params=get_challenge_params, headers=header)
    print(get_challenge_res.text)
    # jQuery112404953340710317169_1751599118683(
    #     {"challenge": "b127d6793d892ed6b026170afc2a63cec4a71ef92ae1271aaeef860d90b6334f", "client_ip": "10.44.215.20",
    #      "ecode": 0, "error": "ok", "error_msg": "", "expire": "60", "online_ip": "10.44.215.20", "res": "ok",
    #      "srun_ver": "SRunCGIAuthIntfSvr V1.18 B20211028", "st": 1751599118})

    token = re.search('"challenge":"(.*?)"', get_challenge_res.text).group(1)
    # print("{0} {1}".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())), get_challenge_res.text),
    #       flush=True)
    print("{0} token为:".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))) + token, flush=True)


def is_connected():
    try:
        session = requests.Session()
        html = session.get("https://www.baidu.com", timeout=2)
    except:
        return False
    return True


def do_complex_work():
    global i, hmd5, chksum
    i = get_info()
    i = "{SRBX1}" + get_base64(get_xencode(i, token))
    hmd5 = get_md5(password, token)
    chksum = get_sha1(get_chksum())
    print("{0} 所有加密工作已完成".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))), flush=True)


def login():
    srun_portal_params = {
        'callback': 'jQuery112404010764862546194_' + str(int(time.time() * 1000)),
        'action': 'login',
        'username': username,
        'password': '{MD5}' + hmd5,
        'ac_id': ac_id,
        'ip': ip,
        'chksum': chksum,
        'info': i,
        'n': n,
        'type': type,
        'os': 'windows+10',
        'name': 'windows',
        'double_stack': '0',
        '_': int(time.time() * 1000)
    }

    # print(srun_portal_params)
    test = requests.Session()
    srun_portal_res = test.get(srun_portal_api, params=srun_portal_params, headers=header)
    # print(srun_portal_res.text)
    # jQuery112404010764862546194_1751599148410(
    #     {"ServerFlag": 0, "ServicesIntfServerIP": "0.0.0.0", "ServicesIntfServerPort": "8001",
    #      "access_token": "293b1e4f23625cd9363dec54e883dd94a29019c271901e02f77bf480ff03135e", "checkout_date": 0,
    #      "client_ip": "10.44.215.20", "ecode": 0, "error": "ok", "error_msg": "", "online_ip": "10.44.215.20",
    #      "real_name": "", "remain_flux": 0, "remain_times": 0, "res": "ok",
    #      "srun_ver": "SRunCGIAuthIntfSvr V1.18 B20211028", "suc_msg": "ip_already_online_error",
    #      "sysver": "1.01.20211028", "username": "202412492138@campus", "wallet_balance": 0})

    print("{0} {1}".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())), srun_portal_res.text),
          flush=True)
    match = re.search(r'\((\{.*\})\)', srun_portal_res.text)
    if match:
        res_dict = json.loads(match.group(1))
        res = res_dict.get("res")
        error = res_dict.get("error")
        ip_addr = res_dict.get("client_ip") or res_dict.get("online_ip") or "未知IP"

        if res == "ok" and error == "ok":
            print("{0} ✅ 登录成功，IP: {1}".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()), ip_addr),
                  flush=True)
        else:
            print("{0} ❌ 登录失败".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())), flush=True)
    else:
        print("{0} ⚠️ 无法解析返回结果".format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())), flush=True)


if __name__ == '__main__':
    # while True:
    #     if is_connected():
    #         print('{0} 已通过认证，无需再次认证'.format(
    #             time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))), flush=True)
    #     else:
    #         ip = init_getip()
    #         get_token()
    #         do_complex_work()
    #         login()
    #     time.sleep(sleeptime)
    ip = init_getip()
    get_token()
    do_complex_work()
    login()