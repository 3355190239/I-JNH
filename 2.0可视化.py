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
get_challenge_api="http://10.32.2.6/cgi-bin/get_challenge"
srun_portal_api="http://10.32.2.6/cgi-bin/srun_portal"
sleeptime = 600


n = '200' #客户端的类型 1  PC端    2  移动端   200 特殊保留值
type = '1'
ac_id = '5'# 5校园网
enc = "srun_bx1" #加密算法的版本
_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

header = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36'
}

def is_connected():
    try:
        session = requests.Session()
        html = session.get("https://www.baidu.com", timeout=2)
    except:
        return False
    return True

def _getbyte(s, i):
    return ord(s[i])

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

def ordat(msg, idx):
    return ord(msg[idx]) if len(msg) > idx else 0

def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(ordat(msg, i) | ordat(msg, i+1) << 8 | ordat(msg, i+2) << 16 | ordat(msg, i+3) << 24)
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
    for i in range(l):
        msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)
    return "".join(msg)[0:ll] if key else "".join(msg)

def get_xencode(msg, key):
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk += [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    c = 0x86014019 | 0x183639A0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while q > 0:
        d = d + c & 0xffffffff
        e = d >> 2 & 3
        for p in range(n):
            y = pwd[p + 1]
            m = ((z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (d ^ y))) + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = (pwd[p] + m) & 0xffffffff
            z = pwd[p]
        y = pwd[0]
        m = ((z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (d ^ y))) + (pwdk[(n & 3) ^ e] ^ z)
        pwd[n] = (pwd[n] + m) & 0xffffffff
        z = pwd[n]
        q -= 1
    return lencode(pwd, False)

def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()

def get_chksum():
    chkstr = token + username + token + hmd5 + token + ac_id + token + ip + token + n + token + type + token + i
    return chkstr

def get_info():
    info_temp = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": ac_id,
        "enc_ver": enc
    }
    i = json.dumps(info_temp, separators=(',', ':'))
    return i

def init_getip():
    global ip
    print("\n📡 正在获取 IP 与在线信息...")
    res = requests.get(get_ip_api)
    data = json.loads(res.text[7:-1])
    ip = data.get('client_ip') or data.get('online_ip')
    print("\n🌐 当前设备网络状态")
    print(" ├─ 用户名        :", data.get('user_name'))
    print(" ├─ IP地址        :", ip)
    print(" ├─ MAC地址       :", data.get('user_mac'))
    print(" ├─ 在线设备总数  :", data.get('online_device_total'))
    print(" ├─ 使用套餐      :", data.get('products_name'), f"（{data.get('billing_name')}）")
    print(" └─ 累计流量      :", int(data.get('sum_bytes', 0)) // 1024 // 1024, "MB")
    return ip

def get_token():
    global token
    print("\n🔑 正在获取 Token...")
    get_challenge_params = {
        "callback": f"jQuery_{int(time.time() * 1000)}",
        "username": username,
        "ip": ip,
        "_": int(time.time() * 1000),
    }
    res = requests.get(get_challenge_api, params=get_challenge_params, headers=header)
    data = json.loads(re.search(r'\((\{.*?\})\)', res.text).group(1))
    token = data['challenge']
    print(" ✅ Token 获取成功")
    print(" ├─ Token       :", token[:32] + "...")
    print(" ├─ IP地址      :", data.get('client_ip'))
    print(" └─ 有效时间    :", data.get('expire'), "秒")

def do_complex_work():
    global i, hmd5, chksum
    i = "{SRBX1}" + get_base64(get_xencode(get_info(), token))
    hmd5 = get_md5(password, token)
    chksum = get_sha1(get_chksum())
    print("\n🔐 加密处理完成")
    print(" ├─ hmd5    :", hmd5[:16] + "...")
    print(" ├─ chksum  :", chksum[:16] + "...")
    print(" └─ info    :", i[:32] + "...")

def login():
    print("\n🚀 正在尝试认证登录...")
    params = {
        'callback': f'jQuery_{int(time.time() * 1000)}',
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
    res = requests.get(srun_portal_api, params=params, headers=header)
    match = re.search(r'\((\{.*\})\)', res.text)
    if match:
        res_dict = json.loads(match.group(1))
        res = res_dict.get("res")
        error = res_dict.get("error")
        ip_addr = res_dict.get("client_ip") or res_dict.get("online_ip") or "未知IP"
        if res == "ok" and error == "ok":
            print("✅ 登录成功")
            print(" └─ IP地址: {}\n".format(ip_addr))
        else:
            print(" ❌ 登录失败")
            print(" ├─ 错误类型   :", error)
            print(" ├─ 提示信息   :", res_dict.get("error_msg"))
            print(" └─ IP地址     :", ip_addr)
    else:
        print(" ⚠️ 无法解析返回结果")

if __name__ == '__main__':

    while True:
        if is_connected():
            print('{0} 已通过认证，无需再次认证'.format(
                time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))), flush=True)
        else:
            ip = init_getip()
            get_token()
            do_complex_work()
            login()
        time.sleep(sleeptime)
