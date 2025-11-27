import argparse
import json
import pdb
import re
import shutil
import subprocess
import time
import os
from selenium import webdriver
from selenium.webdriver import ChromeOptions, DesiredCapabilities
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.by import By


# !coding=utf-8
import logging
from threading import Timer
import io

import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


def kill_command(p):
    """终止命令的函数"""
    p.kill()

def execute(command, timeout):
    # 执行shell命令
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    # 设置定时器去终止这个命令
    timer = Timer(timeout, kill_command, [p])
    try:
        timer.start()
        stdout, stderr = p.communicate()
        return_code = p.returncode
        # pdb.set_trace()
        print(return_code)
        print(stdout)
        if return_code==0:
            return True
    except Exception as ex:
        print(ex)
    finally:
        timer.cancel()

# 设置logging的等级以及打印格式
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')

count=1
parser = argparse.ArgumentParser(description='manual to this script')
parser.add_argument('--gkitag', type=str, help='android kernel common refs tag android for mtk')
parser.add_argument('--kernelbuildid', type=str, help='kernel id for qualcomm')
parser.add_argument('--androidbuildid', type=str, help='boot.img id for qualcomm')
args = parser.parse_args()
# print(args.imagepath)

# parser.add_argument('--arg1', '-a1', type=int, help='参数1，非必须参数')
# parser.add_argument('--arg2', '-a2', type=str, help='参数2，非必须参数,包含默认值', default='xag')
# parser.add_argument('--arg3', '-a3', type=str, help='参数3，必须参数', required=True)

vmlinux={"url":"https://ci.android.com/builds/submitted/"+args.kernelbuildid+"/kernel_aarch64/latest",

         "build_info_js":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                          ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(2) > artifact-folder')"
                          ".shadowRoot.querySelector('div > div.artifact-name.no-download > a').click()",
# "document.querySelector("#artifact_view_page").shadowRoot.querySelector("artifact-viewer").shadowRoot.querySelector("div.artifact-header > div.buttons-container > a > huckle-button").shadowRoot.querySelector("button")"
         "build_info_download":"return arguments[0].shadowRoot.querySelector('artifact-viewer')"
                          ".shadowRoot.querySelector('div.artifact-header > div.buttons-container > a > huckle-button')"
                               ".shadowRoot.querySelector('button').click()",
        # "html_prefix":"<html><head></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">",
        "html_prefix":"'name=\"color-scheme\" content=\"light dark\"></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">",
         "html_suffix":"</pre></body></html>",
         "vmlinux_download":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                          ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(22) > artifact-folder')"
                          ".shadowRoot.querySelector('div > div.artifact-name.no-download > a').click()",
         "vmlinux_symvers_js":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                          ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(23) > artifact-folder')"
                          ".shadowRoot.querySelector('div > div.artifact-name.no-download > a').click()",
         "vmlinux_symvers_download":"return arguments[0].shadowRoot.querySelector('artifact-viewer')"
                          ".shadowRoot.querySelector('div.artifact-header > div.buttons-container > a > huckle-button').click()"
         }

vmlinux_imgid={
        "build_info_js":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                          ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(2) > artifact-folder')"
                          ".shadowRoot.querySelector('div > div.artifact-name.no-download > a').click()",
         "build_info_download":"return arguments[0].shadowRoot.querySelector('artifact-viewer')"
                          ".shadowRoot.querySelector('div.artifact-header > div.buttons-container > a > huckle-button').click()",
         #"html_prefix":"<html><head></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">",
         "html_prefix":"'name=\"color-scheme\" content=\"light dark\"></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">",
         "html_suffix":"</pre></body></html>",
         "kernel_mv":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                 ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(62) > artifact-folder')"
                  ".shadowRoot.querySelector('div > div > span').scrollIntoView()",
         "kernel":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                 ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(62) > artifact-folder')"
                  ".shadowRoot.querySelector('div > div > span').click()",
         "vmlinux_download":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                            ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(62) > artifact-folder')"
                            ".shadowRoot.querySelector('artifact-folder')"
                            ".shadowRoot.querySelector('artifact-folder:nth-child(4)')"
                            ".shadowRoot.querySelector('div:nth-child(6) > div.artifact-name.no-download > a').click()",

        "vmlinux_download_mv":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                            ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(62) > artifact-folder')"
                            ".shadowRoot.querySelector('artifact-folder')"
                            ".shadowRoot.querySelector('artifact-folder:nth-child(4)')"
                            ".shadowRoot.querySelector('div:nth-child(6) > div.artifact-name.no-download > a').scrollIntoView()",
        "vmlinux_symvers_mv":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                             ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(62) > artifact-folder')"
                             ".shadowRoot.querySelector('artifact-folder')"
                             ".shadowRoot.querySelector('artifact-folder:nth-child(4)')"
                             ".shadowRoot.querySelector('div:nth-child(7) > div.artifact-name.no-download > a').scrollIntoView()",
        "vmlinux_symvers_js":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                             ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(62) > artifact-folder')"
                             ".shadowRoot.querySelector('artifact-folder')"
                             ".shadowRoot.querySelector('artifact-folder:nth-child(4)')"
                             ".shadowRoot.querySelector('div:nth-child(7) > div.artifact-name.no-download > a').click()",
        "vmlinux_symvers_download":"return arguments[0].shadowRoot.querySelector('artifact-viewer')"
                          ".shadowRoot.querySelector('div.artifact-header > div.buttons-container > a > huckle-button').click()"

}
vmlinux_debug_imgid={
        "build_info_js":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                          ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(2) > artifact-folder')"
                          ".shadowRoot.querySelector('div > div.artifact-name.no-download > a').click()",
         "build_info_download":"return arguments[0].shadowRoot.querySelector('artifact-viewer')"
                          ".shadowRoot.querySelector('div.artifact-header > div.buttons-container > a > huckle-button').click()",
         #"html_prefix":"<html><head></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">",
         "html_prefix":"'name=\"color-scheme\" content=\"light dark\"></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">",
         "html_suffix":"</pre></body></html>",
         "vmlinux_download":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                            ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(62) > artifact-folder')"
                            ".shadowRoot.querySelector('artifact-folder')"
                            ".shadowRoot.querySelector('artifact-folder:nth-child(6)')"
                            ".shadowRoot.querySelector('div:nth-child(6) > div.artifact-name.no-download > a').click()",
        "vmlinux_download_mv":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                            ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(62) > artifact-folder')"
                            ".shadowRoot.querySelector('artifact-folder')"
                            ".shadowRoot.querySelector('artifact-folder:nth-child(6)')"
                            ".shadowRoot.querySelector('div:nth-child(6) > div.artifact-name.no-download > a').scrollIntoView()",

        "vmlinux_symvers_mv":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                             ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(62) > artifact-folder')"
                             ".shadowRoot.querySelector('artifact-folder')"
                             ".shadowRoot.querySelector('artifact-folder:nth-child(6)')"
                             ".shadowRoot.querySelector('div:nth-child(7) > div.artifact-name.no-download > a').scrollIntoView()",

        "vmlinux_symvers_js":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                             ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(62) > artifact-folder')"
                             ".shadowRoot.querySelector('artifact-folder')"
                             ".shadowRoot.querySelector('artifact-folder:nth-child(6)')"
                             ".shadowRoot.querySelector('div:nth-child(7) > div.artifact-name.no-download > a').click()",
        "vmlinux_symvers_download":"return arguments[0].shadowRoot.querySelector('artifact-viewer')"
                          ".shadowRoot.querySelector('div.artifact-header > div.buttons-container > a > huckle-button').click()",

}

vmlinux_debug={"url":"https://ci.android.com/builds/submitted/"+args.kernelbuildid+"/kernel_debug_aarch64/latest",

         "build_info_js":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                          ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(2) > artifact-folder')"
                          ".shadowRoot.querySelector('div > div.artifact-name.no-download > a').click()",
         "build_info_download":"return arguments[0].shadowRoot.querySelector('artifact-viewer')"
                          ".shadowRoot.querySelector('div.artifact-header > div.buttons-container > a > huckle-button').click()",
        # "html_prefix":"<html><head></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">",
         "html_prefix":"'name=\"color-scheme\" content=\"light dark\"></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">",
         "html_suffix":"</pre></body></html>",
         "vmlinux_download":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                          ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(25) > artifact-folder')"
                          ".shadowRoot.querySelector('div > div.artifact-name.no-download > a').click()",
         "vmlinux_symvers_js":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                          ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(26) > artifact-folder')"
                          ".shadowRoot.querySelector('div > div.artifact-name.no-download > a').click()",
         "vmlinux_symvers_download":"return arguments[0].shadowRoot.querySelector('artifact-viewer')"
                          ".shadowRoot.querySelector('div.artifact-header > div.buttons-container > a > huckle-button').click()"
         }

bootimg = {
    "url":"https://ci.android.com/builds/submitted/8849477/gsi_arm64-user/latest",
    "signed_js": "return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                        ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(90) > artifact-folder')"
                        ".shadowRoot.querySelector('div > div > span').click()",

    "signed_js_mv": "return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                        ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(90) > artifact-folder')"
                        ".shadowRoot.querySelector('div').scrollIntoView()",

    "bootimg_download":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                       ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(90) > artifact-folder')"
                       ".shadowRoot.querySelector('artifact-folder')"
                       ".shadowRoot.querySelector('div:nth-child(5) > div.artifact-name.no-download > a').click()",

    "gsi_js_mv": "return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                             ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(45) > artifact-folder')"
                             ".shadowRoot.querySelector('div > div.artifact-name.no-download > a').scrollIntoView()",

    "bootimg_download_debug":"return arguments[0].shadowRoot.querySelector('div > artifact-list')"
                             ".shadowRoot.querySelector('div > div.grid-container > div:nth-child(45) > artifact-folder')"
                             ".shadowRoot.querySelector('div > div.artifact-name.no-download > a').click()"
}

url1 = 'https://ci.android.com/builds/submitted/8836202/kernel_aarch64/latest'
url2 = 'https://ci.android.com/builds/submitted/8836202/kernel_debug_aarch64/latest'

#path = r'D:\jenkins\gki\chromedriver.exe'
path = r'D:\Program Files\chromedriver_win32\chromedriver.exe'

# path = r'/usr/bin/chromedriver'

download_path="download"


if os.path.exists(download_path):
    shutil.rmtree(download_path)
    print("delete the old download path")
    os.mkdir(download_path)
    print("new download path")
else:
    os.mkdir(download_path)

options = webdriver.ChromeOptions()
options.add_argument(r'--user-data-dir=D:\jenkins\gki\User Data')

prefs = {"download.default_directory":os.getcwd(),'safebrowsing.enabled': False,}
options.add_experimental_option("prefs", prefs)
#options.add_argument("--remote-debugging-port=9222") 
options.add_argument("--proxy-server=wgw.myoas.com:9090")
# options.add_argument("--incognito")
#options.add_argument("--headless")
#options.add_argument('--disable-infobars')
# ca = DesiredCapabilities.CHROME
# ca["goog:loggingPrefs"] = {"performance": "ALL"}
# # driver = webdriver.Chrome(desired_capabilities=ca)
#
# driver  = webdriver.Chrome(executable_path=path, chrome_options=options,desired_capabilities=ca)

options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

#driver  = webdriver.Chrome(executable_path=path, chrome_options=options)
driver  = webdriver.Chrome()
driver.implicitly_wait(20)


def check_download_file(f, load=1):
    time.sleep(int(load))
    file_list = os.listdir(os.getcwd())
    # pdb.set_trace()
    if f in file_list:

        return True
    else:
        return False

def clear_download_file(file):
    file_list = os.listdir(os.getcwd())
    for f in file_list:
        # pdb.set_trace()
        # if re.search(file,f) and re.search("\.zip",f):
        if re.search(file, f) and os.path.isfile(f) :
            # pdb.set_trace()
            os.remove(f)
    # if f in file_list:
    # if os.path.exists(file):
    #     os.remove(file)

def download(file,**filename):
    #driver.implicitly_wait(5)
    time.sleep(5)
    host = driver.find_element(By.XPATH,"//*[@id='artifact_page']")

    driver.execute_script(file["build_info_js"], host)
    # driver.implicitly_wait(5)
    # pdb.set_trace()
    time.sleep(5)
    host= driver.find_element(By.XPATH,"//*[@id='artifact_view_page']")
    driver.execute_script(file["build_info_download"],host)
    #driver.implicitly_wait(5)

    build_info=str(driver.page_source).lstrip(file["html_prefix"]).rstrip(file["html_suffix"])\
        .replace("\n","")
    json_object = json.loads(build_info)
    # pdb.set_trace()
    with open(filename["build_info_name"], "w",encoding="utf-8") as fp:
        fp.write(json.dumps(json_object, indent=4, ensure_ascii=False))

    time.sleep(5)
    driver.back()
    time.sleep(5)
    driver.back()
    time.sleep(5)
    # clear_download_file(file)
    host = driver.find_element(By.XPATH,"//*[@id='artifact_page']")
    time.sleep(5)
    driver.execute_script(file["vmlinux_download"], host)

    count=1
    while (not check_download_file("vmlinux", load=1)):
        time.sleep(1)
        count+=1
        if count >1800:
            break

    driver.back()
    host = driver.find_element(By.XPATH,"//*[@id='artifact_page']")
    driver.execute_script(file["vmlinux_symvers_js"], host)
    # driver.implicitly_wait(2)
    host= driver.find_element(By.XPATH,"//*[@id='artifact_view_page']")
    driver.execute_script(file["vmlinux_symvers_download"],host)

    # driver.implicitly_wait(2)
    vmlinux_symvers = str(driver.page_source).lstrip(file["html_prefix"]).rstrip(file["html_suffix"])

    with open(filename["vmlinux_symvers_name"], "w", encoding="utf-8") as fp:
        fp.write(vmlinux_symvers)


def download_imgid(url,file,**filename):

    driver.get(url)
   # driver.implicitly_wait(5)
    time.sleep(5)
    host = driver.find_element(By.XPATH,"//*[@id='artifact_page']")
    driver.execute_script(file["build_info_js"], host)
    # driver.implicitly_wait(5)
    # pdb.set_trace()
    time.sleep(5)
    host = driver.find_element(By.XPATH,"//*[@id='artifact_view_page']")
    driver.execute_script(file["build_info_download"], host)
    # driver.implicitly_wait(5)
    time.sleep(5)
    build_info = str(driver.page_source).lstrip(file["html_prefix"]).rstrip(file["html_suffix"]) \
        .replace("\n", "")
    json_object = json.loads(build_info)
    # pdb.set_trace()
    with open(filename["build_info_name"], "w", encoding="utf-8") as fp:
        fp.write(json.dumps(json_object, indent=4, ensure_ascii=False))

    driver.get(url)
    time.sleep(5)

    host = driver.find_element(By.XPATH,"//*[@id='artifact_page']")
    driver.execute_script(file["vmlinux_download_mv"], host)
    host = driver.find_element(By.XPATH,"//*[@id='artifact_page']")
    # time.sleep()
    driver.execute_script(file["vmlinux_download"], host)

    count = 1
    while (not check_download_file("vmlinux", load=1)):
        time.sleep(1)
        count += 1
        if count > 1800:
            break

    driver.get(url)
    time.sleep(5)

    host = driver.find_element(By.XPATH,"//*[@id='artifact_page']")
    driver.execute_script(file["vmlinux_symvers_mv"], host)

    host = driver.find_element(By.XPATH,"//*[@id='artifact_page']")
    driver.execute_script(file["vmlinux_symvers_js"], host)
    # driver.implicitly_wait(2)
    time.sleep(5)
    host = driver.find_element(By.XPATH,"//*[@id='artifact_view_page']")
    driver.execute_script(file["vmlinux_symvers_download"], host)

    # driver.implicitly_wait(2)
    vmlinux_symvers = str(driver.page_source).lstrip(file["html_prefix"]).rstrip(file["html_suffix"])

    with open(filename["vmlinux_symvers_name"], "w", encoding="utf-8") as fp:
        fp.write(vmlinux_symvers)

def download_img(img_id):
    signed_img_zipfile = "signed-gsi_arm64-img-" + img_id + ".zip"
    qualcomm_img_url = "https://ci.android.com/builds/submitted/" + img_id + "/gsi_arm64-user/latest"
    qualcomm_img_debug_url = "https://ci.android.com/builds/submitted/" + img_id + "/gsi_arm64-userdebug/latest"
    driver.get(qualcomm_img_url)
    driver.maximize_window()
    driver.refresh()
    time.sleep(5)
    clear_download_file(signed_img_zipfile.rstrip(".zip"))
    host = driver.find_element(By.XPATH,"//*[@id='artifact_page']")
    driver.execute_script(bootimg["bootimg_download"], host)
    count = 1
    while (not check_download_file(signed_img_zipfile, load=1)):
        time.sleep(1)
        count += 1
        if count > 1800:
            break
    # time.sleep(180)
    # driver.implicitly_wait(5)


    if os.path.exists("signed-gsi_arm64-img-" + img_id):
        shutil.rmtree("signed-gsi_arm64-img-" + img_id)
        os.mkdir("signed-gsi_arm64-img-" + img_id)
    else:
        os.mkdir("signed-gsi_arm64-img-" + img_id)

    #unzip_cmd = "tar -zxvf " + signed_img_zipfile + " -C " + "signed-gsi_arm64-img-" + img_id
    unzip_cmd = "unzip -o -d " +"signed-gsi_arm64-img-"+img_id+"/ " +signed_img_zipfile
    ret = execute(unzip_cmd, 600)
    # subprocess.Popen(unzip_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ret is True:
        qcom_cp_cmd = "cp " + "signed-gsi_arm64-img-" + img_id + "/boot-5.10.img qcom/boot.img"
        mtk_cp_cmd = "cp " + "signed-gsi_arm64-img-" + img_id + "/boot-5.10-gz.img mtk/boot.img"
        execute(qcom_cp_cmd, 600)
        execute(mtk_cp_cmd, 600)
    
    

    driver.get(qualcomm_img_debug_url)
    driver.maximize_window()
    driver.refresh()
    gsi_img_zipfile = "gsi_arm64-img-" + img_id + ".zip"
    clear_download_file(gsi_img_zipfile.rstrip(".zip"))
    host = driver.find_element(By.XPATH,"//*[@id='artifact_page']")
    driver.execute_script(bootimg["bootimg_download_debug"], host)
    # time.sleep(180)
    count = 1
    while (not check_download_file(gsi_img_zipfile, load=1)):
        time.sleep(1)
        count += 1
        if count > 1800:
            break

    # driver.implicitly_wait(5)

    if os.path.exists("gsi_arm64-img-" + img_id):
        shutil.rmtree("gsi_arm64-img-" + img_id)
        os.mkdir("gsi_arm64-img-" + img_id)
    else:
        os.mkdir("gsi_arm64-img-" + img_id)

   # unzip_cmd = "tar -zxvf " + gsi_img_zipfile + " -C " + "gsi_arm64-img-" + img_id
    unzip_cmd = "unzip -o -d " +"gsi_arm64-img-"+img_id+"/ " +gsi_img_zipfile
    ret = execute(unzip_cmd, 600)
    # subprocess.Popen(unzip_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ret is True:
        qcom_cp_cmd = "cp " + "gsi_arm64-img-" + img_id + "/boot-5.10.img qcom/boot-debug.img"
        mtk_cp_cmd = "cp " + "gsi_arm64-img-" + img_id + "/boot-5.10-gz.img mtk/boot-debug.img"
        execute(qcom_cp_cmd, 600)
        execute(mtk_cp_cmd, 600)
    

if os.path.exists("mtk"):
    shutil.rmtree("mtk")
    print("delete the old mtk path")
    os.mkdir("mtk")
    print("new mtk path")
else:
    os.mkdir("mtk")
if os.path.exists("qcom"):
    shutil.rmtree("qcom")
    print("delete the old qcom path")
    os.mkdir("qcom")
    print("new qcom path")
else:
    os.mkdir("qcom")

id_flg=True
if str(args.gkitag).strip():
    id_flg = False
    if os.path.exists(str(args.gkitag).strip()):
        shutil.rmtree(str(args.gkitag).strip())
        print("delete the old tag path")
        os.mkdir(str(args.gkitag).strip())
        print("new tag path")
    else:
        os.mkdir(str(args.gkitag).strip())
    tag_url = "https://android.googlesource.com/kernel/common/+/refs/tags/" + str(args.gkitag).strip()
    driver.get(tag_url)
    driver.maximize_window()
    driver.refresh()

    clear_download_file("vmlinux")

    # driver.get(url)
    #time.sleep(50)
    herf = driver.find_element(By.XPATH,"/html/body/div/div/pre[1]/a[1]").text
    #img_herf = driver.find_element(By.XPATH,"/html/body/div/div/pre[1]/a[2]").text
    img_herf = driver.find_element(By.XPATH,"/html/body/div/div/pre[1]/a[1]").text
    vmlinux_url = herf + "/vmlinux"
    vmlinux_symvers_url = herf + "/vmlinux.symvers"
    BUILD_INFO_url = herf + "/BUILD_INFO"
    print(BUILD_INFO_url)
    driver.get(BUILD_INFO_url)
    time.sleep(50)
    host = driver.find_element(By.XPATH,"//*[@id='artifact_view_page']")
    driver.execute_script(vmlinux["build_info_download"], host)
    page1=str(driver.page_source)
    print("page1=",page1)
    build_info = str(driver.page_source).lstrip(vmlinux["html_prefix"]).rstrip(vmlinux["html_suffix"]) \
        .replace("\n", "")
    print("build_info=",build_info)
    json_object = json.loads(build_info)
    # pdb.set_trace()
    with open("BUILD_INFO.txt", "w", encoding="utf-8") as fp:
        fp.write(json.dumps(json_object, indent=4, ensure_ascii=False))

    driver.get(vmlinux_url)
    count = 1
    while (not check_download_file("vmlinux", load=1)):
        time.sleep(1)
        count += 1
        if count > 1800:
            break

    driver.get(vmlinux_symvers_url)
    time.sleep(2)
    host = driver.find_element(By.XPATH,"//*[@id='artifact_view_page']")
    driver.execute_script(vmlinux["vmlinux_symvers_download"], host)

    # driver.implicitly_wait(2)
    vmlinux_symvers = str(driver.page_source).lstrip(vmlinux["html_prefix"]).rstrip(vmlinux["html_suffix"])

    with open("vmlinux.symvers.txt", "w", encoding="utf-8") as fp:
        fp.write(vmlinux_symvers)

    shutil.move("BUILD_INFO.txt", str(args.gkitag).strip())
    shutil.move("vmlinux.symvers.txt", str(args.gkitag).strip())
    shutil.move("vmlinux", str(args.gkitag).strip())

    vmlinux_debug_url = vmlinux_url.replace("kernel_aarch64", "kernel_debug_aarch64")
    vmlinux_symvers_debug_url = vmlinux_symvers_url.replace("kernel_aarch64", "kernel_debug_aarch64")
    BUILD_INFO_debug_url = BUILD_INFO_url.replace("kernel_aarch64", "kernel_debug_aarch64")

    driver.get(BUILD_INFO_debug_url)
    time.sleep(2)
    host = driver.find_element(By.XPATH,"//*[@id='artifact_view_page']")
    driver.execute_script(vmlinux_debug["build_info_download"], host)
    build_info = str(driver.page_source).lstrip(vmlinux_debug["html_prefix"]).rstrip(vmlinux_debug["html_suffix"]) \
        .replace("\n", "")
    json_object = json.loads(build_info)
    # pdb.set_trace()
    with open("BUILD_INFO_debug.txt", "w", encoding="utf-8") as fp:
        fp.write(json.dumps(json_object, indent=4, ensure_ascii=False))

    driver.get(vmlinux_debug_url)
    count = 1
    while (not check_download_file("vmlinux", load=1)):
        time.sleep(1)
        count += 1
        if count > 1800:
            break

    driver.get(vmlinux_symvers_debug_url)
    time.sleep(2)
    host = driver.find_element(By.XPATH,"//*[@id='artifact_view_page']")
    driver.execute_script(vmlinux_debug["vmlinux_symvers_download"], host)

    # driver.implicitly_wait(2)
    vmlinux_symvers = str(driver.page_source).lstrip(vmlinux_debug["html_prefix"]).rstrip(vmlinux_debug["html_suffix"])

    with open("vmlinux.symvers_debug.txt", "w", encoding="utf-8") as fp:
        fp.write(vmlinux_symvers)

    if os.path.exists("vmlinux_debug"):
        os.remove("vmlinux_debug")
    os.rename("vmlinux", "vmlinux_debug")

    shutil.move("BUILD_INFO_debug.txt", str(args.gkitag).strip())
    shutil.move("vmlinux.symvers_debug.txt", str(args.gkitag).strip())
    shutil.move("vmlinux_debug", str(args.gkitag).strip())


    img_id = str(re.findall("\d+", str(img_herf))[0])
    temp = str(str(img_herf).split(img_id)[1]).lstrip("/").rstrip("-user/lastest")
    signed_img_zipfile = "signed-" + temp + "-img-" + img_id + ".zip"

    clear_download_file(signed_img_zipfile)
    signed_img_url = img_herf + "/signed/" + signed_img_zipfile


    driver.get(signed_img_url)
    count = 1
    while (not check_download_file(signed_img_zipfile, load=1)):
        time.sleep(1)
        count += 1
        if count > 1800:
            break
    # time.sleep(180)
    # driver.implicitly_wait(5)

    # pdb.set_trace()
    if os.path.exists(signed_img_zipfile.rstrip(".zip")):
        shutil.rmtree(signed_img_zipfile.rstrip(".zip"))
        os.mkdir(signed_img_zipfile.rstrip(".zip"))
    else:
        os.mkdir(signed_img_zipfile.rstrip(".zip"))

    # unzip_cmd = "tar -zxvf " + signed_img_zipfile + " -C " + "signed-gsi_arm64-img-" + img_id
    unzip_cmd = "pwd" + "&&" + "unzip -o -d " + signed_img_zipfile.rstrip(".zip") + "/ " + signed_img_zipfile
    ret = execute(unzip_cmd, 600)
    # subprocess.Popen(unzip_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    boot_img_qcom="boot-"+str(args.gkitag).strip().split("-")[1]+".img"
    boot_img_mtk="boot-"+str(args.gkitag).strip().split("-")[1]+"-gz.img"
    if ret is True:
        # qcom_cp_cmd = "cp " + signed_img_zipfile.rstrip(".zip") + "/boot-5.10.img qcom/boot.img"
        qcom_cp_cmd = "cp " + signed_img_zipfile.rstrip(".zip") + "/" +boot_img_qcom+ " qcom/boot.img"
        # mtk_cp_cmd = "cp " + signed_img_zipfile.rstrip(".zip") + "/boot-5.10-gz.img mtk/boot.img"
        mtk_cp_cmd = "cp " + signed_img_zipfile.rstrip(".zip") + "/" + boot_img_mtk + " mtk/boot.img"
        execute(qcom_cp_cmd, 600)
        execute(mtk_cp_cmd, 600)

    # signed_img_debug_url = signed_img_url.replace("user", "userdebug")
    gsi_img_zipfile = temp + "-img-" + img_id + ".zip"
    img_debug_url =img_herf.replace("user", "userdebug")+"/"+gsi_img_zipfile
    driver.get(img_debug_url)

    # gsi_img_zipfile = temp + "-img-" + img_id + ".zip"
    clear_download_file(gsi_img_zipfile)

    # host = driver.find_element(By.XPATH,"//*[@id='artifact_page']")
    # driver.execute_script(bootimg["bootimg_download_debug"], host)

    while (not check_download_file(gsi_img_zipfile, load=1)):
        time.sleep(1)
        count += 1
        if count > 1800:
            break
    # time.sleep(180)
    # driver.implicitly_wait(5)

    # img_zipfile = "gsi_arm64-img-" + img_id + ".zip"
    if os.path.exists(gsi_img_zipfile.rstrip(".zip")):
        shutil.rmtree(gsi_img_zipfile.rstrip(".zip"))
        os.mkdir(gsi_img_zipfile.rstrip(".zip"))
    else:
        os.mkdir(gsi_img_zipfile.rstrip(".zip"))

    # unzip_cmd = "tar -zxvf " + gsi_img_zipfile + " -C " + "gsi_arm64-img-" + img_id
    unzip_cmd = "unzip -o -d " + gsi_img_zipfile.rstrip(".zip") + "/ " + gsi_img_zipfile
    ret = execute(unzip_cmd, 600)
    # subprocess.Popen(unzip_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if ret is True:
        # qcom_cp_cmd = "cp " + gsi_img_zipfile.rstrip(".zip") + "/boot-5.10.img qcom/boot-debug.img"
        # mtk_cp_cmd = "cp " + gsi_img_zipfile.rstrip(".zip") + "/boot-5.10-gz.img mtk/boot-debug.img"
        qcom_cp_cmd = "cp " + gsi_img_zipfile.rstrip(".zip") + "/" +boot_img_qcom+ " qcom/boot-debug.img"
        mtk_cp_cmd = "cp " + gsi_img_zipfile.rstrip(".zip") + "/" +boot_img_mtk + " mtk/boot-debug.img"
        execute(qcom_cp_cmd, 600)
        execute(mtk_cp_cmd, 600)

    # 移动文件夹示例
    shutil.move("mtk", str(args.gkitag).strip())
    shutil.move("qcom", str(args.gkitag).strip())
    shutil.move(str(args.gkitag).strip(), download_path)


if id_flg==True:
    if str(args.kernelbuildid).strip():
        qki_kernel_dir="qki_"+"kernel_"+str(args.kernelbuildid).strip()
        if os.path.exists(qki_kernel_dir):
            shutil.rmtree(qki_kernel_dir)
            print("delete the old qki path")
            os.mkdir(qki_kernel_dir)
            print("new qki path")
        else:
            os.mkdir(qki_kernel_dir)
        clear_download_file("vmlinux")

        qualcomm_kernel_url="https://ci.android.com/builds/submitted/"+str(args.kernelbuildid).strip()+"/kernel_aarch64/latest"
        qualcomm_kernel_debug_url="https://ci.android.com/builds/submitted/"+str(args.kernelbuildid).strip()+"/kernel_debug_aarch64/latest"
        driver.get(qualcomm_kernel_url)
        driver.maximize_window()
        driver.refresh()
        download(vmlinux,build_info_name="BUILD_INFO.txt",vmlinux_symvers_name="vmlinux.symvers.txt")
        # driver.quit()
        # if os.path.exists("vmlinux1"):
        #     os.remove("vmlinux1")
        # os.rename("vmlinux","vmlinux1")

        shutil.move("BUILD_INFO.txt", qki_kernel_dir)
        shutil.move("vmlinux.symvers.txt", qki_kernel_dir)
        shutil.move("vmlinux", qki_kernel_dir)

        driver.get(qualcomm_kernel_debug_url)
        download(vmlinux_debug,build_info_name="BUILD_INFO_debug.txt",vmlinux_symvers_name="vmlinux.symvers_debug.txt")
        if os.path.exists("vmlinux_debug"):
            os.remove("vmlinux_debug")
        os.rename("vmlinux", "vmlinux_debug")

        # os.rename("temp","vmlinux")

        shutil.move("BUILD_INFO_debug.txt", qki_kernel_dir)
        shutil.move("vmlinux.symvers_debug.txt", qki_kernel_dir)
        shutil.move("vmlinux_debug", qki_kernel_dir)
        shutil.move(qki_kernel_dir, download_path)

        # if os.path.exists("vmlinux_debug"):
        #     os.remove("vmlinux_debug")
        # os.rename("vmlinux","vmlinux_debug")
        # os.rename("vmlinux1","vmlinux")
        # driver.quit()
        # shutil.move("BUILD_INFO.txt", qki_kernel_dir)
        # shutil.move("BUILD_INFO_debug.txt", qki_kernel_dir)
        # shutil.move("vmlinux.symvers.txt", qki_kernel_dir)
        # shutil.move("vmlinux.symvers_debug.txt", qki_kernel_dir)
        # shutil.move("vmlinux", qki_kernel_dir)
        # shutil.move("vmlinux_debug", qki_kernel_dir)

        if str(args.androidbuildid).strip():
            qki_img_dir="qki_"+"img_" + str(args.androidbuildid).strip()
            if os.path.exists(qki_img_dir):
                shutil.rmtree(qki_img_dir)
                print("delete the old qki path")
                os.mkdir(qki_img_dir)
                print("new qki path")
            else:
                os.mkdir(qki_img_dir)
            download_img(str(args.androidbuildid).strip())
            shutil.move("mtk", qki_img_dir)
            shutil.move("qcom", qki_img_dir)

            shutil.move(qki_img_dir, download_path)
        else:
            print("Need img id!!!")
    elif str(args.androidbuildid).strip():
        qki_img_kernel_dir = "qki_" + "img_kernel_" + str(args.androidbuildid).strip()
        if os.path.exists(qki_img_kernel_dir):
            shutil.rmtree(qki_img_kernel_dir)
            print("delete the old qki path")
            os.mkdir(qki_img_kernel_dir)
            print("new qki path")
        else:
            os.mkdir(qki_img_kernel_dir)
        clear_download_file("vmlinux")

        img_url="https://ci.android.com/builds/submitted/"+str(args.androidbuildid).strip()+"/gsi_arm64-user/latest"
        driver.get(img_url)
        download_imgid(img_url,vmlinux_imgid, build_info_name="BUILD_INFO.txt", vmlinux_symvers_name="vmlinux.symvers.txt")

        shutil.move("BUILD_INFO.txt", qki_img_kernel_dir)
        shutil.move("vmlinux.symvers.txt", qki_img_kernel_dir)
        shutil.move("vmlinux", qki_img_kernel_dir)

        # if os.path.exists("vmlinux1"):
        #     os.remove("vmlinux1")
        # os.rename("vmlinux","vmlinux1")
        download_img(str(args.androidbuildid).strip())

        img_debug_url="https://ci.android.com/builds/submitted/"+str(args.androidbuildid).strip()+"/gsi_arm64-userdebug/latest"
        # driver.get(img_debug_url)
        download_imgid(img_debug_url,vmlinux_debug_imgid,build_info_name="BUILD_INFO_debug.txt",vmlinux_symvers_name="vmlinux.symvers_debug.txt")
        if os.path.exists("vmlinux_debug"):
            os.remove("vmlinux_debug")
        os.rename("vmlinux","vmlinux_debug")

        shutil.move("BUILD_INFO_debug.txt", qki_img_kernel_dir)
        shutil.move("vmlinux.symvers_debug.txt", qki_img_kernel_dir)
        shutil.move("vmlinux_debug", qki_img_kernel_dir)

        # shutil.move("BUILD_INFO.txt", qki_img_kernel_dir)
        # shutil.move("BUILD_INFO_debug.txt", qki_img_kernel_dir)
        # shutil.move("vmlinux.symvers.txt", qki_img_kernel_dir)
        # shutil.move("vmlinux.symvers_debug.txt", qki_img_kernel_dir)
        # shutil.move("vmlinux", qki_img_kernel_dir)
        # shutil.move("vmlinux_debug", qki_img_kernel_dir)
        shutil.move("mtk", qki_img_kernel_dir)
        shutil.move("qcom", qki_img_kernel_dir)

        shutil.move(qki_img_kernel_dir, download_path)



driver.quit()









