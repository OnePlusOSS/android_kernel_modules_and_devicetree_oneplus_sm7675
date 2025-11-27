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
import urllib.request


download_path="download"
parser = argparse.ArgumentParser(description='manual to this script')
parser.add_argument('--gkitag', type=str, help='android kernel common refs tag android for mtk')
args = parser.parse_args()

options = webdriver.ChromeOptions()
prefs = {"download.default_directory":os.getcwd(),'safebrowsing.enabled': False,}
options.add_experimental_option("prefs", prefs)

driver  = webdriver.Chrome(options)
driver.implicitly_wait(20)

vmlinux={"build_info_download":"return arguments[0].shadowRoot.querySelector('artifact-viewer')"
                          ".shadowRoot.querySelector('div.artifact-header > div.buttons-container > a > huckle-button')"
                               ".shadowRoot.querySelector('button').click()",
         "html_prefix":"'name=\"color-scheme\" content=\"light dark\"></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">",
         "html_suffix":"</pre></body></html>",
         "vmlinux_symvers_download":"return arguments[0].shadowRoot.querySelector('artifact-viewer')"
              ".shadowRoot.querySelector('div.artifact-header > div.buttons-container > a > huckle-button').click()"
        }

def download_build_info(BUILD_INFO_url):
    driver.get(BUILD_INFO_url)
    time.sleep(10)
    host = driver.find_element(By.XPATH,"//*[@id='artifact_view_page']")
    driver.execute_script(vmlinux["build_info_download"], host)
    page1=str(driver.page_source)
    #print("page1=",page1)
    build_info = str(driver.page_source).lstrip(vmlinux["html_prefix"]).rstrip(vmlinux["html_suffix"]) \
        .replace("\n", "")
    #print("build_info=",build_info)
    json_object = json.loads(build_info)
    with open("BUILD_INFO.txt", "w", encoding="utf-8") as fp:
        fp.write(json.dumps(json_object, indent=4, ensure_ascii=False))

    time.sleep(5)
    driver.back()
    time.sleep(5)
    driver.back()

def download_vmlinux_symvers(vmlinux_symvers_url):
    driver.get(vmlinux_symvers_url)
    time.sleep(2)
    host = driver.find_element(By.XPATH,"//*[@id='artifact_view_page']")
    driver.execute_script(vmlinux["vmlinux_symvers_download"], host)
    vmlinux_symvers = str(driver.page_source).lstrip(vmlinux["html_prefix"]).rstrip(vmlinux["html_suffix"])
    with open("vmlinux.symvers.txt", "w", encoding="utf-8") as fp:
        fp.write(vmlinux_symvers)

def check_download_file(f, load=1):
    time.sleep(int(load))
    file_list = os.listdir(os.getcwd())
    if f in file_list:
        return True
    else:
        return False

def download_vmlinux(vmlinux_url):
    time.sleep(5)
    driver.get(vmlinux_url)
    count=1
    while (not check_download_file("vmlinux", load=1)):
        time.sleep(1)
        count+=1
        if count >1800:
            break
    driver.back()

def download_boot_img(url,boot):
    time.sleep(5)
    boot_url = url + "/" + boot
    print(boot_url)
    driver.get(boot_url)
    count=1
    while (not check_download_file(boot, load=1)):
        time.sleep(1)
        count+=1
        if count >1800:
            break

    driver.back()

def init_env():
    if os.path.exists(download_path):
        shutil.rmtree(download_path)
        print("delete the old download path")
        os.mkdir(download_path)
        print("new download path")
    else:
        os.mkdir(download_path)

    if os.path.exists(str(args.gkitag).strip()):
        shutil.rmtree(str(args.gkitag).strip())
        print("delete the old tag path")
        os.mkdir(str(args.gkitag).strip())
        print("new tag path")
    else:
        os.mkdir(str(args.gkitag).strip())

init_env()

if str(args.gkitag).strip():
    tag_url = "https://android.googlesource.com/kernel/common/+/refs/tags/" + str(args.gkitag).strip()
    print(tag_url)
    driver.get(tag_url)
    driver.maximize_window()
    driver.refresh()

    herf = driver.find_element(By.XPATH,"/html/body/div/div/pre[1]/a[1]").text
    vmlinux_url = herf + "/vmlinux"
    vmlinux_symvers_url = herf + "/vmlinux.symvers"
    BUILD_INFO_url = herf + "/BUILD_INFO"
    print(vmlinux_url)
    print(vmlinux_symvers_url)
    print(BUILD_INFO_url)
    download_build_info(BUILD_INFO_url)
    download_vmlinux_symvers(vmlinux_symvers_url)
    download_boot_img(herf,"boot.img")
    download_vmlinux(vmlinux_url)
    #url = herf +  "/boot.img"
    #save_path = 'boot.img'
    #urllib.request.urlretrieve(url, save_path)

    #url = herf +  "/vmlinux"
    #save_path = 'vmlinux'
    #urllib.request.urlretrieve(url, save_path)

time.sleep(10)
driver.quit()









