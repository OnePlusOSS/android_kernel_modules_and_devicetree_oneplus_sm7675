import time
from selenium import webdriver
from selenium.webdriver.common.by import By

# 指定webdriver的路径
chrome_path = r"F:\goki\chrome-win64\chrome-win64\chrome.exe" # 请将其替换为在您的系统上chromedriver可执行文件的正确路径
#driver_path = "F:\goki\chrome-win64\chrome-win64\chrome.exe"
chrome_path = "F:\goki\driver\chrome-win64\chrome-win64\chrome.exe"

options = webdriver.ChromeOptions()
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

driver  = webdriver.Chrome( options)
# 创建webdriver对象
#driver = webdriver.Chrome("F:\goki\driver\chrome-win64\chrome-win64\chrome.exe")
#driver = webdriver.Chrome()
# 使用webdriver访问指定网页
driver.get("https://android-review.googlesource.com/c/kernel/common/+/2291734")
#driver.get("https://www.baidu.com")
url = driver.current_url    # 本行用于获取当前页面的url，即百度首页地址
print(url)
driver.maximize_window()


title = driver.title  # 获取当前页面title
print(title)

#title = driver.description  # 获取当前页面title
#print(title)

#driver.find_element(By.ID, 'kw').send_keys('selenium')  #搜索框输入selenium
#driver.find_element(By.ID, 'su').click()     # 点击百度一下
#url = driver.find_element(By.CLASS_NAME, 'changeCopyClipboard')
#print(url)
#river.find_element(By.CLASS_NAME, ' pg-app ')
driver.find_element(By.ID, 'mainHeader')

driver.forward()
#time.sleep(5)
driver.back()
driver.refresh()
#time.sleep(5)
driver.forward()

#driver.find_element_by_xpath("//*[@id='artifact_page']")
#username_input = driver.find_element_by_name("username")
#password_input = driver.find_element_by_name("password")
#username_input.send_keys("your_username")
#password_input.send_keys("your_password" + Keys.RETURN)


#driver.find_element（"id","username")

driver.minimize_window()  # 最小化窗口
driver.maximize_window()  # 最大化窗口
#driver.fullscreen_window() # 全屏窗口
# 添加更多的代码以与网页交互
time.sleep(40)
# 当你完成所有操作后，记得关闭driver
#driver.close()
