# coding=utf-8
import os
import datetime
import re         #regular expression
import pymysql
import xlwt
import xlrd

import smtplib    # reg in to send email
import time
import requests
import socket

#import telnet2
import random
import schedule

# email module, construct email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.header import Header

today_is = datetime.datetime.now().strftime('%F')

'''
-sS　 SYN扫描，只完成三次握手前两次，很少有系统记入日志，默认使用，需要root(admin)权限
-A　  全面系统监测，使用脚本检测，扫描等
-v　  显示扫描过程，推荐使用
-iL　 批量扫描，读取主机列表，如[-iL  C:\ip.txt]
-T4　 针对TCP端口禁止动态扫描延迟超过10ms
-oG   输出扫描结果为grep文件
'''


# 定期扫描任务，生成扫描结果xml和扫描log文件
def nmap_Scanner():
    filename = 'yhsip.txt'
    result = os.system("nmap -v -A -T4 -iL %s -oG result_%s.org"%(filename,today_is))
    print(result)

# 从nmap输出结果中提取对应ip/port信息
def collect_info():
    filename = 'result_%s.org'%(today_is)
    os.system("awk '/open/' %s  >>  result_%s.txt"%(filename,today_is))
    f1 = open('result_%s.txt'%(today_is),'r')
    f2 = open('ip_port_result_%s.txt'%(today_is),'w')
    for line in f1.readlines():
        h = re.compile(r'Host: \b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b').\
            findall(line)
        p = re.compile(r'[0-9]*/open').findall(line)
        print >> f2, (h, p)
    f1.close()
    f2.close()


# 将f2文件ip数据与数据库ip数据进行对比，获取admin
def com_mysql():
    # 连接数据库
    conn = pymysql.connect(
        host='localhost',
        port=3306,
        user='admin123',
        password='123456Qw!',
        db='ipdata',
        charset='utf8mb4')

    # 创建游标
    cursor = conn.cursor()

    file1 = open('final_log_%s.txt'%(today_is), 'w')
    f2 = open('ip_port_result_%s.txt' % (today_is), 'r')
    for line in f2.readlines():
        h = re.compile(r'Host: \b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b').findall(line)
        p = re.compile(r'[0-9]*/open').findall(line)
        host_ip = str(h)
        host_port = str(p)
        host_ip = host_ip.replace('Host: ', '')[2:-2]
        effect_row = cursor.execute("select Platform,Admin,Email from Iptables where Public_NET = \"%s\"" % (host_ip))
        Admin = cursor.fetchone()
        if not Admin:
            print >> file1, (host_ip, "is not found!!!Port:", host_port)
        else:
            print >> file1, (Admin, host_ip, host_port)
    conn.commit()
    cursor.close()
    conn.close()
    f2.close()

#将最终结果存入excel表
def create_xls():
    f1 = open('final_log_%s.txt'%(today_is), 'r')

    f2 = xlwt.Workbook(encoding='utf-8', style_compression=0)
    sheet = f2.add_sheet('test', cell_overwrite_ok=True)
    sheet.write(0, 0, "平台")
    sheet.write(0, 1, "管理员")
    sheet.write(0, 2, "邮箱")
    sheet.write(0, 3, "IP")
    sheet.write(0, 4, "端口")
    a = 0

    for line in f1.readlines():
        line = line.split()
        a = a + 1
        for i in range(len(line)):
            # 转换打印所属平台
            if i == 0:
                line[i] = line[i][2:-1]
                if line[i] == "u'\u4fe1\u606f\u5b89\u5168\u5e73\u53f0\u7f51\u7edc\u8bbe\u5907'":
                    line[i] = "信息安全平台网络设备"
                    print(line[i])
                    sheet.write(a, i, line[i])
                    s1 = line[i]
                elif line[i] == "u'WIFI\u5e73\u53f0'":
                    line[i] = "WIFI平台"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'163\u540e\u53f0'":
                    line[i] = "163后台"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'PDSN'":
                    line[i] = "PDSN"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'HACCG'":
                    line[i] = "HACCG"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'AAA'":
                    line[i] = "AAA"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u6821\u56ed\u7f51'":
                    line[i] = "校园网"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'DACS'":
                    line[i] = "DACS"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'163\u5927\u540e\u53f0\u7f51\u7edc\u8bbe\u5907'":
                    line[i] = "163大后台网络设备"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[
                    i] == "u'\u4e92\u8054\u7f51\u4e13\u7ebf\u4fe1\u606f\u5b89\u5168\u7cfb\u7edf\u7f51\u7edc\u8bbe\u5907'":
                    line[i] = "互联网专线信息安全系统网络设备"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u4e92\u8054\u7f51\u4e13\u7ebf\u4fe1\u606f\u5b89\u5168\u7cfb\u7edfCU\u8bbe\u5907'":
                    line[i] = "互联网专线信息安全系统CU设备"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'VPDNLNS'":
                    line[i] = "VPDN LNS"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u7eff\u901a\u4e1a\u52a1'":
                    line[i] = "绿通业务"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u4e92\u8054\u7f51\u4e13\u7ebf\u4fe1\u606f\u5b89\u5168\u7cfb\u7edfEU\u8bbe\u5907'":
                    line[i] = "互联网专线信息安全系统EU设备"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'WIFI\u5e73\u53f0\uff08\u4e3b\u673a\uff09'":
                    line[i] = "WIFI平台（主机）"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'4G\u6838\u5fc3\u7f51'":
                    line[i] = "4G核心网"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u79fb\u52a8\u6838\u5fc3\u7f51\u7efc\u5408\u7f51\u7ba1'":
                    line[i] = "移动核心网综合网管"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'WAP\u7f51\u5173'":
                    line[i] = "WAP网关"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'VPDNAAA\u5e73\u53f0'":
                    line[i] = "VPDNAAA平台"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u79fb\u52a8DPI\u5e73\u53f0'":
                    line[i] = "移动DPI平台"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u63a5\u5165\u7f51'":
                    line[i] = "接入网"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u7701\u53f7\u767eWIFI\u63a7\u5236\u5668AC\u5e73\u53f0\u7f51\u7edc\u8bbe\u5907'":
                    line[i] = "省号百WIFI控制器AC平台网络设备"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u4fe1\u606f\u5b89\u5168\u5e73\u53f0\u670d\u52a1\u5668'":
                    line[i] = "信息安全平台服务器"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u56fa\u7f51DPI'":
                    line[i] = "固网DPI"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'AAA\u7f51\u7edc\u8bbe\u5907'":
                    line[i] = "AAA网络设备"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'HACCG\u7f51\u7edc\u8bbe\u5907'":
                    line[i] = "HACCG网络设备"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u63a5\u5165\u7f51'":
                    line[i] = "接入网"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'DACS\u7f51\u7edc\u8bbe\u5907'":
                    line[i] = "DACS网络设备"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u6821\u56ed\u7f51AAA\u7f51\u7edc\u8bbe\u5907'":
                    line[i] = "校园网AAA网络设备"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u878d\u5408\u9632\u706b\u5899'":
                    line[i] = "融合防火墙"
                    print(line[i])
                    sheet.write(a, i, line[i])
                else:
                    sheet.write(a, i, line[i])
                    print(line[i], "not exist")
            elif i == 1:
                line[i] = line[i][:-1]
                if line[i] == "u'\u97e6\u5c11\u6797'":
                    line[i] = "韦少林"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u8c2d\u5dcd'":
                    line[i] = "谭巍"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u6731\u715c\u6587'":
                    line[i] = "朱煜文"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u6234\u9ad8\u8fdc'":
                    line[i] = "戴高远"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u738b\u5b87\u822a'":
                    line[i] = "王宇航"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u738b\u6625\u96e8'":
                    line[i] = "王春雨"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u5b89\u51ac\u840d'":
                    line[i] = "安冬萍"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u4f55\u6e0a\u6587'":
                    line[i] = "何渊文"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u9648\u4ef2\u6807'":
                    line[i] = "陈仲标"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u7530\u5c0f\u51b0'":
                    line[i] = "田小冰"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u8d56\u5fd7\u658c'":
                    line[i] = "赖志斌"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u9648\u5a49\u6708'":
                    line[i] = "陈婉月"
                    print(line[i])
                    sheet.write(a, i, line[i])
                elif line[i] == "u'\u51af\u5f66\u73b2'":
                    line[i] = "冯彦玲"
                    print(line[i])
                    sheet.write(a, i, line[i])
                else:
                    print("%s is not exist."%(line[i]))
                    sheet.write(a, i, line[i])
            elif i == 2:
                line[i] = line[i][2:-3]
                sheet.write(a, i, line[i])
            elif i == 3:
                line[i] = line[i][1:-2]
                sheet.write(a, i, line[i])
            else:
                sheet.write(a, i, line[i])

    f1.close()
    f2.save(r'%s_log.xls'%(today_is))


# 二次确认
def check2():
    smtpserver = 'smtp.qq.com'
    username = '895779392@qq.com'
    password = 'ybodkyhpvhqubeba'
    sender = '895779392@qq.com'
    subject = '端口服务开放提醒邮件'

    f = xlrd.open_workbook('%s_log.xls'%(today_is))
    table = f.sheet_by_name(u'test')
    table_name = table.name
    cols = table.ncols
    rows = table.nrows

    for i in range(1, rows - 1):
        Platform_data = table.cell(i, 0).value
        Admin_data = table.cell(i, 1).value
        Email_data = table.cell(i, 2).value
        IP_data = table.cell(i, 3).value
        host = IP_data
        receiver = Email_data
        msg = MIMEMultipart('mixed')
        msg['Subject'] = subject
        msg['From'] = '895779392@qq.com'
        msg['To'] = receiver
        msg['Date'] = today_is

        for a in range(4, cols):
            Port_data = table.cell(i, a).value
            p = re.compile(r"\d+\.?\d*").findall(Port_data)
            port = str(p)[3:-2]
            if port!='':
                port = int(port)
                print(host,port,receiver) 
                
                #web service   nodejs call to open browser
                if port > 79 and port < 100:
                    url = 'http://' + host + ':' + str(port) + '/'
                    filename = random.randrange(10000, 100000, 5)
                    try:
                        rep = requests.get(url, timeout=10)
                        if rep.status_code < 500:
                            os.system("node webtojpg1.js %s %s" % (url, filename))
                            time.sleep(5)
                            # 构造附件
                            sendImage = open(r'%s.jpg' % (filename), 'rb')
                            msgImage = MIMEImage(sendImage.read())
                            msgImage.add_header('Content-ID', '<image1>')
                            msg.attach(msgImage)
                            text = u"%s，请注意！平台：%s，IP：%s，开放端口：%s" % (Admin_data, Platform_data, IP_data, port)
                            body = """
                                    <h5>%s</h5>
                                    <img src="cid:image1"/>
                                   """ % (text)
                            msg.attach(MIMEText(body, 'html', 'utf-8'))
                            smtp = smtplib.SMTP()
                            smtp.connect(smtpserver)
                            smtp.login(username, password)
                            smtp.sendmail(sender, receiver, msg.as_string())
                            smtp.close()
                            time.sleep(60)
                            sendImage.close()
                            print 'Send email success!'
                    except:
                        print 'check2 failed.'

                # web service 
                elif port > 8000 and port < 10000:
                    url = 'http://' + host + ':' + str(port) + '/'
                    filename = random.randrange(10000, 100000, 5)
                    try:
                        rep = requests.get(url, timeout=10)
                        if rep.status_code < 500:
                            os.system("node webtojpg1.js %s %s" % (url, filename))
                            time.sleep(5)  # screen shot time 
                            
                            # start processing email
                            sendImage = open(r'%s.jpg' % (filename), 'rb')
                            msgImage = MIMEImage(sendImage.read())
                            msgImage.add_header('Content-ID', '<image1>')
                            msg.attach(msgImage)
                            
                            text = u"%s，请注意！平台：%s，IP：%s，开放端口：%s" % (Admin_data, Platform_data, IP_data, port)
                            # HTML format 
                            body = """
                                   <h1> hello world </h1>
                                   
                                   <h5>%s</h5>
                                   
                                   <img src="cid:image1"/>
                                   """%(text)
                            msg.attach(MIMEText(body,'html','utf-8'))  
                            smtp = smtplib.SMTP()
                            smtp.connect(smtpserver)
                            smtp.login(username, password)
                            smtp.sendmail(sender, receiver, msg.as_string())
                            smtp.close()
                           
                            time.sleep(60)
                            sendImage.close()
                            print 'Send email success!'
                    except:
                        print 'check2 failed.'

                        
                else: # 其他端口 
                    try:
                        tt = telnet2.Telnet(host, port, 10)
                        msg1 = tt.listener()
                        if "denied" in msg or "closed" in msg:
                            print '%s,%s, failed' % (host, port)
                        else:
                            text = u"%s，请注意！平台：%s，IP：%s，开放端口：%s" % (Admin_data, Platform_data, IP_data, port)
                            text_plain = MIMEText(text, 'plain', 'utf-8')
                            msg.attach(text_plain)
                            smtp = smtplib.SMTP()
                            smtp.connect(smtpserver)
                            smtp.login(username, password)
                            smtp.sendmail(sender, receiver, msg.as_string())
                            smtp.close()
                            time.sleep(60)  #  空格间隙 邮箱发送过于频繁
                            print 'Send email success!'
                    except:
                        print 'check2 failed.'

#def job():
#    nmap_Scanner()
#    collect_info()
#    com_mysql()
#    create_xls()
#    check2()
#    print 'Finshed!'

#schedule.every().day.at("01:00").do(job)

#while True:
#    schedule.run_pending()

if __name__ == '__main__':
    #nmap_Scanner()
    #collect_info()
    #com_mysql()
    #create_xls()
    check2()
