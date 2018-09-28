# post-Scanning-python-

I implemented a port scanning function that will use nmap to automatically scanned all the ports based on the given IP, and then filtered all open ports, queryed related info such as the infursctrures managers in mySQL, produced a report about the related info, and then notified infursctrures managers via eamil.

项目步骤
1    输入list of IP       公网上1000台左右的设备（wifi router switcher）
     通过nmap 扫描所有IP的所有端口
    
2    过滤掉down的端口    只留下up端口
    输入导入到org 格式的文件    [[ip][port1 port2 ….]]
    org 格式支持正则表达式

3    和MySQL中的数据作比对
        输入IP    查询管理员等相关信息

4    查询信息     导入到excel         import     xlrd    xlmt
            
5    通过SMTP 邮件协议， 邮件自动发送到管理员
        通知管理员异常端口    
       
（正常情况下公网端口应该是不对外提供服务 如果开放的话不正常）
