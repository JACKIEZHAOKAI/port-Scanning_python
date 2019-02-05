# post-Scanning-python-

I implemented a port scanning function that will use nmap to automatically scanned all the ports based on the given IP, and then filtered all open ports, queryed related info such as the infursctrures managers in mySQL, produced a report about the related info, and then notified infursctrures managers via eamil.

Steps:
1    read a list of IP address from files, including 1000+ network infrustructures from public net.

2    applied Nmap to scan all ports of the above IP address

3    filtered out all the ports that are turned down. Left the ports in UP status
     and output the result in the format of  [[ip][port1 port2 ….]]
     
4    compared with network infrustructures database (MYSQL)
     Given an IP address, query the info of network administrator
     output info into excel   

5    applied SMTP email protocol to send files to network administrator
     to detect network anomaly. (Reguraly, public network ports should NOT provide service)
