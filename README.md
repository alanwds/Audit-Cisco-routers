# Audit-Cisco-routers
Script to compliance check on cisco routers

What is it?

Audit-Cisco-routers is a script to get info from cisco routers and compair with security params (Compliance check). 
Each param will be checked and, if was ok it will be setted as "Conforme", else, will be setted as "Nao conforme".
The script write the output in a local log file (check_router.log) and by syslog

My main goal when I developed this tool was to identify security issues in a pool of routers.

License and author

This application is distributed under the GNU license.

Contact the author at alanwds@gmail.com

Dependency, Library and Environment:

Audit-Cisco-routers has been tested in the following environment:

#Perl 5.0 

Depends:

Running the Application

1 - Install Perl 5.0 or higher

2 - Install depends:


3 - Edit the file (attackReport_en.py ) according your Peakflow Appliance

4 - ./attackReport_en.py
