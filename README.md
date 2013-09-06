bastille-mon
============

Perl daemon to monitor bastille firewall logs and lock abusive ips through ip tables 

some project from way back in 2007

http://sourceforge.net/projects/bastille-mon/




Linux Bastille Monitor  (Bastille-mon) Created by Vahid Hedayati July 2007
This program  is written in perl and requires a few perl modules:
(INSTALL script will try and install below for you)
Sys::Syslog;
Net::SMTP;
Net::Whois::IP;
IPTables::IPv4;


This works with Bastille firewall and stores various configuration in 
/etc/Bastille

It can easily be modified to work with any firewall please read further down 
look for configuration file and chain settings.

Running as a daemon it monitors /var/log/messages(configurable) 
for bastille iptables dropped logs as well as PSAD scan alerts, 
it has a threshold for TCP/UDP as well as PSAD (view cfg file).

It will block ip on iptables instantly, send email to abuse contact of IP 
and store the even in /etc/Bastille/bastille-mon.run.

................................................................................
INSTALLATION
................................................................................
To install simply run ./INSTALL.sh as root.

This installation will also check to make sure you have all relevant
perl modules, if not it will try and install them for you.

................................................................................
AFTER INSTALL
................................................................................
Once it is all installed please remember 
to edit /etc/init.d/bastille-firewall (line 88) and add:
sh  /etc/Bastille/bastille-mon.run

it will look like
......
  start|restart|reload)
      if [ $bretval -eq 0 ]; then touch $LOCKFILE; fi
      sh  /etc/Bastille/bastille-mon.run
......
................................................................................
Description of files installed.
................................................................................
Starting/Stopping :
/etc/init.d/bastille-mon.sh {start|stop}

Configuration File:
/etc/Bastille/bastille-mon.cfg

Allowed Hosts: 
/etc/Bastille/allowed-hosts

This lets you define Work / Friends ips to ignore

as part of allowed-hosts /usr/local/bastille-mon/update-ignorelist.sh 
is run each time bastille-mon is started.
This does a last  and adds all ip's in last to allowed-host
if you wish to disable this feature comment out of /etc/init.d/bastille-mon.sh 
or edit update-ignorelist and define last for a specific user or something i.e. 
last freddie where freddie = useracount of person that logs in.

Trusted UDP/TCP Ports:
/etc/Bastille/allowed-udp
/etc/Bastille/allowed-tcp
Please ensure you put in port numbers one port per line 
in the above files for any ports 
that you may think are not a threat and you dont wish to ban IP's over.
In my case used to have tcp 8180 open in the past 
and so search engines/results still hit it and I dont wish to report 
users for doing this so 8180 is in my allowed-tcp file.

Log Files:
/var/log/fw-actioned.log
This is a result of all the blocks made by bastille-mon 

/etc/Bastille/bastille-mon.run
Containts all iptables rules to be run when bastille-firewall is started
I have added a whole bunch of South East Asian Attackers  listed in:
http://www.tatsukichi.gr.jp
feel free to wipe all this by running:
>/etc/Bastille/bastille-mon.run
(only before first usage unless you wish you own blocklist)

Latest Port Mapping:
/etc/Bastille/ports.txt 
this uses wget to get latest version of ports.txt and used within email sent. 
with details of  what the port name is that was being hit.
Please run once in a blue moon (make sure you have wget installed)
or enable in startup script currently hashed out.
/usr/local/bastille-mon/get-latest-ports.sh
