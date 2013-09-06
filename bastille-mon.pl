#!/usr/bin/perl 

#####################################################
#bastille-mon.pl - monitors bastille firewall logs  #
#configured in /etc/Bastille/bastille-mon.cfg       #
#Written by Vahid Hedayat July 2007                 #
#####################################################

use strict;
use Sys::Syslog;
use Net::SMTP;
use Net::Whois::IP;
use IPTables::IPv4; 
use File::Tail;

our ($tcp_max,$udp_max,$psad_max,$dir,$domain,$from,$knownhosts,$knownudp,$knowntcp,$failedto,$smtphost);
our ($watchfile,$iptables,$ports,$PIDFILE,$logfile,$egrep,$cfgfile,$chain,$daemonize);

my $config=$ARGV[0];
my $defaultconf="/etc/Bastille/bastille-mon.cfg";
if ($config eq '') { $config=$defaultconf; }

#Run through config 
open (CONFIG,"$config")|| die "Could not open $config file\n";
while (<CONFIG>) {
    chomp;                  # no newline
    s/#.*//;                # no comments
    s/^\s+//;               # no leading white
    s/\s+$//;               # no trailing white
    next unless length;     # anything left?
    my ($var, $value) = split(/\s*=\s*/, $_, 2);
    no strict 'refs';
    $$var = $value;
}
close(CONFIG);

#Global Variables
my ($times,$dates,$years,$line,$value,$val,$blk_ips);
my ($ip,@getport,$block,$result);
my %blocked=();    # already blocked ip's
my ($to,$subject,$body);
my %validip=();
my %validtcp=();
my %validudp=();

#Read in known hosts ports
mass_open($knownhosts);
mass_open($knowntcp);
mass_open($knownudp);

#open up ports file - which contains port mapping so that it can report what port they were snooping.

#SMTP body message change this if you wish... to suite you
$body .="Dear Sir/Madam \nPlease remain calm, this is results that was either a port scan [instant block], ";
$body .="or connections to 3+ closed ports.";
$body .="For safety purposes  I have blocked IP from this host, could you please ";
$body .="investigate as to why your IP address tried to attempt connections to this host,";
$body .=" logs are provided below:\n";

#If damoenize set in configure bastille-mon will run as daemon - defaults should be on
if ($daemonize) {
    my $pid = fork();
    if ($pid) {
        # My PID rests in $pid
        open(PID,">$PIDFILE") or die("Unable to open PID file: $!\n");
        print PID "$pid\n";
        close PID;
        exit;
    } else {
        close(STDIN);
        close(STDOUT);
    }
}

#Open the log file to write messages to for what application does.

#Run the bastille-mon
&find_hackers();

#Nothing to touch below accept - one line you can enable under TCP for port 22 so that it sets it to max count straight away
#would only advise this if you run ssh on a different port and have 22 as a trap. (line 138)

sub find_hackers {
 my %tail = (
     name => $watchfile,
     maxinterval => 10,
     interval => 5,
     adjustafter => 3,
     tail => -1,
  );

  my $tai = File::Tail->new(%tail);
  my $psad_pattern1 = '(.*) (.*) (.*) (.*) psad: scan detected: (.*) \-\> (.*) tcp: \[(.*)\] flags: (.*) tcp pkts: (.*) DL: (.*)';
  my $psad_pattern2 = '(.*) (.*) (.*) (.*) psad: scan detected: (.*) \-\> (.*) udp: \[(.*)\] udp pkts: (.*) DL: (.*)';
  my $psad_pattern3 = '(.*) (.*) (.*) (.*) psad: src: (.*) signature match: "(.*)" \(sid: (.*)\) (.*) port: (.*)';
  my $tcp_pattern = '(.*) (.*) (.*) (.*) kernel: ([^<]*)MAC=(.*) SRC=(.*) DST=(.*) LEN=(.*) TOS=([^<]*)PROTO=(.*) SPT=(.*) DPT=(.*) WINDOW=(.*) RES=(.*) ([^<]*) URGP=(.*)';
  my $udp_pattern = '(.*) (.*) (.*) (.*) kernel: ([^<]*)MAC=(.*) SRC=(.*) DST=(.*) LEN=(.*) TOS=([^<]*)ID=(.*) PROTO=(.*) SPT=(.*) DPT=(.*) LEN=(.*)';
  my %tries=();      # number of attempts per ip

  open(IPTPIPE, "$iptables -L -n|");
  my $blockChain=0;
  my $go="0";
  while (<IPTPIPE>){
    if ($_ =~ /Chain $chain([^<]*)/) { $go="1"; }
      if ($go) {
         $blockChain=1 if (/DROP/);
          next unless $blockChain;
	  last if (/^$/ );
	  $blocked{$1}=1 if (/(\d+\.\d+\.\d+\.\d+)/);
	  $blocked{$1}=1 if (/(\d+\.\d+\.\d+\.\d+\/\d+)/);
      }
   }
  close IPTPIPE;

  $blk_ips=join(",",keys(%blocked));
  syslog('warning',"$0 started. currently blocked ip's are: $blk_ips");
  # watch the messages file

  while (1) {
    my @rest="";
    my ($month, $day,$time,$ig,$sip,$tsrcip,$usrcip,$p1srcip,$p2srcip,$p3srcip,$dst,$length,$length2,$tos,$proto,$spt,$dpt,$win,$res,$urg,$pkt,$match,$type,$bod);
    #my $sip="";
    $_ = $tai->read;
    chomp($_);

    if ($tcp_pattern) {
       ($month,$day,$time,$ig,$ig,$ig,$tsrcip,$dst,$length,$tos,$proto,$spt,$dpt,$win,$res,$urg)= $_  =~ /$tcp_pattern/;
    }elsif ($udp_pattern) {
       ($month,$day,$time,$ig,$ig,$ig,$usrcip,$dst,$length,$tos,$proto,$ig,$spt,$dpt,$length2)= $_  =~ /$udp_pattern/;
    }elsif ($psad_pattern1) {
       ($month,$day,$time,$ig,$p1srcip,$dst,$proto,$ig,$pkt,$ig) = $_ =~ /$psad_pattern1/;
    }elsif ($psad_pattern2) {
       ($month,$day,$time,$ig,$p2srcip,$dst,$proto,$ig,$pkt,$ig) = $_ =~ /$psad_pattern2/;
    }elsif ($psad_pattern3) {
       ($month,$day,$time,$ig,$p3srcip,$proto,$ig,$pkt,$dst) = $_ =~ /$psad_pattern3/;
    }


   if (($tsrcip) || ( $usrcip))  { 
     if($tsrcip){$sip=$tsrcip;}elsif($usrcip){$sip=$usrcip;}

     chomp($sip);
     $sip=~ s/^\s+//;
     $sip=~ s/\s+$//;
     next if defined($validtcp{$dpt});
     next if defined($validip{$sip});
     next if defined($blocked{$sip});
     &make_date();
     #USERS ENABlE THIS IF YOUR RUN  SSH ON ANOTHER PORT AND TREAT 22 AS SUSPISCIOUS LOCKS AFTER 1 ATTEMPT
     if ($dpt eq '22') { $tries{$sip}+=3; } else { $tries{$sip}+=1; }
     if ($tries{$sip} eq $tcp_max){
       $block=&add_iptable(chain=>"$chain", source=>$sip, jump=>"DROP");
       if ($block eq 'YES') {
         $subject="$domain Bastille-Mon TCP Port Attack $time (CET) $day-$month-$years $sip -> $dpt";
         $blocked{$sip}=1;
         $bod .="3 ATTEMPTS FROM $sip last attempt was:\n\n";
         @rest=`grep $sip $watchfile|$egrep \"($chain|psad)\"`;
         $bod .="@rest\n";
         $to = get_whois($sip) || '';
	 &send_log("$times $dates -- $day-$month:$time BLOCKED_TCP IP=$sip:$spt -> $dpt  -> $to ");
         $bod .="$times $dates Incidence Occured @ $day-$month:$time (CET) BLOCK TCP CONNECTION ";
         $bod .="IP=$sip:$spt -> DEST:$dst:$dpt USING:$proto \n";

       }   
       if (($block eq 'NO') && ($to eq '')) {
       } elsif (($block eq 'YES') && ($to eq '')) {
         syslog('warning',"$dates $times $0 blocked_TCP $sip\n");
       } else {
         &send_email($from,$to,$subject,$body.$bod);
         syslog('warning',"$dates $times $0 blocked_TCP $sip\n");
       }
     }


  }elsif (($p1srcip)|| ($p2srcip) || ($p3srcip)) {
      if($p1srcip){$sip=$p1srcip;}elsif($p2srcip){$sip=$p2srcip;} elsif($p3srcip){$sip=$p3srcip;}
      chomp($sip);
      $sip=~ s/^\s+//;
      $sip=~ s/\s+$//;
      next if defined($validip{$sip});
      next if defined($blocked{$sip});
      $tries{$sip}+=1;
      if ($tries{$sip} eq $psad_max){
        $block=&add_iptable(chain=>"$chain", source=>$sip, jump=>"DROP");
        if ($block eq 'YES') {
         $blocked{$sip}=1;
         &make_date();
         $subject="$domain Bastille-Mon PSAD attack  TCP Port SCAN $time (CET) $day-$month-$years $sip ->  $dst:$proto -  $pkt";
         $to = get_whois($sip) || '';
         &send_log("$times $dates -- $day-$month:$time BLOCKED_PSAD_SCAN >$sip< -> $proto - $pkt -> $to");
         $bod .="$dates $times BLOCKED PSAD ATTACK  $time (CET) $day-$month-$years PSAD SCANN : $sip to $dst:$proto -> $pkt ";
         $bod .="\nACTUAL LOGS:\n";
         @rest=`grep $sip $watchfile|$egrep \"($chain|psad)\"`;
         $bod .="@rest\n";
        }
        if (($block eq 'NO') && ($to eq '')) {
        } elsif (($block eq 'YES') && ($to eq '')) {
          syslog('warning',"$dates $times $0 blocked_PSAD_SCAN $sip\n");
        } else {
          &send_email($from,$to,$subject,$body.$bod);
          syslog('warning',"$dates $times $0 blocked_PSAD_SCAN $sip\n");
        }
      }



    }
  }
 }


sub get_whois {
  ($ip)=@_;
  my $email="";
  my $response = whoisip_query($ip);
  foreach (sort keys(%{$response}) ) {
    if (( $_ =~ /email/) || ($_ =~ /e-mail/) || ($_ =~ /mailbox/) ) {
       $email=$response->{$_};
       chomp($email);
           
       
    }
  }
   if ($email=~ /(.*)\@(.*)/) { 
       return ($email);
   }else {
     return ($failedto);
    }
}


sub make_date {
 my @months = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');
 my ($secs,$mins,$hours,$mdays,$mons,$years,$wdays) = (localtime(time))[0,1,2,3,4,5,6];
   $times = sprintf("%02d:%02d:%02d",$hours,$mins,$secs);
  $years +=1900;
   $dates = "$mdays $months[$mons] $years";
  $wdays="";
}

sub send_email {
     my $smtp = Net::SMTP->new("$smtphost");
     my ($frm,$tt,$sub,$bod)=@_;
     $smtp->mail("$frm");
     if ($to =~ /\,/) { 
       $smtp->to(split(/,/, $to));
     }else{
        $smtp->to("$tt");
     }
     $smtp->data();
     $smtp->datasend("subject: $sub\n\n");
     $smtp->datasend("$tt\n");
     $smtp->datasend("$bod\n\n\n");
     $smtp->datasend("Download Bastille-mon from http://sourceforge.net/projects/bastille-mon\n"); 
     $smtp->dataend();
     $smtp->quit;
     return "OK";
     #sleep 5;
}


	   

sub mass_open {
  my  ($file)=@_;
   open (FILE,"<$file");
   while (<FILE>) {
   if ($_ =~ /^#/) {} else {
     $val=$_;
     chomp($val);
     if ($file=~ /([^<]*)allowed-hosts/) {
        $validip{$val}=1;
     }elsif  ($file=~/([^<]*)allowed-udp/) {
        $validtcp{$val}=1;
     }elsif  ($file=~/([^<]*)allowed-udp/) {
        $validudp{$val}=1;
     }
   }
  }
 }


sub add_iptable {
  my $state="";
  use IPTables::IPv4;
  my (%rule) = @_;
  my ($table, $output);
  $table = IPTables::IPv4::init('filter');
   my $srcip=$rule{'source'};
   $state="NO" if defined($blocked{$srcip});
    if ($state eq 'NO') {
    } else {
      $table->append_entry($rule{'chain'}, { source=>$rule{'source'}, jump=>$rule{'jump'} });
      $table->commit();
      open (FILE,">>$cfgfile");
      print FILE "$iptables -I $chain -s $rule{'source'} -j DROP\n";
      close(FILE);
      $state="YES";    
    }
     return "$state";
}

sub send_log {
   my ($input)=@_;
   open (LOGFILE,">>$logfile");
   print LOGFILE "$input\n";
   close (LOGFILE);
}    

