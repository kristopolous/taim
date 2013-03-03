#!/usr/bin/perl
#-------------------------------------
# t - apache front end script for taim
# 	(C) 2007 Chris McKenzie
#	http://qaa.ath.cx
#
# 	All rights reserved.
#-------------------------------------

# My vx8300 gives an XID as a UID
use CGI qw(:standard);
use IO::Socket;

print "Content-type:	text/html\n\n";

my $g_server_host = "10.0.0.5";
my $g_server_port = 19091;
my $g_server_handle;
my $g_server_message_out;

my @g_shortcuts = ( "a", "e", "i", "k", "o", "s", "t", "x" );
my $g_timeout = 1;
my $g_return = "";

my $g_input_uid = param("h");
my $g_input_message = param("i");
my $g_input_user = param("u");
my $g_input_pass = param("p");

sub ServerConnect
{
	$g_server_handle = new IO::Socket::INET
	(
		PeerAddr => $g_server_host,
		PeerPort => $g_server_port,
		Proto => 'tcp'
	);
}
	
sub ServerGetUid
{
	ServerConnect();

	if($g_server_handle)
	{
		print $g_server_handle "uid\n";
		$g_input_uid = <$g_server_handle>;
	}
}

sub ServerQuery
{
	ServerConnect();
	
	if($g_server_handle)
	{
		print $g_server_handle $g_server_message_out."\n";
	}
}

sub ServerGetData
{
	my $ix = 0;
	my $list;

	sleep $g_timeout;

	ServerConnect();

	$g_return .= "<pre>";

	if($g_server_handle)
	{
		print $g_server_handle "get ".$g_input_uid."\n";
	
		while($list = <$g_server_handle>)
		{
			if( ! ($list =~ m/^\[/) )
			{
				$g_return .= $g_shortcuts[$ix].".";
				$ix++;
			}
			$list =~ s/<br>/\n/g;
			$list =~ s/<[^>]+>//g;
			$g_return .= $list;
		}
	}
}

sub FormatOutput
{
	$g_return .= "<form action=t>";

	if(! $g_server_handle)
	{
		$g_return .= "Unable to contact server ".$g_server_host.":".$g_server_port."\n";
	}
	else
	{	
		if(param("h") eq "")
		{
			$g_return .= "<pre>user<input name=u>\n";
			$g_return .= "pass<input type=password name=p>\n";
		}
		else
		{
			$g_return .= "<input name=i>";
		}
	}

	$g_return .= "<input type=hidden name=h value=".$g_input_uid.">";
	$g_return .= "<input type=submit>";
}

if($g_input_uid eq "")
{
	ServerGetUid();
}
else
{
	if($g_input_user ne "")
	{
		$g_server_message_out = "user ".$g_input_uid." ".$g_input_user."\n";
		ServerQuery();
	
		$g_server_message_out = "pass ".$g_input_uid." ".$g_input_pass."\n";
		ServerQuery();

		sleep 2;
	}	
	elsif($g_input_message ne "")
	{	
		if($g_input_message =~ m/^\./)
		{
			$g_server_message_out = $g_input_message;
			$g_server_message_out =~ s/^.//;
			$g_server_message_out =~ s/!/$g_input_uid/;
		}
		else
		{
			$g_server_message_out = "send ".$g_input_uid." ".$g_input_message;
		}

		ServerQuery();
	}
		
	ServerGetData();
}

FormatOutput();

print $g_return;
