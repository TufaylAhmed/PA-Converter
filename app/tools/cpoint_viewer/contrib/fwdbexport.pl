#!/usr/local/bin/perl
##############################################################################
# fwdbexport.pl:
#              extracts the groups ans users from fwauth.NDB in csv
#              format to standard out
#              generates a users.fws for use with the *local mode
#              of the policy editor
#
# Copyright (C) 2000 Christian Port
# 
# thanks to:
#  Sean O'Neill
#  Stefan Moser
#  anonymous programmer
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
###########################################################
#
# Juny 2000
# v1.3
#     - have received a large userdatabase
#       fixed a bug with a counter
# March 2000
# v 1.2
#     -Fixed a major Bug in decoding
#
# February 2000
# v 1.1
#     - Fixed a bug
#          all names were extracted lowercase
#
# February 2000
# v 1.0
#   there was need for the decoding of the fwauth.NDB
#   I have made it
#
#############################################################################

#
# Used modules
#
use Getopt::Long;

#
# Defaults, Constants
#
$SCR_NAME="fwdbexport";
$VERSION="1.4";
$TRUE = 1;
$FALSE = 0;
@days=(MON,TUE,WED,THU,FRI,SAT,SUN);

$INPUT_FILE="fwauth.NDB";
$OUTPUT_FILE="users.fws";
@user_fields=(name, color, groups, destinations, sources, auth_method, fromhour, tohour, expiration_date, days, accept_track, internal_password, SKEY_seed, SKEY_number, SKEY_passwd, SKEY_gateway, comments, radius_server, vlan_auth_list, userc, expire, isakmp.transform, isakmp.data.integrity, isakmp.encryption, isakmp.methods, isakmp.encmethods, isakmp.hashmethods, isakmp.authmethods, tacacs_server, SKEY_method);
@group_fields=(name, groups, color, comments);
$delimiter=";\t";


# Parse and process options
if (!GetOptions(\%optctl, 'groups|g', 'input|i=s', 'output|o=s', 'attr|a=s', 'delimiter|d=s', 'help', 'version')
    || $optctl{help} == 1 || $optctl{version} == 1 || @ARGV > 0)
{
	if ($optctl{version} == 1)
	{
		print STDERR "$SCR_NAME version $VERSION\n";
	}
	else
	{
		usage();
	}

	exit;
}


if($optctl{groups}==1){
  @fields=@group_fields;
}else{
  @fields=@user_fields;
}

$OUTPUT_FILE=$optctl{output} if(defined($optctl{output}));
$INPUT_FILE=$optctl{input} if(defined($optctl{input}));
$delimiter=$optctl{delimiter} if(defined($optctl{delimiter}));

# Parse attribute fields
if (defined($optctl{'attr'}))
{
  @attr = split(/,/, lc($optctl{'attr'}));
  foreach $field (@attr)
  {
    if (!grep(/^$field$/, @fields))
    {
       die "invalid attribute field specified: $field\n";
    }
  }
  @fields = @attr;
}

# open input and seek to start of data
open(DAT, "<$INPUT_FILE") || die "can't open $INPUT_FILE\n";
if(!seek(DAT, 12288, 0)){
  print "file to short(1)\n";
  exit;
}

# read header
die "file to short(2)\n" if(read(DAT, $tmp, 256) < 256);
#structur: ?,?,startblock,number of blocks
($sh,$sl,$bh,$bl)=unpack("x2CCCC", $tmp);
$StartBlk=$sh*256+$sl;
$NumBlocks=$bh*256+$bl;

# read NumBlocks in array
$i=1;
while(read(DAT, $tmp, 256)){
  $block[$i]=$tmp;
  $i++
}
close(DAT);

# parse blocks and write records in textfile
open(OUT, ">$OUTPUT_FILE") || die "can't open $OUTPUT_FILE\n";
print OUT "(\n\t";
for($i=1;$i<=$NumBlocks;$i++){
  ($st,$nh,$nl)=unpack("C3", $block[$i]);
  $next=($st&127)*65536+$nh*256+$nl;
  if($st & 128){    # first bit in block marks a new record
    ($st,$nh,$nl,$ihh,$ih,$il,$chh,$ch,$cl,$type)=unpack("C3x3C2C3C3C", $block[$i]);
    $ilen=$ih*256+$il; # len of record name
    $clen=$chh*65536+$ch*256+$cl; # len of record content
    $glen=$clen+$ilen; # len of whole record
    $llen=$clen; # num of bytes to read
    if($glen>243){
      $llen=243-$ilen;
      $rlen=$clen-$llen;
    } else {
      if($next) {
        print STDERR "error 1 in Block $i\n";
        $next=0;
      }
    }
    $index=unpack("x13 a$ilen", $block[$i]);
    $cont=unpack("x13 x$ilen a$llen", $block[$i]);
    $content=": $cont";
    # going through the chain until end
    while($next){
      $llen=$rlen;
      if($rlen>253){
        $llen=253;
        $rlen-=253;
      }
      ($st,$nh,$nl,$cont)=unpack("C3a$llen", $block[$next]);
      $curr=$next;
      $next=($st&127)*65536+$nh*256+$nl;
      if($next && ($llen < 253)) {
        $next=0;
        print STDERR "error 2 in Block $curr ($next:$llen)\n";
      }
      $content.=$cont;
    }
    $content=~s/\n/\n\t/g;
    print OUT "$content";
  }
}
print OUT ")";

# read users.fws and assign to hash
close(OUT);
open(OBJECTS, "<$OUTPUT_FILE") || die "can't open $OUTPUT_FILE\n";
process_objects(\%user);
close(OBJECTS);

# maybe we have found some illegal chars
print stderr join("\n", keys(%Errors));
print stderr "\n";

# print csv
print join "$delimiter", @fields;
print "\n";
if($optctl{groups}){
  foreach $i (keys %user){
    next if($user{$i}[1]{type}[1]!~m/usrgroup/); # only groups
    next if(!defined($user{$i}[1]{color})); # predefined groups have no color
    print_group(\%{$user{$i}[1]},$i);
  }
}else{
  foreach $i (keys %user){
    next if($user{$i}[1]{type}[1]!~m/user/); # only user
    print_user(\%{$user{$i}[1]});
  }
}

# print contents of a user record
sub print_user{
  my ($hash) = @_;
  my ($i,@res,$key);
  foreach $key (@fields){
    print_key($hash, $key);
  }
  print "\n";
}

# print contents of a user record
sub print_group{
  my ($hash,$name) = @_;
  my ($i,@res,$key);
  foreach $key (@fields){
    if($key=~/name/){    # name is not a field of the record
      print "$name;\t";  # taking recordname instead
      next;
    }
    print_key($hash, $key);
  }
  print "\n";
}

# print the content of a field
sub print_key{
  my ($hash,$key) = @_;
  my(@res);
  if(defined($$hash{$key})){
    if(defined($$hash{$key}[2])){  # is this key a hash?
      if($$hash{$key}[1]{members}[1]){ # has it members?
        print "{".$$hash{$key}[1]{members}[1]."}";
      }
      else{  # no members but a hash
        foreach $i (keys(%{$$hash{$key}[1]})){ # nessesary for group membership
          next if($i=~/members/); # ignore the member mark
          next if($i=~/accept_track/); # ignore the accept_track hash (from userc)
          if(!defined($$hash{$key}[1]{$i}[2])){ # nessesary for userc
            push @res, $$hash{$key}[1]{$i}[1];
          }else{
            push @res, $$hash{$key}[1]{$i}[0];
          }
        }
        if(@res){ # print the results
          print "{".join(',', @res);
          print "}";
        }
      }
    }
    else{  # not a hash
      if($key=~/^days$/){ # special for days
        $days=$$hash{$key}[1];
        for($i=0;$i<8;$i++){
          push @res, $days[$i] if($days & (1<<$i));
        }
        if(@res){
          print "{".join(',', @res);
          print "}";
        }
      }
      else{
        print "$$hash{$key}[1]";
      }
    }
  }
  print "$delimiter";
}


sub process_objects
{
	my ($hash,$name) = @_;

	while (<OBJECTS>)
	{
		chop;
		s/^\s+//;
		s/\011+//;

		return if (/^\)$/);

                # check for irregular chars
                if(/[‰ˆ¸ƒ÷‹ﬂ]/){
                  $Errors{"Error in $name: $_"}="";
                }
		if (/^\:([^\s]*) \(([^\)]*)$/)
		{
			# This branch recursively handles 'open' lines, i.e. lines
			# that do not end in a ')'
			# e.g. ': (CSFB-mgmt-server'

			$key = $1; $key2 = $2;

			#	  if ($key2 eq '')
			#	    {
			#	      $key2 = $key;
			#    	    }

			if ($key eq '')
			{
				$key = $key2;
			}
			if ($key2 eq '')
			{
				$key2 = $key;
			}

			#$lcKey = lc($key2);
			$lcKey = lc($key);
			$$hash{$lcKey}[0] = $key2;
			$$hash{$lcKey}[2] = $key;
			process_objects(\%{$$hash{$lcKey}[1]},$key);
		}
		elsif (/^\:([^\s]*) (.*)$/)
		{
			# This branch recursively handles 'closed' lines, i.e. lines
			# that end in a ')'
			# e.g. ':comments ("London Management Server")'

			$key = $1; $value = $2;

			if ($key eq '')
			{
				# Group members
				$key = 'members';
			}

			$lcKey = lc($key);
			$$hash{$lcKey}[0] = $key;

			if ($$hash{$lcKey}[1] ne '')
			{
				$$hash{$lcKey}[1] .= ', ';
			}

			if ($value =~ /^\((.*)\)$/)
			{
				$value = $1;
			}

			if ($value =~ /^\"(.*)\"$/)
			{
				$value = $1;
			}
	  
			$$hash{$lcKey}[1] .= $value;
		}
	}
}

sub usage
{
  print STDERR <<EOF
usage: $SCR_NAME [options]
       $SCR_NAME --help
       $SCR_NAME --version

options:
   --groups: print out groups instead of users

   --input=<input file>: Location of output file.
          Default is fwauth.NDB.

   --output=<output file>: Location of output file.
          Default is users.fws (as needed in *local mode).

   --attr=<attr-list>: List of attributes to include in the csv output.
          See also 'type-list' below.

   --delimiter=<delimiter>: specify delimiter

   all options can also be specifyed ba the first letter with one dash 

   attr-list: comma-separated list of attributes

   user attributes:
     name, color, groups, destinations, sources, auth_method, fromhour, tohour,
     expiration_date, days, accept_track, internal_password, SKEY_seed, SKEY_number,
     SKEY_passwd, SKEY_gateway, comments, radius_server, expire, SKEY_method

   group attributes:
     name, groups, color, comments
EOF
}

