# -*- perl -*-

# t/002_load.t - check module loading and create testing directory

use Test::More tests => 2;

BEGIN { use_ok( 'Net::NTP::Parser::TimeStamp64Bit' ); }

# Packet with length of 8
my @p = (0, 0, 0, 0, 0, 0, 0, 0);
my $object = Net::NTP::Parser::TimeStamp64Bit->new(@p);
isa_ok ($object, 'Net::NTP::Parser::TimeStamp64Bit');
