# -*- perl -*-

# t/020_time.t

use Test::More tests => 3;

BEGIN { use_ok( 'Net::NTP::Parser::TimeStamp64Bit' ); }

# RFC2030-formatted 852.5625 seconds
my @p = (0x00, 0x00, 0x03, 0x54, 0x90, 0x00, 0x00, 0x00);
my $object = Net::NTP::Parser::TimeStamp64Bit->new(@p);
isa_ok ($object, 'Net::NTP::Parser::TimeStamp64Bit');

my $ans = 852.5625;
is $object->get_scalar, $ans;
