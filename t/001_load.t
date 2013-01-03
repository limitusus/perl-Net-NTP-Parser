# -*- perl -*-

# t/001_load.t - check module loading and create testing directory

use Test::More tests => 2;

BEGIN { use_ok( 'Net::NTP::Parser' ); }

my $object = Net::NTP::Parser->new();
isa_ok ($object, 'Net::NTP::Parser');
