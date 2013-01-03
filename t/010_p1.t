# -*- perl -*-

# t/010_p1.t - check module loading and create testing directory

use Test::More tests => 14;

BEGIN { use_ok( 'Net::NTP::Parser' ); }

my $packet = q{#\4\6\351\0\0\0\212\0\0\vG\n4\n\310\324\215~\361\324,}
    . q{\261\177\324\215\1775\322xaR\324\215\1775\322\344:2\324\215\177v}
    . q{\323\335\224\35};
my $object = Net::NTP::Parser->new($packet);

is $object->get_LI, 0, "Leap Indicator";
is $object->get_VN, 4, "Version Number";
is $object->get_mode, 3, "Mode";  # Client
is $object->get_stratum, 4, "Stratum";
is $object->get_poll, 6, "Poll";
is $object->get_precision, -23, "Precision";
# Here values must exactly same
use bignum;
is $object->get_rootdelay, 0.002105712890625, "Root Delay";
is $object->get_rootdispersion, 0.0440521240234375, "Root Dispersion";
is $object->get_referenceidentifier, 171182792, "Reference Identifier";
no bignum;
isa_ok $object->get_referencetimestamp, "Net::NTP::Parser::TimeStamp64Bit";
isa_ok $object->get_originatetimestamp, "Net::NTP::Parser::TimeStamp64Bit";
isa_ok $object->get_receivetimestamp, "Net::NTP::Parser::TimeStamp64Bit";
isa_ok $object->get_transmittimestamp, "Net::NTP::Parser::TimeStamp64Bit";
