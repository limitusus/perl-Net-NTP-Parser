package Net::NTP::Parser;

use strict;
use warnings;
use Carp;

use Net::NTP::Parser::TimeStamp64Bit;
#use Smart::Comments;

BEGIN {
    use Exporter ();
    use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
    $VERSION     = '0.01';
    @ISA         = qw(Exporter);
    @EXPORT      = qw();
    @EXPORT_OK   = qw();
    %EXPORT_TAGS = ();
}

# Constant hashes
my $LIs = {
    0 => "No warning",
    1 => "Last minute has 61 seconds",
    2 => "Last minute has 59 seconds",
    3 => "alarm condition",
};
my $Modes = {
    0 => "reserved",
    1 => "symmetric active",
    2 => "symmetric passive",
    3 => "client",
    4 => "server",
    5 => "broadcast",
    6 => "reserved for NTP control message",
    7 => "reserved for private use",
};
# Binary Hash for special characters (console control and escape)
my %binary_hash = (
    "a" => 7,
    "b" => 8,
    "t" => 9,
    "n" => 10,
    "v" => 11,
    "f" => 12,
    "r" => 13,
    "\\" => 92,
);

use Class::Std::Utils;
{
    my %packet_of;
    my %packetsize_of;
    my %LI_of;
    my %VN_of;
    my %Mode_of;
    my %Stratum_of;
    my %Poll_of;
    my %Precision_of;
    my %RootDelay_of;
    my %RootDispersion_of;
    my %ReferenceIdentifier_of;
    my %ReferenceTimestamp_of;
    my %OriginateTimestamp_of;
    my %ReceiveTimestamp_of;
    my %TransmitTimestamp_of;

    sub new {
        my ($class, $raw_msg) = @_;
        my $o = anon_scalar();
        bless ($o, ref ($class) || $class);
        $packet_of{ident $o} = $raw_msg;
        $o->parse if $raw_msg;
        return $o;
    }

    sub DESTROY {
        my $self = shift;
        delete $packet_of{ident $self};
        delete $packetsize_of{ident $self};
        delete $LI_of{ident $self};
        delete $VN_of{ident $self};
        delete $Mode_of{ident $self};
        delete $Stratum_of{ident $self};
        delete $Poll_of{ident $self};
        delete $Precision_of{ident $self};
        delete $RootDelay_of{ident $self};
        delete $RootDispersion_of{ident $self};
        delete $ReferenceIdentifier_of{ident $self};
        delete $ReferenceTimestamp_of{ident $self};
        delete $OriginateTimestamp_of{ident $self};
        delete $ReceiveTimestamp_of{ident $self};
        delete $TransmitTimestamp_of{ident $self};
    }

    sub get_LI {
        return $LI_of{ident shift};
    }

    sub get_VN {
        return $VN_of{ident shift};
    }

    sub get_mode {
        return $Mode_of{ident shift};
    }

    sub get_stratum {
        return $Stratum_of{ident shift};
    }

    sub get_poll {
        return $Poll_of{ident shift};
    }

    sub get_precision {
        return $Precision_of{ident shift};
    }

    sub get_rootdelay {
        return $RootDelay_of{ident shift};
    }

    sub get_rootdispersion {
        return $RootDispersion_of{ident shift};
    }

    sub get_referenceidentifier {
        return $ReferenceIdentifier_of{ident shift};
    }

    sub get_referencetimestamp {
        return $ReferenceTimestamp_of{ident shift};
    }

    sub get_originatetimestamp {
        return $OriginateTimestamp_of{ident shift};
    }

    sub get_receivetimestamp {
        return $ReceiveTimestamp_of{ident shift};
    }

    sub get_transmittimestamp {
        return $TransmitTimestamp_of{ident shift};
    }

    sub parse {
        my $self = shift;
        my $raw_msg = shift || $packet_of{ident $self};
        croak "Can't parse without a target packet message" if !$raw_msg;
        my @bytes = dissolve($raw_msg);
        ### @bytes
        $self->ntp_unpack(@bytes);
    }

    sub dissolve {
        my $msg = shift;
        # Translate raw message into binary
        $msg =~ s{
                     (
                         \\
                         [0-7]{1,3}
                     |
                         \\
                         [abtnvfr\\]
                     |
                         [[:print:]]
                     )
             }{$1 }gxms;
        my @parts = split / /, $msg;
        my @bytes = map {
            if ($_ =~ /\\([0-7]{1,3})/) {
                my $num = "0$1";
                oct $num;
            } elsif ($_ =~ /\\([abtnvfr\\])/) {
                my $key = $1;
                my $val = $binary_hash{$key};
                $val;
            } else {
                ord $_;
            }
        } @parts;
        return @bytes;
    }

    sub ntp_unpack {
        my $self = shift;
        my @bytes = @_;
        $packetsize_of{ident $self} = scalar @bytes;
        $LI_of{ident $self} = ($bytes[0] >> 6) & 0x3;
        $VN_of{ident $self} = ($bytes[0] >> 3) & 0x7;
        $Mode_of{ident $self} = $bytes[0] & 0x7;
        $Stratum_of{ident $self} = $bytes[1];
        $Poll_of{ident $self} = $bytes[2];
        $Precision_of{ident $self} = $bytes[3] > 127
            ? $bytes[3] - (2 ** 8) : $bytes[3];

        use bignum;
        my $RootDelay = ($bytes[4] << 8 | $bytes[5])
            + ($bytes[6] << 8 | $bytes[7]) * (2 ** -16);
        if (($bytes[4] >> 7) & 1) { # Negative value
            $RootDelay -= 2 ** 32;
        }
        $RootDelay_of{ident $self} = $RootDelay;
        my $RootDispersion = ($bytes[8] << 8 | $bytes[9])
            + ($bytes[10] << 8 | $bytes[11]) * (2 ** -16);
        $RootDispersion_of{ident $self} = $RootDispersion;
        no bignum;
        # TODO
        my $ReferenceIdentifier = ($bytes[12] << 24) | ($bytes[13] << 16)
            | ($bytes[14] << 8) | $bytes[15];
        $ReferenceIdentifier_of{ident $self} = $ReferenceIdentifier;
        $ReferenceTimestamp_of{ident $self} = new Net::NTP::Parser::TimeStamp64Bit(@bytes[16..23]);
        $OriginateTimestamp_of{ident $self} = new Net::NTP::Parser::TimeStamp64Bit(@bytes[24..31]);
        $ReceiveTimestamp_of{ident $self} = new Net::NTP::Parser::TimeStamp64Bit(@bytes[32..39]);
        $TransmitTimestamp_of{ident $self} = new Net::NTP::Parser::TimeStamp64Bit(@bytes[40..47]);
    }

    sub dump_ntp {
        my $ntp = shift;
        for my $k (keys %$ntp) {
            print "## $k $ntp->{$k}\n";
        }
        print "PacketSize: $ntp->{PacketSize}\n";
        print "LI: $ntp->{LI} ($LIs->{$ntp->{LI}})\n";
        print "VN: $ntp->{VN}\n";
        print "Mode: $ntp->{Mode} ($Modes->{$ntp->{Mode}})\n";
        print "Stratum: $ntp->{Stratum}\n";
        print "Poll: $ntp->{Poll}\n";
        print "Precision: 2 ** $ntp->{Precision} seconds\n";
        print "Root Delay: $ntp->{RootDelay}\n";
        print "Reference Identifier: $ntp->{ReferenceIdentifier}\n";
        print "Reference Timestamp: " . $ntp->{ReferenceTimestamp}->get_timestring . "\n";
        print "Originate Timestamp: " . $ntp->{OriginateTimestamp}->get_timestring . "\n";
        print "Receive Timestamp: " . $ntp->{ReceiveTimestamp}->get_timestring . "\n";
        print "Transmit Timestamp: " . $ntp->{TransmitTimestamp}->get_timestring . "\n";
    }

}


=head1 NAME

Net::NTP::Parser - Reads an NTP packet and inspects it

=head1 SYNOPSIS

  use Net::NTP::Parser;
  # stringified 48 bytes NTP packet
  my $packet = q{#\4\6\351\0\0\0\212\0\0\vG\n4\n\310\324\215~\361\324,}
    . q{\261\177\324\215\1775\322xaR\324\215\1775\322\344:2\324\215\177v}
    . q{\323\335\224\35};
  my $ntp = Net::NTP::Parser->new($pack);
  $ntp->dump;
  # Leap Indicator
  $ntp->get_LI;
  # Version Number
  $ntp->get_VN;
  # Mode
  $ntp->get_mode;
  # Stratum
  $ntp->get_stratum;
  # Poll Interval (power of 2)
  $ntp->get_poll;
  # Precision (power of 2)
  $ntp->get_precision;
  # Root Delay
  $ntp->get_rootdelay;
  # Root dispersion
  $ntp->get_rootdispersion;
  # Reference Identifier
  $ntp->get_referenceidentifier;
  # Reference Timestamp
  $ntp->get_referencetimestamp;
  # Originate Timestamp
  $ntp->get_originatetimestamp;
  # Receive Timestamp
  $ntp->get_receivetimestamp;
  # Transmit Timestamp
  $ntp->get_transmittimestamp;

=head1 DESCRIPTION

This module reads a stringified packet of SNTP and give interfaces to read it for human.

The input is intended to be from strace(1) command like:

  strace -e trace=network -s 4096 ntpdate ntp1.jst.mfeed.ad.jp

will output the following:

  sendto(4, "\343\0\4\372\0\1\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\324\220$\32j\222-\224", 48, 0, {sa_family=AF_INET, sin_port=htons(123), sin_addr=inet_addr("210.173.160.27")}, 16) = 48
  recvfrom(4, "$\2\4\355\0\0\0\21\0\0\0027\322\255\240V\324\220#\330*!\303S\324\220$\32j\222-\224\324\220$\32e\224f\317\324\220$\32e\225\241\37", 1092, 0, {sa_family=AF_INET, sin_port=htons(123), sin_addr=inet_addr("210.173.160.27")}, [16]) = 48

The above packets are of RFC 2030 but is not human-readable.
This module receives a stringified packet like above "\343 ... \224" (48 bytes) and provides an OO interface to see the values.


=head1 USAGE

See SYNOPSIS.

=head1 BUGS

This module expects a "valid" packet data. The behaviour is unknown if the input is wrong.

=head1 SUPPORT

Send email to limitusus [at] cpan [dot]. Pull request at github will be of course welcome.
  https://github.com/limitusus/perl-Net-NTP-Parser

=head1 AUTHOR

    limitusus
    CPAN ID: LIMITUSUS
    limitusus@cpan.org
    https://github.com/limitusus/

=head1 COPYRIGHT

This program is free software licensed under the...

	The MIT License

The full text of the license can be found in the
LICENSE file included with this module.


=head1 SEE ALSO

RFC 2030.

=cut

1;
