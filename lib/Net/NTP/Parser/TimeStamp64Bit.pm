package Net::NTP::Parser::TimeStamp64Bit;

use strict;
use warnings;
use Carp;
use Data::Dumper;
use DateTime;

BEGIN {
    use Exporter ();
    use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
    $VERSION     = '0.01';
    @ISA         = qw(Exporter);
    #Give a hoot don't pollute, do not export more than needed by default
    @EXPORT      = qw();
    @EXPORT_OK   = qw();
    %EXPORT_TAGS = ();
}

use Class::Std::Utils;
{
    my %bytes_of;
    my %MSB_of;
    my %utc_of;
    my %fraction_of;

    sub new {
        my $class = shift;
        my @args = @_;
        my $o = anon_scalar();
        croak "Invalid Data" if @args != 8;
        $bytes_of{ident $o} = \@args;
        return bless $o, $class;
    }

    sub DESTROY {
        my $self = shift;
        delete $bytes_of{ident $self};
        delete $MSB_of{ident $self};
        delete $utc_of{ident $self};
        delete $fraction_of{ident $self};
    }

    sub get_MSB {
        return $MSB_of{ident shift};
    }

    sub get_utc {
        return $utc_of{ident shift};
    }

    sub get_fraction {
        return $fraction_of{ident shift};
    }

    sub _get_bytes {
        return $bytes_of{ident shift};
    }

    sub get_scalar {
        my $self = shift;
        my @ts = @{$bytes_of{ident $self}};
        my $integer = ($ts[0] << 24)
            | ($ts[1] << 16)
                | ($ts[2] << 8)
                    | ($ts[3]);
        my $fraction = ($ts[4] << 24)
            | ($ts[5] << 16)
                | ($ts[6] << 8)
                    | ($ts[7]);
        use bignum;
        $fraction *= 2 ** -32;
        my $ts = $integer + $fraction;
        no bignum;
        return $ts;
    }

    sub get_timestring {
        my $self = shift;
        my @ts = @{$bytes_of{ident $self}};
        # Pick the MSB
        $MSB_of{ident $self} = ($ts[0] & 0x80) >> 7;
        # NTP Timestamp Format convention in RFC 2030
        my $basedatetime = $MSB_of{ident $self}
            ? DateTime->new(year => 1900, month => 1,
                            hour => 0, minute => 0, second => 0,
                            time_zone => "UTC")
                : DateTime->new(year => 2036, month => 2, day => 7,
                                hour => 6, minute => 28, second => 16,
                                time_zone => "UTC");
        my $seconds = ($ts[0] << 24)
            | ($ts[1] << 16)
                | ($ts[2] << 8)
                    | ($ts[3]);
        my $delta = DateTime::Duration->new(seconds => $seconds);
        my $utc = $basedatetime->add_duration($delta);
        use bignum;
        my $fraction = ($ts[4] << 24)
            | ($ts[5] << 16)
                | ($ts[6] << 8)
                    | ($ts[7]);
        $fraction *= 2 ** -32;
        no bignum;
        $utc_of{ident $self} = $utc;
        $fraction_of{ident $self} = $fraction;
        return $utc . " + " . $fraction . " seconds";
    }
}

1;

=head1 NAME

Net::NTP::Parser::TimeStamp64Bit - RFC 2030-based timestamp module

=head1 AUTHOR

    limitusus
    CPAN ID: LIMITUSUS
    limit.usus@gmail.com
    https://github.com/limitusus/

=head1 COPYRIGHT

This program is free software licensed under the...

	The MIT License

The full text of the license can be found in the
LICENSE file included with this module.

=cut
