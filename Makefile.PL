use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Net::NTP::Parser',
    VERSION_FROM => 'lib/Net/NTP/Parser.pm', # finds \$VERSION
    AUTHOR       => 'limitusus (limitusus@cpan.org)',
    ABSTRACT     => 'Reads an NTP packet and inspects it',
    PREREQ_PM    => {
                     'Test::Simple' => 0.44,
                     'DateTime' => 0,
                     'Class::Std::Utils' => 0,
                    },
);
