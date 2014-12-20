package Net::Hawk::Role::WithCrypto;
use strict;
use warnings;
use 5.010;
use Package::Variant
    importing => ['Moo::Role'],
    subs => ['has'];
use Types::Standard 1.000003 qw(HasMethods);

sub make_variant {
    my ($class,$target_package,@methods) = @_;

    has _crypto => (
        is => 'ro',
        (@methods ? ( isa => HasMethods[@methods] ) : () ),
        init_arg => 'crypto',
        default => sub {
            require Net::Hawk::Crypto;
            Net::Hawk::Crypto->new;
        },
    );
}

1;
