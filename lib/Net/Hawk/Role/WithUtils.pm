package Net::Hawk::Role::WithUtils;
use strict;
use warnings;
use 5.010;
use Package::Variant
    importing => ['Moo::Role'],
    subs => ['has'];
use Types::Standard 1.000003 qw(HasMethods);

sub make_variant {
    my ($class,$target_package,@methods) = @_;

    has _utils => (
        is => 'ro',
        (@methods ? ( isa => HasMethods[@methods] ) : () ),
        init_arg => 'utils',
        default => sub {
            require Net::Hawk::Utils;
            Net::Hawk::Utils->new;
        },
    );
}

1;
