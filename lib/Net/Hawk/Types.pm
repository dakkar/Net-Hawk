package Net::Hawk::Types;
use strict;
use warnings;
use 5.010;
use Type::Library
    -base,
    -declare => qw(Algorithm);
use Type::Utils -all;
use Types::Standard qw(Str Enum);

declare Algorithm, as Enum[qw(sha1 sha256)];

1;

