package Net::Hawk::Types;
use strict;
use warnings;
use 5.010;
use Type::Library
    -base,
    -declare => qw(Algorithm HTTPHeaders);
use Type::Utils -all;
use Types::Standard qw(Str Enum HashRef ArrayRef);

declare Algorithm, as Enum[qw(sha1 sha256)];

class_type HTTPHeaders, { class => 'HTTP::Headers' };
coerce HTTPHeaders,
    from HashRef, via { require HTTP::Headers; HTTP::Headers->new(%$_) },
    from ArrayRef, via { require HTTP::Headers; HTTP::Headers->new(@$_) },
    ;

1;

