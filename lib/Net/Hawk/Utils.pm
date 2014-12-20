package Net::Hawk::Utils;
use strict;
use warnings;
use 5.010;

sub parse_content_type {
    my ($header) = @_;
    return '' unless defined $header;

    my ($ret) = $header =~ m{^\s*(\S+?)\s*(;|$)};
    return lc($ret);
}

1;
