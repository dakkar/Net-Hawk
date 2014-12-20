package Net::Hawk::Utils;
use strict;
use warnings;
use Time::HiRes qw(gettimeofday);
use 5.010;
use Moo;

sub parse_content_type {
    my ($self,$header) = @_;
    return '' unless defined $header;

    my ($ret) = $header =~ m{^\s*(\S+?)\s*(;|$)};
    return lc($ret);
}

sub now_msecs {
    my ($self,$offset_ms) = @_;

    my ($sec,$usec) = gettimeofday;
    return $sec + int($usec/1000) + $offset_ms//0;
}

sub now_secs {
    my ($self,$offset_ms) = @_;

    return int(now_msecs($offset_ms)/1000);
}

1;
