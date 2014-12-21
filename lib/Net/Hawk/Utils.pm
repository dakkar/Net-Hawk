package Net::Hawk::Utils;
use strict;
use warnings;
use Time::HiRes qw(gettimeofday);
use 5.010;
use Moo;
use Types::Standard 1.000003 qw(Str Int Object ArrayRef Optional Undef);
use Types::URI qw(Uri);
use Type::Params qw(compile);
use Net::Hawk::Errors;

sub parse_content_type {
    state $argcheck = compile(Object,Str|Undef);
    my ($self,$header) = $argcheck->(@_);
    return '' unless defined $header;

    my ($ret) = $header =~ m{^\s*(\S+?)\s*(;|$)};
    return lc($ret);
}

sub now_msecs {
    state $argcheck = compile(Object,Int);
    my ($self,$offset_ms) = $argcheck->(@_);

    my ($sec,$usec) = gettimeofday;
    return $sec + int($usec/1000) + $offset_ms//0;
}

sub now_secs {
    state $argcheck = compile(Object,Int);
    my ($self,$offset_ms) = $argcheck->(@_);

    return int(now_msecs($offset_ms)/1000);
}

sub parse_authorization_header {
    state $argcheck = compile(Object,Str|Undef,Optional[ArrayRef]);
    my ($self,$header,$keys) = $argcheck->(@_);
    $keys //= [qw(id ts nonce hash ext mac app dlg)];
    my %valid_keys; @valid_keys{@$keys}=();

    Net::Hawk::Errors::UnAuthorized->throw(message=>'no header')
          unless $header;
    my ($attr_string) = $header =~ m{^hawk(?:\s+(.+))?$}i
        or Net::Hawk::Errors::BadRequest->throw(
            message => 'invalid header syntax',
            value => $header,
        );

    my %attributes;

    my @attr_strings = split /\s*,\s*/, $attr_string;
    for my $attr (@attr_strings) {
        my ($key,$value) = $attr =~ m{^(\w+)="([^"\\]*)"}
            or Net::Hawk::Errors::BadRequest->throw(
                message => 'Bad header format',
                value => $header,
            );

        Net::Hawk::Errors::BadRequest->throw(
            message => "Unknown attribute $key",
            value => $header,
        ) unless exists $valid_keys{$key};

        Net::Hawk::Errors::BadRequest->throw(
            message => "Bad attribute value $value",
            value => $header,
        ) unless $value =~ m{^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~]+$};

        Net::Hawk::Errors::BadRequest->throw(
            message => "Duplicate attribute $key",
            value => $header,
        ) if exists $attributes{$key};

        $attributes{$key}=$value;
    }

    return \%attributes;
}

1;
