package Net::Hawk::Crypto;
use strict;
use warnings;
use 5.010;
use Moo;
use Types::Standard 1.000003 qw(Str Int Object Dict Optional Undef Any HasMethods slurpy);
use Types::URI qw(Uri);
use Type::Params qw(compile);
use Try::Tiny;
use Net::Hawk::Utils;
use Digest;

sub header_version() { 1 }

sub generate_normalized_string {
    state $argcheck = compile(Object,Str,Dict[
        resource => Uri,
        ts => Int,
        nonce => Str,
        method => Optional[Str],
        host => Str,
        port => Int,
        hash => Optional[Str],
        ext => Optional[Str],
        app => Optional[Str],
        dlg => Optional[Str],
        slurpy Any,
    ]);
    my ($self,$type,$options) = $argcheck->(@_);

    my $normalized = sprintf(
        "hawk.%d.%s\n%d\n%s\n%s\n%s\n%s\n%d\n%s\n%s\n",
        header_version(), $type,
        $options->{ts},
        $options->{nonce},
        uc($options->{method} // ''),
        $options->{resource}->path_query,
        lc($options->{host}),
        $options->{port},
        $options->{hash} // '',
        ($options->{ext} // '') =~ s{\\}{\\\\}gr =~ s{\n}{\\n}gr,
    );

    if ($options->{app}) {
        $normalized .= sprintf(
            "%s\n%s\n",
            $options->{app},
            $options->{dlg} // '',
        );
    }

    return $normalized;
}

sub calculate_payload_hash {
    state $argcheck = compile(Object,Str|Undef,Str,Str);
    my ($self,$payload,$algorithm,$content_type) = $argcheck->(@_);

    my $hash = $self->initialize_payload_hash($algorithm,$content_type);
    $hash->add($payload//'');
    return $self->finalize_payload_hash($hash);
}

sub initialize_payload_hash {
    state $argcheck = compile(Object,Str,Str);
    my ($self,$algorithm,$content_type) = $argcheck->(@_);

    my $digest = try {
        Digest->new($algorithm);
    }
    catch {
        $algorithm =~ s{(?<=[a-z])(?=[0-9])}{-};
        Digest->new(uc($algorithm));
    };

    $digest->add(sprintf("hawk.%d.payload\n",header_version()));
    $digest->add(Net::Hawk::Utils::parse_content_type($content_type),"\n");
    return $digest;
}

sub finalize_payload_hash {
    state $argcheck = compile(Object,HasMethods[qw(add b64digest)]);
    my ($self,$digest) = $argcheck->(@_);

    $digest->add("\n");
    my $ret = $digest->b64digest();
    $ret .= '=' while length($ret) % 4;
    return $ret;
}

1;
