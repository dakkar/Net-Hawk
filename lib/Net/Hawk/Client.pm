package Net::Hawk::Client;
use strict;
use warnings;
use 5.010;
use Moo;
use Types::Standard 1.000003 qw(Str Int Object Dict Optional Undef Any HashRef HasMethods slurpy);
use Types::URI qw(Uri);
use Type::Params qw(compile);
use Try::Tiny;
use Net::Hawk::Utils;
use Session::Token;
use Net::Hawk::Types qw(HTTPHeaders);
use Net::Hawk::Role::WithUtils;
use Net::Hawk::Role::WithCrypto;

with WithUtils(qw(now_secs));
with WithCrypto(qw(calculate_payload_hash));

sub header {
    state $argcheck = compile(Object,Uri,Str,Dict[
        timestamp => Optional[Int],
        localtime_offset_msec => Optional[Int],
        credentials => Dict[
            id => Str,
            key => Str,
            algorithm => Str,
        ],
        nonce => Optional[Str],
        hash => Optional[Str],
        ext => Optional[Str|Undef],
        app => Optional[Str],
        dlg => Optional[Str],
        payload => Optional[Str],
        content_type => Optional[Str],
        slurpy Any,
    ]);
    my ($self,$uri,$method,$options) = $argcheck->(@_);

    my $timestamp = $options->{timestamp} //
        $self->_utils->now_secs($options->{localtime_offset_msec});

    my $credentials = $options->{credentials};

    my %artifacts = (
        ts => $timestamp,
        nonce => $options->{nonce} || Session::Token->new->get,
        method => $method,
        resource => $uri->path_query,
        host => $uri->host,
        port => $uri->port // ($uri->scheme eq 'http:' ? 80 : 443),
    );
    for my $k (qw(hash ext app dlg)) {
        next unless defined $options->{$k};
        $artifacts{$k} = $options->{$k};
    }

    if ( !$artifacts{hash} && defined $options->{payload} ) {
        $artifacts{hash} = $self->_crypto->calculate_payload_hash(
            $options->{payload},
            $credentials->{algorithm},
            $options->{content_type},
        );
    }

    my $mac = $self->_crypto->calculate_mac(header=>$credentials,\%artifacts);

    my $has_ext = ($options->{ext}//'') ne '';

    my $header = sprintf(
        'Hawk id="%s", ts="%d", nonce="%s"',
        $credentials->{id},
        $artifacts{ts},
        $artifacts{nonce},
    )
        . ($artifacts{hash} ? sprintf(', hash="%s"',$artifacts{hash}) : '')
        . ($has_ext ? sprintf(', ext="%s"', $artifacts{ext} =~ s{([\\"])}{\\$1}gr) : '' )
        . sprintf(', mac="%s"',$mac);

    if ($artifacts{app}) {
        $header .= sprintf(', app="%s"', $artifacts{app});
        if ($artifacts{dlg}) {
            $header .= sprintf(', dlg="%s"',$artifacts{dlg});
        }
    }

    return {
        field => $header,
        artifacts => \%artifacts,
    };
}

sub authenticate {
    state $argcheck = compile(
        Object,
        HTTPHeaders,
        HashRef,
        Optional[HashRef],
        Optional[HashRef],
    );
    my ($self,$headers,$credentials,$artifacts,$options) = $argcheck->(@_);

    $artifacts //= {}; $options //= {};

    my $www_auth = $headers->header('www-authenticate');
    if ($www_auth) {
        my $attributes = try { $self->_utils->parse_authorization_header(
            $www_auth,[qw(ts tsm error)],
        ) };
        return unless $attributes;

        if ($attributes->{ts}) {
            my $tsm = $self->_crypto->calculate_ts_mac(
                $attributes->{ts},$credentials,
            );
            return unless $tsm eq $attributes->{tsm};
        }
    }

    my $serv_auth = $headers->header('server-authorization');
    return 1 unless $serv_auth || $options->{required};

    my $attributes = try { $self->_utils->parse_authorization_header(
        $serv_auth,
        [qw(mac ext hash)],
    ) };
    return unless $attributes;

    my $mac = $self->_crypto->calculate_mac(
        response => $credentials,
        {
            %$artifacts,
            ext => $attributes->{ext},
            hash => $attributes->{hash},
        },
    );
    return unless $mac eq $attributes->{mac};

    return 1 unless defined $options->{payload};
    return unless $attributes->{hash};

    my $calculated_hash = $self->_crypto->calculated_payload_hash(
        $options->{payload},
        $credentials->{algorithm},
        scalar $headers->header('content-type'),
    );
    return $calculated_hash eq $attributes->{hash};
}

1;
