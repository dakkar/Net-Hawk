package Net::Hawk::Client {
    use v6;
    use URI;
    use Net::Hawk::Utils;
    use Net::Hawk::Crypto;

    our proto header(*@,*%) returns Hash {*};
    multi header(Str:D $uri!,*@pos,*%nam) returns Hash {
        return header(URI.new($uri),|@pos,|%nam);
    };
    multi header(
      URI:D $uri!,
      Str:D $method!,
        Int :$timestamp,
        Int :$localtime_offset_msec,
        Hash:D :$credentials (
            Str:D :id($),
            Str:D :key($),
            Str:D :algorithm($),
        ),
        Str :$nonce,
        Str :$hash,
        Str :$ext,
        Str :$app,
        Str :$dlg,
        Str :$payload,
        Str :$content_type,
        *%,
    ) returns Hash {
        $timestamp //= now_secs($localtime_offset_msec);

        my %artifacts = (
            ts => +($timestamp),
            nonce => $nonce // ['a'..'z','A'..'Z','_',0..9].pick(6).join(''),
            method => $method,
            resource => $uri.path_query,
            host => $uri.host,
            port => +($uri.port) // ($uri.scheme eq 'http:' ?? 80 !! 443),
        );
        for <hash ext app dlg> -> $k {
            next unless defined $::($k);
            %artifacts{$k} = $::($k);
        }

        if ( !%artifacts<hash> && defined $payload ) {
            %artifacts<hash> = calculate_payload_hash(
                $payload,
                $credentials<algorithm>,
                $content_type,
            );
        }

        my $mac = calculate_mac(
            'header',
            $credentials,
            %artifacts,
        );

        my $has_ext = ($ext//'') ne '';

        my $header = sprintf(
            'Hawk id="%s", ts="%d", nonce="%s"',
            $credentials<id>,
            %artifacts<ts>,
            %artifacts<nonce>,
        )
        ~ (%artifacts<hash> ?? sprintf(', hash="%s"',%artifacts<hash>) !! '')
        ~ ($has_ext ?? sprintf(', ext="%s"', %artifacts<ext>.trans(['\\','"']=>['\\\\','\\"']) ) !! '' )
        ~ sprintf(', mac="%s"',$mac);

        if (%artifacts<app>) {
            $header ~= sprintf(', app="%s"', %artifacts<app>);
            if (%artifacts<dlg>) {
                $header ~= sprintf(', dlg="%s"',%artifacts<dlg>);
            }
        }

        return {
            field => $header,
            artifacts => %artifacts,
        };
    }

        my sub get_header(Str:D $key, @headers) returns Str {
            @headers \
                ==> grep { .key eq $key } \
                ==> map { .value } \
                ==> join ',';
        }
        our sub authenticate(
          Array:D $headers,
          Hash:D $credentials,
            Hash $artifacts?,
            Hash $options?,
        ) returns Bool {

            my $www_auth = get_header('www-authenticate',$headers);

            if ($www_auth) {
                my $attributes = try {
                    $attributes = parse_authorization_header(
                        $www_auth,<ts tsm error>,
                    );
                };
                return False unless $attributes;

                if ($attributes<ts>) {
                    my $tsm = calculate_ts_mac(
                        +$attributes<ts>,$credentials,
                    );
                    return False unless $tsm eq $attributes<tsm>;
                }
            }

            my $serv_auth = get_header('server-authorization',$headers);
            return True unless $serv_auth || $options<required>;

            my $attributes = try {
                parse_authorization_header(
                    $serv_auth,
                    <mac ext hash>,
                );
            };
            return False unless $attributes;

            my $mac = calculate_mac(
                'response',
                $credentials,
                %(
                    %$artifacts,
                    ext => $attributes<ext>,
                    hash => $attributes<hash>,
                ),
            );
            return False unless $mac eq $attributes<mac>;

            return True unless defined $options<payload>;
            return False unless $attributes<hash>;

            my $calculated_hash = calculate_payload_hash(
                $options<payload>,
                $credentials<algorithm>,
                get_header('content-type',$headers),
            );
            return $calculated_hash eq $attributes<hash>;
        };
}
