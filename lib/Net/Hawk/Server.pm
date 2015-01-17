package Net::Hawk::Server {
    use v6;
    use Net::Hawk::Utils;
    use Net::Hawk::Crypto;
    use URI;
    use URI::Escape;
    use MIME::Base64;

    our sub authenticate(
        %req!,
        &credentials_func:($,&)!,
        %options!,
        &callback:($,%,%)!,
    ) {

        %options<nonce_func> //= sub ($,$,&nonceCallback) { return &nonceCallback.() };
        %options<timestamp_skew_sec> //= 60;
        my $now = now_msecs(%options<localtime_offset_msec>//0);
        my %request = parse_request(%req,%options);
        my $attributes = try {
            parse_authorization_header(%request<authorization>);
        };
        warn $attributes.perl;
        return &callback.($!,{},{}) unless $attributes;

        my %artifacts = (
            %request<method host port> :p,
            resource => %request<url>,
            $attributes<ts nonce hash ext app dlg mac id> :p,
        );

        if not $attributes{all(<id ts nonce mac>)} :exists {
            return &callback.(
                Net::Hawk::Errors::BadRequest.new(
                    text => 'Missing attributes',
                    value => %request<authorization>,
                ),
                Nil,
                %artifacts,
            );
        };

        &credentials_func.(
            $attributes<id>,
            sub ($err,%credentials) {
                if $err {
                    return &callback.($err,%credentials,%artifacts);
                };
                if not %credentials {
                    return &callback.(
                        Net::Hawk::Errors::UnAuthorized.new(
                            text => 'Unknown credentials',
                        ),
                        Nil,
                        %artifacts,
                    );
                };
                if not %credentials{all(<key algorithm>)}.defined {
                    return &callback.(
                        Net::Hawk::Errors::Internal.new(
                            text => 'Invalid credentials',
                        ),
                        %credentials,
                        %artifacts,
                    );
                };
                if not is_valid_hash_algorithm %credentials<algorithm> {
                    return &callback.(
                        Net::Hawk::Errors::Internal.new(
                            text => 'Unknown algorithm',
                        ),
                        %credentials,
                        %artifacts,
                    );
                };

                my $mac = calculate_mac('header',%credentials,%artifacts);
                unless $mac eq $attributes<mac> { # DANGER! this should be a fixed-time comparison!
                    return &callback.(
                        Net::Hawk::Errors::UnAuthorized.new(
                            text => 'Bad mac',
                        ),
                        %credentials,
                        %artifacts,
                    );
                };

                if (%options<payload>.defined) {
                    if not $attributes<hash> {
                        return &callback.(
                            Net::Hawk::Errors::UnAuthorized.new(
                                text => 'Missing required payload hash',
                            ),
                            %credentials,
                            %artifacts,
                        );
                    };

                    my $hash = calculate_payload_hash(
                        %options<payload>,
                        %credentials<algorithm>,
                        %request<content_type>,
                    );
                    unless $hash eq $attributes<hash> { # DANGER! this should be a fixed-time comparison!
                        return &callback.(
                            Net::Hawk::Errors::UnAuthorized.new(
                                text => 'Bad payload hash',
                            ),
                            %credentials,
                            %artifacts,
                        );
                    };
                };

                %options<nonce_func>.(
                    $attributes<nonce>,
                    $attributes<ts>,
                    sub ($err) {
                        if $err {
                            return &callback.(
                                Net::Hawk::Errors::UnAuthorized.new(
                                    text => 'Invalid nonce',
                                ),
                                %credentials,
                                %artifacts,
                            );
                        };

                        if abs(($attributes<ts> * 1000) - $now) >
                            (%options<timestamp_skew_sec> * 1000) {
                            my $tsm = timestamp_message(
                                %credentials,
                                %options<localtime_offset_msec>,
                            );
                            return &callback.(
                                Net::Hawk::Errors::UnAuthorized.new(
                                    text => 'Stale timestamp',
                                    tsm => $tsm,
                                ),
                                %credentials,
                                %artifacts,
                            );
                        };

                        return &callback.(Nil,%credentials,%artifacts);
                    },
                );
            },
        );
    };

    our sub authenticateBewit(
        %req,
        &credentials_func:($,&)!,
        %options!,
        &callback:($,%,%)!,
    ) {
        my $now = now_msecs(%options<localtime_offset_msec>//0);
        my %request = parse_request(%req,%options);
        my $resource = URI.new(%request<url>);
        return &callback.(Net::Hawk::Errors::UnAuthorized.new,{},{})
            unless $resource;
        my $bewit_param = $resource.query_form<bewit>;
        return &callback.(
            Net::Hawk::Errors::UnAuthorized.new(
                text => 'Empty bewit',
            ),
            {},
            {},
        ) unless $bewit_param;
        return &callback.(
            Net::Hawk::Errors::UnAuthorized.new(
                text => 'Invalid method',
            ),
            {},
            {},
        ) unless %request<method> eq any(<GET HEAD>);
        return &callback.(
            Net::Hawk::Errors::BadRequest.new(
                text => 'Multiple authentications',
            ),
            {},
            {},
        ) if %request<authorization>;

        # we should throw if bad b64 encoding…
        my $bewit_str = MIME::Base64.new.decode-str($bewit_param);
        my @bewit_parts = $bewit_str.split('\\');
        return &callback.(
            Net::Hawk::Errors::BadRequest.new(
                text => 'Invalid bewit structure',
                value => $bewit_str,
            ),
            {},
            {},
        ) unless @bewit_parts == 4;

        my %bewit = (
            id => @bewit_parts[0],
            exp => try { :10(@bewit_parts[1]) },
            mac => @bewit_parts[2],
            ext => @bewit_parts[3] // '',
        );
        return &callback.(
            Net::Hawk::Errors::BadRequest.new(
                text => 'Missing bewit attributes',
            ),
            {},
            {},
        ) unless %bewit{all <id exp mac>}.defined;

        return &callback.(
            Net::Hawk::Errors::UnAuthorized.new(
                text => 'Access expired',
            ),
            {},
            {},
        ) if %bewit<exp>*1000 <= $now;

        # the URI object is immutable, and all its attributes are
        # private so I can't even use 'clone' to get a modified object
        my $url = %request<url>.subst(
            /( <?after '?'> | '&') bewit\=.*? ( '&'| $ )/,
            { $1 && $2 ?? '&' !! '' }
        );

        &credentials_func.(
            %bewit<id>,
            sub ($err,%credentials) {
                return &callback.($err,%credentials//{},%bewit<ext>//{})
                    if $err;
                return &callback.(
                    Net::Hawk::Errors::UnAuthorized.new(
                        text => 'Unknown credentials',
                    ),
                    {},
                    %bewit,
                ) unless %credentials;
                return &callback.(
                    Net::Hawk::Errors::Internal.new(
                        text => 'Invalid credentials',
                    ),
                    %credentials,
                    %bewit,
                ) unless %credentials{all <key algorithm>}.defined;
                if not is_valid_hash_algorithm %credentials<algorithm> {
                    return &callback.(
                        Net::Hawk::Errors::Internal.new(
                            text => 'Unknown algorithm',
                        ),
                        %credentials,
                        %bewit,
                    );
                };

                my $mac = calculate_mac('bewit',%credentials,{
                    ts => %bewit<exp>,
                    nonce => '',
                    method => 'GET',
                    resource => $url,
                    %request<host port> :p,
                    %bewit<ext> :p,
                });
                unless $mac eq %bewit<mac> { # DANGER! this should be a fixed-time comparison!
                    return &callback.(
                        Net::Hawk::Errors::UnAuthorized.new(
                            text => 'Bad mac',
                        ),
                        %credentials,
                        %bewit,
                    );
                };

                return &callback.(Nil,%credentials,%bewit);
            },
        );
    };
};
