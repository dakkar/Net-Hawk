#!perl
use strict;
use warnings;
use Test::More;
use Net::Hawk::Client;

my $c = Net::Hawk::Client->new();

subtest readme => sub {
    my %credentials = (
        id => 'dh37fgj492je',
        key => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm => 'sha256',
    );
    my %options = (
        credentials => \%credentials,
        timestamp => 1353832234,
        nonce => 'j4h3g2',
        ext => 'some-app-ext-data'
    );

    subtest GET => sub {
        my $field = $c->header(
            'http://example.com:8000/resource/1?b=1&a=2',
            'GET',
            \%options,
        )->{field};

        is(
            $field,
            'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="',
            'Hawk header generated ok',
        );
    };

    subtest POST => sub {
        $options{payload} = 'Thank you for flying Hawk';
        $options{content_type} = 'text/plain';

        my $field = $c->header(
            'http://example.com:8000/resource/1?b=1&a=2',
            'POST',
            \%options,
        )->{field};

        is(
            $field,
            'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", hash="Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=", ext="some-app-ext-data", mac="aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw="',
            'Hawk header generated ok',
        );
    };
};

subtest header => sub {
    my $uri = 'http://example.net/somewhere/over/the/rainbow';
    my $uri_s = 'https://example.net/somewhere/over/the/rainbow';
    my %args = (
        credentials => {
            id => '123456',
            key => '2983d45yun89q',
            algorithm => 'sha1',
        },
        ext => 'Bazinga!',
        timestamp => 1353809207,
        nonce => 'Ygvqdz',
        payload => 'something to write about',
    );

    my $header = $c->header($uri,POST => \%args);
    is(
        $header->{field},
        'Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="bsvY3IfUllw6V5rvk4tStEvpBhE=", ext="Bazinga!", mac="qbf1ZPG/r/e06F4ht+T77LXi5vw="',
        'valid authorization header (sha1)',
    );

    $args{credentials}{algorithm}='sha256';
    $args{content_type} = 'text/plain';
    $header = $c->header($uri_s,POST => \%args);
    is(
        $header->{field},
        'Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", ext="Bazinga!", mac="q1CwFoSHzPZSkbIvl0oYlD+91rBUEvFk763nMjMndj8="',
        'valid authorization header (sha256)',
    );

    delete $args{ext};
    $header = $c->header($uri_s,POST => \%args);
    is(
        $header->{field},
        'Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="',
        'valid authorization header (no ext)',
    );

    $args{ext}=undef;
    $header = $c->header($uri_s,POST => \%args);
    is(
        $header->{field},
        'Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="',
        'valid authorization header (null ext)',
    );

    $args{payload}='';
    $header = $c->header($uri_s,POST => \%args);
    is(
        $header->{field},
        'Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="q/t+NNAkQZNlq/aAD6PlexImwQTxwgT2MahfTa9XRLA=", mac="U5k16YEzn3UnBHKeBzsDXn067Gu3R4YaY6xOt9PYRZM="',
        'valid authorization header (empty payload)',
    );

    $args{hash} = $c->_crypto->calculate_payload_hash(
        'something to write about',
        $args{credentials}{algorithm},
        $args{content_type},
    );
    $header = $c->header($uri_s,POST => \%args);
    is(
        $header->{field},
        'Hawk id="123456", ts="1353809207", nonce="Ygvqdz", hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="HTgtd0jPI6E4izx8e4OHdO36q00xFCU0FolNq3RiCYs="',
        'valid authorization header (pre hashed payload)',
    );
};

subtest authenticate => sub {
    ok(
        ! $c->authenticate([
            'server-authorization' => 'Hawk mac="abc", bad="xyz"',
        ],{}),
        'returns false on invalid header',
    );

    my %artifacts = (
        method => 'POST',
        host => 'example.com',
        port => '8080',
        resource => '/resource/4?filter=a',
        ts => '1362336900',
        nonce => 'eb5S_L',
        hash => 'nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=',
        ext => 'some-app-data',
        app => undef,
        dlg => undef,
        mac => 'BlmSe8K+pbKIb6YsZCnt4E1GrYvY1AaYayNR82dGpIk=',
        id => '123456',
    );

    my %credentials = (
        id => '123456',
        key => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm => 'sha256',
        user => 'steve'
    );

    ok(
        ! $c->authenticate([
            'content-type' => 'text/plain',
            'server-authorization' => 'Hawk mac="_IJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"',
        ],\%credentials,\%artifacts),
        'returns false on invalid mac',
    );

    ok(
        $c->authenticate([
            'content-type' => 'text/plain',
            'server-authorization' => 'Hawk mac="XIJRsMl/4oL+nn+vKoeVZPdCHXB4yJkNnBbTbHFZUYE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"',
        ],\%credentials,\%artifacts),
        'returns true on ignoring hash',
    );

    ok(
        ! $c->authenticate([
            'www-authenticate' => 'Hawk ts="1362346425875", tsm="PhwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", x="Stale timestamp"',
        ],{}),
        'fails on invalid WWW-Authenticate header format',
    );

    ok(
        ! $c->authenticate([
            'www-authenticate' => 'Hawk ts="1362346425875", tsm="hwayS28vtnn3qbv0mqRBYSXebN/zggEtucfeZ620Zo=", error="Stale timestamp"',
        ],\%credentials),
        'fails on invalid WWW-Authenticate header format',
    );

    ok(
        $c->authenticate([
            'www-authenticate' => 'Hawk error="Stale timestamp"',
        ],{}),
        'skips tsm validation when missing ts',
    );
};

done_testing();
