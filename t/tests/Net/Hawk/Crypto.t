#!perl
use v6;
use Test;
use URI;
use Net::Hawk::Crypto;

subtest {
    my %credentials = (
        id => 'dh37fgj492je',
        key => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm => 'sha256',
    );
    my %options = (
        credentials => %credentials,
        timestamp => 1353832234,
        nonce => 'j4h3g2',
        ext => 'some-app-ext-data'
    );

    subtest {
        my $string = generate_normalized_string(
            type => 'header',
            credentials => %credentials,
            ts => %options<timestamp>,
            nonce => %options<nonce>,
            method => 'GET',
            resource => URI.new('/resource?a=1&b=2'),
            host => 'example.com',
            port => 8000,
            ext => %options<ext>,
        );

        is(
            $string,
            "hawk.1.header\n1353832234\nj4h3g2\nGET\n/resource?a=1&b=2\nexample.com\n8000\n\nsome-app-ext-data\n",
            'normalized string generated ok',
        );
    };

    subtest {
        my $payload = 'Thank you for flying Hawk';
        my $content_type = 'text/plain';

        my $payload_hash = calculate_payload_hash(
            $payload,
            %credentials<algorithm>,
            $content_type,
        );

        my $string = generate_normalized_string(
            type => 'header',
            credentials => %credentials,
            ts => %options<timestamp>,
            nonce => %options<nonce>,
            method => 'POST',
            resource => '/resource?a=1&b=2',
            host => 'example.com',
            port => 8000,
            hash => $payload_hash,
            ext => %options<ext>,
        );

        is(
            $string,
            "hawk.1.header\n1353832234\nj4h3g2\nPOST\n/resource?a=1&b=2\nexample.com\n8000\nYi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=\nsome-app-ext-data\n",
            'normalized string generated ok',
        );
    };
};

subtest {
    my %args = (
        credentials => {
            key => 'dasdfasdf',
            algorithm => 'sha256',
        },
        ts => 1357747017,
        nonce => 'k3k4j5',
        method => 'GET',
        resource => '/resource/something',
        host => 'example.com',
        port =>8080
    );
    my $string = generate_normalized_string(
        type=>'header',|%args,
    );
    is(
        $string,
        "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\n\n",
        'valid normalized string',
    );

    $string = generate_normalized_string(
        type=>'header',
        |%args,
        ext => 'this is some app data',
    );
    is(
        $string,
        "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\nthis is some app data\n",
        'valid normalized string (ext)',
    );

    $string = generate_normalized_string(
        type=>'header',
        |%args,
        ext => 'this is some app data',
        hash => 'U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=',
    );
    is(
        $string,
        "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\nU4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=\nthis is some app data\n",
        'valid normalized string (payload + ext)',
    );
};

done;
