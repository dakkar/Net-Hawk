#!perl
use strict;
use warnings;
use Test::More;
use Net::Hawk::Crypto;

my $c = Net::Hawk::Crypto->new();

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
    my $string = $c->generate_normalized_string(
        header => {
            credentials => \%credentials,
            ts => $options{timestamp},
            nonce => $options{nonce},
            method => 'GET',
            resource => '/resource?a=1&b=2',
            host => 'example.com',
            port => 8000,
            ext => $options{ext},
        }
    );

    is(
        $string,
        "hawk.1.header\n1353832234\nj4h3g2\nGET\n/resource?a=1&b=2\nexample.com\n8000\n\nsome-app-ext-data\n",
        'normalized string generated ok',
    );
};

subtest POST => sub {
    my $payload = 'Thank you for flying Hawk';
    my $content_type = 'text/plain';

    my $payload_hash = $c->calculate_payload_hash(
        $payload,
        $credentials{algorithm},
        $content_type,
    );

    my $string = $c->generate_normalized_string(
        header => {
            credentials => \%credentials,
            ts => $options{timestamp},
            nonce => $options{nonce},
            method => 'POST',
            resource => '/resource?a=1&b=2',
            host => 'example.com',
            port => 8000,
            hash => $payload_hash,
            ext => $options{ext},
        }
    );

    is(
        $string,
        "hawk.1.header\n1353832234\nj4h3g2\nPOST\n/resource?a=1&b=2\nexample.com\n8000\nYi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=\nsome-app-ext-data\n",
        'normalized string generated ok',
    );
};

subtest normalized_string => sub {
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
    my $string = $c->generate_normalized_string(
        header => \%args,
    );
    is(
        $string,
        "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\n\n",
        'valid normalized string',
    );

    $string = $c->generate_normalized_string(
        header => {
            %args,
            ext => 'this is some app data',
        },
    );
    is(
        $string,
        "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\nthis is some app data\n",
        'valid normalized string (ext)',
    );

    $string = $c->generate_normalized_string(
        header => {
            %args,
            ext => 'this is some app data',
            hash => 'U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=',
        },
    );
    is(
        $string,
        "hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\nU4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=\nthis is some app data\n",
        'valid normalized string (payload + ext)',
    );
};

done_testing;
