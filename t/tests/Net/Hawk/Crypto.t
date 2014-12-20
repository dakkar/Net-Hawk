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

done_testing;
