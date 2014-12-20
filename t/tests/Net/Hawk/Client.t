#!perl
use strict;
use warnings;
use Test::More;
use Net::Hawk::Client;

my $c = Net::Hawk::Client->new();

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

done_testing();
