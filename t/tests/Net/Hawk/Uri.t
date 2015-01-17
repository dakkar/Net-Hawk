#!perl6
use v6;
use Test;
use Net::Hawk::Uri;
use Net::Hawk::Utils;
use Net::Hawk::Crypto;
use URI::Escape;
use MIME::Base64;

my MIME::Base64 $mime .= new;

my sub credentialsFunc($id,&callback) {
    &callback.(Nil,{
        id => $id,
        key => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm => 'sha256',
        user => 'steve',
    });
};

subtest {
    my %req = (
        method => 'GET',
        url => '/resource/4?a=1&b=2',
        host => 'example.com',
        port => 80,
    );

    credentialsFunc('123456', sub ($err, %credentials) {
        my $bewit = Net::Hawk::Uri::getBewit(
            'http://example.com/resource/4?a=1&b=2',
            {
                credentials => %credentials,
                ttl_sec => 60 * 60 * 24 * 365 * 100,
                ext => 'some-app-data',
            },
        );
        %req<url> ~= "\&bewit=$bewit";

        Net::Hawk::Uri::authenticate(
            %req,
            &credentialsFunc,
            {},
            sub ($err, %credentials, %attributes) {
                ok(!$err,"no error");
                is(%credentials<user>,'steve','correct user');
                is(%attributes<ext>,'some-app-data','ext passed on');
            },
        );
    });
}, 'generate a bewit then successfully authenticate it';

subtest {
    my %req = (
        method => 'GET',
        url => '/resource/4?a=1&b=2',
        host => 'example.com',
        port => 80,
    );

    credentialsFunc('123456', sub ($err, %credentials) {
        my $bewit = Net::Hawk::Uri::getBewit(
            'http://example.com/resource/4?a=1&b=2',
            {
                credentials => %credentials,
                ttl_sec => 60 * 60 * 24 * 365 * 100,
            },
        );
        %req<url> ~= "\&bewit=$bewit";

        Net::Hawk::Uri::authenticate(
            %req,
            &credentialsFunc,
            {},
            sub ($err, %credentials, %attributes) {
                ok(!$err,"no error");
                is(%credentials<user>,'steve','correct user');
            },
        );
    });
}, 'generate a bewit then successfully authenticate it (no ext)';

subtest {
    my %req = (
        method => 'GET',
        url => '/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ',
        host => 'example.com',
        port => 8080,
    );

    Net::Hawk::Uri::authenticate(
        %req,
        &credentialsFunc,
        {},
        sub ($err, %credentials, %attributes) {
            ok(!$err,"no error");
            is(%credentials<user>,'steve','correct user');
            is(%attributes<ext>,'some-app-data','ext passed on');
        },
    );
}, 'authenticate a request (last param)';

subtest {
    my %req = (
        method => 'GET',
        url => '/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ&a=1&b=2',
        host => 'example.com',
        port => 8080,
    );

    Net::Hawk::Uri::authenticate(
        %req,
        &credentialsFunc,
        {},
        sub ($err, %credentials, %attributes) {
            ok(!$err,"no error");
            is(%credentials<user>,'steve','correct user');
            is(%attributes<ext>,'some-app-data','ext passed on');
        },
    );
}, 'authenticate a request (first param)';

subtest {
    my %req = (
        method => 'GET',
        url => '/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2NDFcZm1CdkNWT3MvcElOTUUxSTIwbWhrejQ3UnBwTmo4Y1VrSHpQd3Q5OXJ1cz1cc29tZS1hcHAtZGF0YQ',
        host => 'example.com',
        port => 8080,
    );

    Net::Hawk::Uri::authenticate(
        %req,
        &credentialsFunc,
        {},
        sub ($err, %credentials, %attributes) {
            ok(!$err,"no error");
            is(%credentials<user>,'steve','correct user');
            is(%attributes<ext>,'some-app-data','ext passed on');
        },
    );
}, 'authenticate a request (only param)';

subtest {
    my %req = (
        method => 'GET',
        url => '/resource/4?bewit=MTIzNDU2XDQ1MTE0ODQ2NDFcZm1CdkNWT3MvcElOTUUxSTIwbWhrejQ3UnBwTmo4Y1VrSHpQd3Q5OXJ1cz1cc29tZS1hcHAtZGF0YQ',
        host => 'example.com',
        port => 8080,
        authorization => 'Basic asdasdasdasd',
    );

    Net::Hawk::Uri::authenticate(
        %req,
        &credentialsFunc,
        {},
        sub ($err, %credentials, %attributes) {
            ok($err,"error detected");
            is($err.text,
               'Multiple authentications',
               'correct error message');
        },
    );
}, 'fail on multiple authentication';

subtest {
    my %req = (
        method => 'POST',
        url => '/resource/4?filter=a',
        host => 'example.com',
        port => 8080,
    );

    credentialsFunc('123456', sub ($err, %credentials) {
        my $exp = floor(now_msecs() / 1000) + 60;
        my $ext = 'some-app-data';
        my $mac = calculate_mac(
            'bewit',
            %credentials,
            {
              ts => $exp,
              nonce=> '',
              method=> %req<method>,
              resource=> %req<url>,
              host => %req<host>,
              port=> %req<port>,
              ext=> $ext,
          },
        );

        my $bewit = "%credentials<id>\\$exp\\$mac\\$ext";
        $bewit = uri_escape($mime.encode-str($bewit));
        %req<url> ~= "\&bewit=$bewit";

        Net::Hawk::Uri::authenticate(
            %req,
            &credentialsFunc,
            {},
            sub ($err, %credentials, %attributes) {
                ok($err,"error detected");
                is($err.text,
                   'Invalid method',
                   'correct error message');
            },
        );
    });
}, 'fail on method other than GET';

done;
