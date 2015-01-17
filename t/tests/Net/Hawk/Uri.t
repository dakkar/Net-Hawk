#!perl6
use v6;
use Test;
use Net::Hawk::Uri;

subtest {
    my sub credentialsFunc($id,&callback) {
        &callback.(Nil,{
          id => $id,
          key => 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
          algorithm => 'sha256',
          user => 'steve',
        });
    };

    my %req = (
        method => 'GET',
        url => '/resource/4?a=1&b=2',
        host => 'example.com',
        port => 80,
    );

    credentialsFunc('123456', sub ($err, %credentials) {
        my $bewit = Net::Hawk::Uri::getBewit(
            'http://example.com/resource/4?a=1&b=2',
            credentials => %credentials,
            ttl_sec => 60 * 60 * 24 * 365 * 100,
            ext => 'some-app-data',
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

done;
