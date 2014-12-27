#!perl6
use v6;
use Test;
use Net::Hawk::Utils;

subtest {
    is(parse_content_type(Str),'','undef -> empty string');
    is(parse_content_type('text/plain'),'text/plain','simple');
    is(parse_content_type('text/plain; charset=utf-8'),'text/plain','ignore options');
};

subtest {
    throws_like { parse_authorization_header(Str) },
        Net::Hawk::Errors::UnAuthorized,
          text => 'no header';

    throws_like { parse_authorization_header('bad') },
        Net::Hawk::Errors::BadRequest,
          text => 'invalid header syntax';

    throws_like { parse_authorization_header('hawk: bad') },
        Net::Hawk::Errors::BadRequest,
          text => 'Bad header format';

    is_deeply( parse_authorization_header('hawk: id="1"'),
               { id => '1' },
               'ok parse');
};

done;
