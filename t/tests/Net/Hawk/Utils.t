#!perl6
use v6;
use Test;
use Net::Hawk::Utils;

subtest {
    is(parse_content_type(Str),'','undef -> empty string');
    is(parse_content_type('text/plain'),'text/plain','simple');
    is(parse_content_type('text/plain; charset=utf-8'),'text/plain','ignore options');
},'parse content type';

subtest {
    throws_like { parse_authorization_header(Str) },
        Net::Hawk::Errors::UnAuthorized,
          text => rx:s/no header/;

    throws_like { parse_authorization_header('bad') },
        Net::Hawk::Errors::BadRequest,
          text => rx:s/invalid header/;

    throws_like { parse_authorization_header('hawk bad') },
        Net::Hawk::Errors::BadRequest,
          text => rx:i:s/bad header/;

    throws_like { parse_authorization_header('hawk bad="a"') },
        Net::Hawk::Errors::BadRequest,
          text => rx:i:s/unknown attribute/;

    throws_like { parse_authorization_header('hawk id="a", id="b"') },
        Net::Hawk::Errors::BadRequest,
          text => rx:i:s/duplicate attribute/;

    is_deeply( parse_authorization_header('hawk id="1"'),
               { id => '1' },
               'ok parse');
},'parse header';

done;
