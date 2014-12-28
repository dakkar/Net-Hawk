package Net::Hawk::Utils {
    use v6;
    use URI;
    use Net::Hawk::Errors;

    proto parse_content_type($) returns Str is export {*}
    multi parse_content_type(Str:U) returns Str { return '' }
    multi parse_content_type(Str:D $header) returns Str {
      my $ret = $header ~~ m{^ \s* (\S+?) \s* (\;|$) };
      return $ret[0].lc;
    }

    sub now_msecs(Int $offset_ms=0) returns Int is export {
        return floor(now*1000) + $offset_ms;
    }

    sub now_secs(Int $offset_ms=0) returns Int is export {
        return floor(now_msecs($offset_ms)/1000);
    }

    proto parse_authorization_header($,*@) returns Hash is export {*}
    multi parse_authorization_header(Str:U,*@) returns Hash {
        Net::Hawk::Errors::UnAuthorized.new(text=>'no header').throw
    }
    multi parse_authorization_header(Str:D $header, @keys=qw<id ts nonce hash ext mac app dlg>) returns Hash {
          my $valid_keys = Set(@keys);

          my ($attr_string) = @($header ~~ m:i{^ hawk [ \s+ (.+) ]? $}
             or Net::Hawk::Errors::BadRequest.new(
                text => 'invalid header syntax',
                value => $header,
             ).throw
          );

          my %attributes;

          my @attr_strings = split /\s* ',' \s*/, $attr_string;

          for @attr_strings -> $attr {
              my ($key, $value) = @(
                 $attr ~~ m{^ (\w+) '="' (<-["\\]>*) '"' }
                 or Net::Hawk::Errors::BadRequest.new(
                    text => 'Bad header format',
                    value => $header,
                 ).throw
              );

              Net::Hawk::Errors::BadRequest.new(
                text => "Unknown attribute $key",
                value => $header,
              ).throw unless $valid_keys{~$key} :exists;

              Net::Hawk::Errors::BadRequest.new(
                text => "Bad attribute value $value",
                value => $header,
              ).throw unless $value ~~ m{^<[ \w \  !#$%&'()*+,\-./:;\<=\>?@\[\]^`{|}~ ]>+$};

              Net::Hawk::Errors::BadRequest.new(
                text => "Duplicate attribute $key",
                value => $header,
              ).throw if %attributes{$key} :exists;

              %attributes{$key} = ~$value;
          }

          return %attributes;
     }
}

1;
