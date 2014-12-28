package Net::Hawk::Crypto {
    use v6;
    use URI;
    use Digest::SHA;
    use Digest::HMAC;
    use MIME::Base64;
    use Net::Hawk::Utils;

    sub header_version() { 1 }

    proto generate_normalized_string(*%x) returns Str is export {*};
    multi generate_normalized_string(Str:D :$resource!,*%named) returns Str {
        return generate_normalized_string(|%named,resource=>URI.new($resource));
    };
    multi generate_normalized_string(
        Str:D :$type!,
        URI:D :$resource!,
        Int:D :$ts!,
        Str:D :$nonce!,
        Str :$method,
        Str:D :$host!,
        Int:D :$port!,
        Str :$hash,
        Str :$ext,
        Str :$app,
        Str :$dlg,
          *%,
    ) returns Str is export {
      my $normalized = sprintf(
          "hawk.%d.%s\n%d\n%s\n%s\n%s\n%s\n%d\n%s\n%s\n",
          header_version(), $type,
          $ts,
          $nonce,
          uc($method // ''),
          $resource.path_query,
          lc($host),
          $port,
          $hash // '',
          ($ext // '').trans(['\\',"\n"] => ['\\\\','\\n']),
      );

      if ($app) {
          $normalized .= sprintf(
              "%s\n%s\n",
              $app,
              $dlg // '',
          );
      }

      return $normalized;
    };

    sub digest_for(Str:D $algorithm) {
        if ($algorithm eq 'sha1') { return &sha1 }
        elsif ($algorithm eq 'sha256') { return &sha256 }
        else { die "bad alg $algorithm" }
    }

    sub calculate_payload_hash(
        Str $payload!,
        Str:D $algorithm!,
        Str $content_type!,
    ) returns Str is export {
        my $hash_function = digest_for($algorithm);
        return MIME::Base64.encode(
            $hash_function(sprintf("hawk.%d.payload\n%s\n%s\n",
                                   header_version(),
                                   parse_content_type($content_type),
                                   $payload)));
    };

    sub calc_hmac(
      Str:D $data,
      Str:D $algorithm,
      Str:D $key,
    ) returns Str {
        my $hash_function = digest_for($algorithm);
        return MIME::Base64.encode(
            hmac($key,$data,$hash_function)
        );
    }

    sub calculate_mac(
      Str:D $type,
      Hash:D $credentials ( Str :$algorithm, Str :$key, *% ),
      Hash:D $options
    ) returns Str is export {
        my $normalized = generate_normalized_string(:$type,|$options);

        return calc_hmac(
            $normalized,
            $algorithm,
            $key,
        );
    }

}
=begin finish
sub calculate_ts_mac {
    state $argcheck = compile(
        Object,Int,
        Dict[
            algorithm => Algorithm,
            key => Str,
            slurpy Any,
        ],
    );
    my ($self,$ts,$credentials) = $argcheck->(@_);

    my $string = sprintf(
        "hawk.%s.ts\n%d\n",
        header_version(),
        $ts,
    );

    return $self->calc_hmac(
        $string,
        $credentials->{algorithm},
        $credentials->{key},
    );
}

sub make_digest {
    state $argcheck = compile(Object,Algorithm);
    my ($self,$algorithm) = $argcheck->(@_);

    return Digest::SHA->new($algorithm =~ s{^sha}{}r);
}

sub _pad_b64 {
    my ($b64) = @_;

    $b64 .= '=' while length($b64) % 4;
    return $b64;
}

1;
