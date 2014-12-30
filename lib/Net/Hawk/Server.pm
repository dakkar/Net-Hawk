package Net::Hawk::Server {
    use v6;

    our sub authenticate(
        %request!,
        &credentialsFunc:($,&)!,
        %whatever!,
        &callback:($,%,%)!,
    ) {
        my %creds;
        &credentialsFunc.('some id', sub ($err,%credentials) { %creds = %credentials });
        %request<url> ~~ m{'bewit=' $<ext>=(.*?) ['&'|$]};
        my %attributes = (
            ext => $/<ext>;
        );
        &callback.(Nil,%creds,%attributes);
    };
};
