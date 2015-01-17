package Net::Hawk::Uri {
    use v6;
    use Net::Hawk::Client;
    use Net::Hawk::Server;
    our constant &getBewit := &Net::Hawk::Client::getBewit;
    our constant &authenticate := &Net::Hawk::Server::authenticateBewit;
}
