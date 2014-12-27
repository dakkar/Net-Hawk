package Net::Hawk::Errors {
    use v6;
    class base is Exception {
        has $.text;
        method message { return "{self.text}" }
    }

    class BadRequest is base {
        has $.value;

        method message {
            return "{ self.text } ({ self.value // '<undef>' })";
        }
    }

    class UnAuthorized is base {}
}
