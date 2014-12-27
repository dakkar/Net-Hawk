package Net::Hawk::Errors {
    use v6;
    class base is Exception {
        has $.text;
        sub message { return "{.text}" }
    }

    class BadRequest is base {
        has $.value;

        sub message {
            return "{ .text } ({ .value // '<undef>' })";
        }
    }

    class UnAuthorized is base {}
}
