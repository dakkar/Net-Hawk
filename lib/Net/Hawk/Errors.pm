package Net::Hawk::Errors;
use strict;
use warnings;
use 5.010;

package Net::Hawk::Errors::base {
    use Moo;
    use Types::Standard qw(Str);
    with 'Throwable';
    use overload
        q{""}    => 'as_string',
        fallback => 1;

    has message => (
        is       => 'ro',
        isa      => Str,
        required => 1,
    );

    sub as_string { $_[0]->message }
};

package Net::Hawk::Errors::BadRequest {
    use Moo; extends 'Net::Hawk::Errors::base';

    has value => (is => 'ro');

    sub as_string {
        my ($self) = @_;
        return sprintf(
            '%s (%s)',
            $self->message,
            $self->value // '<undef>',
        );
    }
};

package Net::Hawk::Errors::UnAuthorized {
    use Moo; extends 'Net::Hawk::Errors::base';
};

1;
