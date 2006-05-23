=head1 NAME

Authen::Passphrase::AcceptAll - accept any passphrase

=head1 SYNOPSIS

	use Authen::Passphrase::AcceptAll;

	$ppr = Authen::Passphrase::AcceptAll->new;

	if($ppr->match($passphrase)) { ...

	$passphrase = $ppr->passphrase;

	$passwd = $ppr->as_crypt;
	$userPassword = $ppr->as_rfc2307;

=head1 DESCRIPTION

An object of this class is a passphrase recogniser that accepts any
passphrase whatsoever.  This is a subclass of C<Authen::Passphrase>, and
this document assumes that the reader is familiar with the documentation
for that class.

This type of passphrase recogniser is obviously of no use at all in
controlling access to any resource.  Its use is to permit a resource to
be public in a system that expects some type of passphrase access control.

=cut

package Authen::Passphrase::AcceptAll;

use warnings;
use strict;

our $VERSION = "0.000";

use base qw(Authen::Passphrase);

# There is only one object of this class, and its content is
# insignificant.

=head1 CONSTRUCTOR

=over

=item Authen::Passphrase::AcceptAll->new

Returns an accept-all passphrase recogniser object.  The same object is
returned from each call.

=cut

{
	my $singleton = bless({});
	sub new($) { $singleton }
}

=back

=head1 METHODS

=over

=item $ppr->match(PASSPHRASE)

=item $ppr->passphrase

=item $ppr->as_crypt

=item $ppr->as_rfc2307

These methods are part of the standard C<Authen::Passphrase> interface.
The C<match> method always returns true, and the C<passphrase> method
returns the empty string (the shortest of the infinite number of correct
passphrases).

=cut

sub match($$) { 1 }

sub passphrase($$) { "" }

sub as_crypt($) { "" }

=back

=head1 SEE ALSO

L<Authen::Passphrase>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
