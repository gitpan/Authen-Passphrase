=head1 NAME

Authen::Passphrase::Clear - cleartext passphrases

=head1 SYNOPSIS

	use Authen::Passphrase::Clear;

	$ppr = Authen::Passphrase::Clear->new("passphrase");

	if($ppr->match($passphrase)) { ...

	$passphrase = $ppr->passphrase;

	$userPassword = $ppr->as_rfc2307;

=head1 DESCRIPTION

An object of this class is a passphrase recogniser that accepts
some particular passphrase which it knows.  This is a subclass of
C<Authen::Passphrase>, and this document assumes that the reader is
familiar with the documentation for that class.

I<Warning:> Storing a passphrase in cleartext, as this class does,
is a very bad idea.  It means that anyone who sees the passphrase file
immediately knows all the passphrases.  Do not use this unless you really
know what you're doing.

=cut

package Authen::Passphrase::Clear;

use warnings;
use strict;

our $VERSION = "0.001";

use base qw(Authen::Passphrase);

# An object of this class is a blessed scalar containing the passphrase.

=head1 CONSTRUCTOR

=over

=item Authen::Passphrase::Clear->new(PASSPHRASE)

Returns a passphrase recogniser object that stores the specified
passphrase in cleartext and accepts only that passphrase.

=cut

sub new($$) {
	my($class, $passphrase) = @_;
	return bless(\$passphrase, $class);
}

=back

=head1 METHODS

=over

=item $ppr->match(PASSPHRASE)

=item $ppr->passphrase

=item $ppr->as_rfc2307

These methods are part of the standard C<Authen::Passphrase> interface.
The C<passphrase> method trivially works.

=cut

sub match($$) {
	my($self, $passphrase) = @_;
	return $passphrase eq $$self;
}

sub passphrase($) { ${$_[0]} }

sub as_rfc2307($) { "{CLEARTEXT}".${$_[0]} }

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
