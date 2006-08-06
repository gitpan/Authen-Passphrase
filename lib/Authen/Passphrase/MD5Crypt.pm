=head1 NAME

Authen::Passphrase::MD5Crypt - passphrases using the MD5-based Unix
crypt()

=head1 SYNOPSIS

	use Authen::Passphrase::MD5Crypt;

	$ppr = Authen::Passphrase::MD5Crypt->new(
			salt => "my",
			hash_base64 => "rABM6TzyLaAnhuiWWgU81.");

	$salt = $ppr->salt;
	$hash_base64 = $ppr->hash_base64;

	if($ppr->match($passphrase)) { ...

	$passwd = $ppr->as_crypt;
	$userPassword = $ppr->as_rfc2307;

=head1 DESCRIPTION

An object of this class encapsulates a passphrase hashed using
the MD5-based Unix crypt() hash function.  This is a subclass of
C<Authen::Passphrase>, and this document assumes that the reader is
familiar with the documentation for that class.

The crypt() function in a modern Unix actually supports several
different passphrase schemes.  This class is concerned only with one
particular scheme, an MD5-based algorithm designed by Poul-Henning Kamp
and originally implemented in FreeBSD.  To handle the whole range of
passphrase schemes supported by the modern crypt(), see the C<from_crypt>
constructor and the C<as_crypt> method in L<Authen::Passphrase>.

The MD5-based crypt() scheme uses the whole passphrase, a salt which
can in principle be an arbitrary byte string, and the MD5 message
digest algorithm.  First the passphrase and salt are hashed together,
yielding an MD5 message digest.  Then a new digest is constructed,
hashing together the passphrase, the salt, and the first digest, all in
a rather complex form.  Then this digest is passed through a thousand
iterations of a function which rehashes it together with the passphrase
and salt in a manner that varies between rounds.  The output of the last
of these rounds is the resulting passphrase hash.

In the crypt() function the raw hash output is then represented in ASCII
as a 22-character string using a base 64 encoding.  The base 64 digits
are "B<.>", "B</>", "B<0>" to "B<9>", "B<A>" to "B<Z>", "B<a>" to "B<z>"
(in ASCII order).  Because the base 64 encoding can represent 132 bits
in 22 digits, more than the 128 required, the last digit can only take
four of the base 64 digit values.  An additional complication is that
the bytes of the raw algorithm output are permuted in a bizarre order
before being represented in base 64.

There is no tradition of handling these passphrase hashes in raw
binary form.  The textual encoding described above, including the final
permutation, is used universally, so this class does not support any
binary format.

=cut

package Authen::Passphrase::MD5Crypt;

use warnings;
use strict;

use Carp qw(croak);
use Crypt::PasswdMD5 1.0 qw(unix_md5_crypt);

our $VERSION = "0.001";

use base qw(Authen::Passphrase);
use fields qw(salt hash_base64);

=head1 CONSTRUCTOR

=over

=item Authen::Passphrase::MD5Crypt->new(ATTR => VALUE, ...)

Generates a new passphrase recogniser object using the MD5-based crypt()
algorithm.  The following attributes may be given:

=over

=item B<salt>

The salt, as a raw string.  It may be any byte string, but in crypt()
usage it is conventionally limited to zero to eight base 64 digits.

=item B<hash_base64>

The hash, as a string of 22 base 64 digits.  This is the final part of
what crypt() outputs.

=back

The salt and hash must both be given.

=cut

sub new($@) {
	my $class = shift;
	my Authen::Passphrase::MD5Crypt $self = fields::new($class);
	while(@_) {
		my $attr = shift;
		my $value = shift;
		if($attr eq "salt") {
			croak "salt specified redundantly"
				if exists $self->{salt};
			$self->{salt} = $value;
		} elsif($attr eq "hash_base64") {
			croak "hash specified redundantly"
				if exists $self->{hash_base64};
			$value =~ m#\A[./0-9A-Za-z]{21}[./01]\z#
				or croak "\"$value\" is not a valid ".
						"MD5-based crypt() hash";
			$self->{hash_base64} = $value;
		} else {
			croak "unrecognised attribute `$attr'";
		}
	}
	croak "salt not specified" unless exists $self->{salt};
	croak "hash not specified" unless exists $self->{hash_base64};
	return $self;
}

=back

=head1 METHODS

=over

=item $ppr->salt

Returns the salt, in raw form.

=cut

sub salt($) {
	my Authen::Passphrase::MD5Crypt $self = shift;
	return $self->{salt};
}

=item $ppr->hash_base64

Returns the hash value, as a string of 22 base 64 digits.

=cut

sub hash_base64($) {
	my Authen::Passphrase::MD5Crypt $self = shift;
	return $self->{hash_base64};
}

=item $ppr->match(PASSPHRASE)

=item $ppr->as_crypt

=item $ppr->as_rfc2307

These methods are part of the standard C<Authen::Passphrase> interface.
Not every passphrase recogniser of this type can be represented as a
crypt string: the crypt format only allows the salt to be up to eight
bytes, and it cannot contain any NUL or "B<$>" characters.

=cut

sub match($$) {
	my Authen::Passphrase::MD5Crypt $self = shift;
	my($passphrase) = @_;
	die "can't use a crypt-incompatible salt yet ".
			"(need generalised Crypt::MD5Passwd)"
		if $self->{salt} =~ /[^\ -\#\%-9\;-\~]/ ||
			length($self->{salt}) > 8;
	my $hash = unix_md5_crypt($passphrase, $self->{salt});
	$hash =~ s/\A.*\$//;
	return $hash eq $self->{hash_base64};
}

sub as_crypt($) {
	my Authen::Passphrase::MD5Crypt $self = shift;
	croak "can't put this salt into a crypt string"
		if $self->{salt} =~ /[^\ -\#\%-9\;-\~]/ ||
			length($self->{salt}) > 8;
	return "\$1\$".$self->{salt}."\$".$self->{hash_base64};
}

=back

=head1 SEE ALSO

L<Authen::Passphrase>,
L<Crypt::PasswdMD5>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
