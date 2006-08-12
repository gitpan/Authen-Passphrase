=head1 NAME

Authen::Passphrase::BlowfishCrypt - passphrases using the Blowfish-based
Unix crypt()

=head1 SYNOPSIS

	use Authen::Passphrase::BlowfishCrypt;

	$ppr = Authen::Passphrase::BlowfishCrypt->new(
		cost => 8,
		salt => "sodium__chloride",
		hash_base64 => "BPZijhMHLvPeNMHd6XwZyNamOXVBTPi");

	$ppr = Authen::Passphrase::BlowfishCrypt->new(
		cost => 8, salt_random => 1,
		passphrase => "passphrase");

	$key_nul = $ppr->key_nul;
	$cost = $ppr->cost;
	$cost = $ppr->keying_nrounds_log2;
	$salt = $ppr->salt;
	$salt_base64 = $ppr->salt_base64;
	$hash = $ppr->hash;
	$hash_base64 = $ppr->hash_base64;

	if($ppr->match($passphrase)) { ...

	$passwd = $ppr->as_crypt;
	$userPassword = $ppr->as_rfc2307;

=head1 DESCRIPTION

An object of this class encapsulates a passphrase hashed using the
Blowfish-based Unix crypt() hash function, known as "bcrypt".  This is
a subclass of C<Authen::Passphrase>, and this document assumes that the
reader is familiar with the documentation for that class.

The crypt() function in a modern Unix actually supports several different
passphrase schemes.  This class is concerned only with one particular
scheme, a Blowfish-based algorithm designed by Niels Provos and David
Mazieres for OpenBSD.  To handle the whole range of passphrase schemes
supported by the modern crypt(), see the C<from_crypt> constructor and
the C<as_crypt> method in L<Authen::Passphrase>.

The Blowfish-based crypt() scheme uses a variant of Blowfish called
"Eksblowfish", for "expensive key schedule Blowfish".  It has the
cryptographic strength of Blowfish, and a very slow key setup phase
to resist brute-force attacks.  There is a "cost" parameter to the
scheme: the length of key setup is proportional to 2^cost.  There is
a 128-bit salt.  Up to 72 characters of the passphrase will be used;
any more will be ignored.

The cost, salt, and passphrase are all used to (very
slowly) key Eksblowfish.  Once key setup is done, the string
"OrpheanBeholderScryDoubt" (three Blowfish blocks long) is encrypted 64
times in ECB mode.  The final byte of the ciphertext is then dropped,
yielding a 23-byte hash.

In the crypt() function the salt and hash are represented in ASCII
using a base 64 encoding.  The base 64 digits are "B<.>", "B</>",
"B<A>" to "B<Z>", "B<a>" to "B<z>", "B<0>" to "B<9>" (in that order).
The 16-byte salt is represented as 22 base 64 digits, and the 23-byte
hash as 31 base 64 digits.

This algorithm is intended for situations where the efficiency of
a brute force attack is a concern.  It is suitable for use in new
applications where this requirement exists.  If that is not a concern,
and it suffices to merely make brute force the most efficient attack, see
L<Authen::Passphrase::SaltedDigest> for more efficient hash algorithms.

=cut

package Authen::Passphrase::BlowfishCrypt;

use warnings;
use strict;

use Carp qw(croak);
use Crypt::Eksblowfish::Bcrypt 0.000 qw(bcrypt_hash en_base64 de_base64);
use Data::Entropy::Algorithms 0.000 qw(rand_bits);

our $VERSION = "0.002";

use base qw(Authen::Passphrase);
use fields qw(key_nul cost salt hash);

=head1 CONSTRUCTOR

=over

=item Authen::Passphrase::BlowfishCrypt->new(ATTR => VALUE, ...)

Generates a new passphrase recogniser object using the generalised
DES-based crypt() algorithm.  The following attributes may be given:

=over

=item B<key_nul>

Boolean indicating whether to append a NUL to the passphrase before using
it as a key.  The algorithm as originally devised does not do this,
but it was later modified to do it.  The version that does append NUL
is to be preferred.  Default true.

=item B<cost>

Base-two logarithm of the number of keying rounds to perform.

=item B<keying_nrounds_log2>

Synonym for B<cost>.

=item B<salt>

The salt, as a 16-byte string.

=item B<salt_base64>

The salt, as a string of 22 base 64 digits.

=item B<salt_random>

Causes salt to be generated randomly.  The value given for this attribute
is ignored.  The source of randomness may be controlled by the facility
described in L<Data::Entropy>.

=item B<hash>

The hash, as a 23-byte string.

=item B<hash_base64>

The hash, as a string of 31 base 64 digits.

=item B<passphrase>

A passphrase that will be accepted.

=back

The cost and salt must be given, and either the hash or the passphrase.

=cut

sub new($@) {
	my $class = shift;
	my __PACKAGE__ $self = fields::new($class);
	my $passphrase;
	while(@_) {
		my $attr = shift;
		my $value = shift;
		if($attr eq "key_nul") {
			croak "foldness specified redundantly"
				if exists $self->{fold};
			$self->{key_nul} = !!$value;
		} elsif($attr eq "cost" || $attr eq "keying_nrounds_log2") {
			croak "cost specified redundantly"
				if exists $self->{cost};
			croak "\"$value\" is not a valid cost parameter"
				unless $value == int($value) && $value >= 0;
			$self->{cost} = $value;
		} elsif($attr eq "salt") {
			croak "salt specified redundantly"
				if exists $self->{salt};
			$value =~ m#\A[\x{0}-\x{ff}]{16}\z#
				or croak "\"$value\" is not a valid raw salt";
			$self->{salt} = $value;
		} elsif($attr eq "salt_base64") {
			croak "salt specified redundantly"
				if exists $self->{salt};
			croak "\"$value\" is not a valid salt"
				unless length($value) == 22;
			$self->{salt} = de_base64($value);
		} elsif($attr eq "salt_random") {
			croak "salt specified redundantly"
				if exists $self->{salt};
			$self->{salt} = rand_bits(128);
		} elsif($attr eq "hash") {
			croak "hash specified redundantly"
				if exists($self->{hash}) ||
					defined($passphrase);
			$value =~ m#\A[\x{0}-\x{ff}]{23}\z#
				or croak "not a valid raw hash";
			$self->{hash} = $value;
		} elsif($attr eq "hash_base64") {
			croak "hash specified redundantly"
				if exists($self->{hash}) ||
					defined($passphrase);
			croak "\"$value\" is not a valid hash"
				unless length($value) == 31;
			$self->{hash} = de_base64($value);
		} elsif($attr eq "passphrase") {
			croak "passphrase specified redundantly"
				if exists($self->{hash}) ||
					defined($passphrase);
			$passphrase = $value;
		} else {
			croak "unrecognised attribute `$attr'";
		}
	}
	$self->{key_nul} = 1 unless exists $self->{key_nul};
	croak "cost not specified" unless exists $self->{cost};
	croak "salt not specified" unless exists $self->{salt};
	$self->{hash} = $self->_hash_of($passphrase) if defined $passphrase;
	croak "hash not specified" unless exists $self->{hash};
	return $self;
}

=back

=head1 METHODS

=over

=item $ppr->key_nul

Returns a boolean indicating whether a NUL will be appended to the
passphrase before using it as a key.

=cut

sub key_nul($) {
	my __PACKAGE__ $self = shift;
	return $self->{key_nul};
}

=item $ppr->cost

Returns the base-two logarithm of the number of keying rounds that will
be performed.

=cut

sub cost($) {
	my __PACKAGE__ $self = shift;
	return $self->{cost};
}

=item $ppr->keying_nrounds_log2

Synonym for C<cost>.

=cut

*keying_nrounds_log2 = \&cost;

=item $ppr->salt

Returns the salt, as a string of sixteen bytes.

=cut

sub salt($) {
	my __PACKAGE__ $self = shift;
	return $self->{salt};
}

=item $ppr->salt_base64

Returns the salt, as a string of 22 base 64 digits.

=cut

sub salt_base64($) {
	my __PACKAGE__ $self = shift;
	return en_base64($self->{salt});
}

=item $ppr->hash

Returns the hash value, as a string of 23 bytes.

=cut

sub hash($) {
	my __PACKAGE__ $self = shift;
	return $self->{hash};
}

=item $ppr->hash_base64

Returns the hash value, as a string of 31 base 64 digits.

=cut

sub hash_base64($) {
	my __PACKAGE__ $self = shift;
	return en_base64($self->{hash});
}

=item $ppr->match(PASSPHRASE)

=item $ppr->as_crypt

=item $ppr->as_rfc2307

These methods are part of the standard C<Authen::Passphrase> interface.

=cut

sub _hash_of($$) {
	my __PACKAGE__ $self = shift;
	my($passphrase) = @_;
	return bcrypt_hash({
		key_nul => $self->{key_nul},
		cost => $self->{cost},
		salt => $self->{salt},
	}, $passphrase);
}

sub match($$) {
	my __PACKAGE__ $self = shift;
	my($passphrase) = @_;
	return $self->_hash_of($passphrase) eq $self->{hash};
}

sub as_crypt($) {
	my __PACKAGE__ $self = shift;
	croak "passphrase can't be expressed as a crypt string"
		if $self->{cost} > 99;
	return sprintf("\$2%s\$%02d\$%s%s", $self->key_nul ? "a" : "",
			$self->cost, $self->salt_base64, $self->hash_base64);
}

=back

=head1 SEE ALSO

L<Authen::Passphrase>,
L<Crypt::Eksblowfish::Bcrypt>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
