=head1 NAME

Authen::Passphrase::DESCrypt - passphrases using the DES-based Unix
crypt()

=head1 SYNOPSIS

	use Authen::Passphrase::DESCrypt;

	$ppr = Authen::Passphrase::DESCrypt->new(
			salt_base64 => "my",
			hash_base64 => "TYK.j.88/9s");

	$ppr = Authen::Passphrase::DESCrypt->new(
			fold => 1,
			initial => "xyzzy!!!",
			nrounds => 500,
			salt_base64 => "quux",
			hash_base64 => "QCKcHlgVsRY");

	$fold = $ppr->fold;
	$initial = $ppr->initial;
	$initial_base64 = $ppr->initial_base64;
	$nrounds = $ppr->nrounds;
	$nrounds_base64 = $ppr->nrounds_base64_4;
	$salt = $ppr->salt;
	$salt_base64 = $ppr->salt_base64_2;
	$salt_base64 = $ppr->salt_base64_4;
	$hash = $ppr->hash;
	$hash_base64 = $ppr->hash_base64;

	if($ppr->match($passphrase)) { ...

	$passwd = $ppr->as_crypt;
	$userPassword = $ppr->as_rfc2307;

=head1 DESCRIPTION

An object of this class encapsulates a passphrase hashed using some
form of the DES-based Unix crypt() hash function.  This is a subclass
of C<Authen::Passphrase>, and this document assumes that the reader is
familiar with the documentation for that class.

The crypt() function in a modern Unix actually supports several different
passphrase schemes.  That is not what this class is about.  This class
is concerned only with one family of schemes, variants of the DES-based
scheme that crypt() originally implemented, which confusingly is usually
referred to merely as "crypt()".  To handle the whole range of passphrase
schemes supported by the modern crypt(), see the C<from_crypt> constructor
and the C<as_crypt> method in L<Authen::Passphrase>.

=head2 The traditional DES-based Unix crypt() password scheme

I<Warning:> this password scheme is weak by modern standards, and in
any case does not support a large password space.  Cracking crypt()ed
passwords has been a routine activity since the early 1990s.  This scheme
is supported for compatibility reasons only, and should not be used
except when compatibility is required.  Do not use this in the design of
any new system or for new passwords in any system that supports better
passphrase schemes.

The traditional Unix crypt() password scheme is based on the DES block
encryption algorithm.  Using the password as a 56-bit key, it passes a
64-bit data block, initialised to zero, through the encryption function
25 times, and the hash is the 64-bit output of this process.  A 12-bit
salt is used to tweak the encryption algorithm.

The 56-bit key is extracted from the password in a very poor way.
Only the first eight bytes of the password are used, and any remainder
is ignored.  This makes it impossible to use a passphrase, rather than
a password, hence the terminology in this section.  Of the eight bytes
used, the top bit is also ignored; this function hails from the days of
pure ASCII.

A password hash of this scheme is conventionally represented in ASCII as
a 13-character string using a base 64 encoding.  The base 64 digits are
"B<.>", "B</>", "B<0>" to "B<9>", "B<A>" to "B<Z>", "B<a>" to "B<z>"
(in ASCII order).  The first two characters give the 12-bit salt.
The remaining eleven characters give the 64-bit hash.  Because the base
64 encoding can represent 66 bits in eleven digits, more than the 64
required, the last character of the string can only take sixteen of the
base 64 digit values.

=head2 Variant DES-based Unix crypt() passphrase schemes

To make password cracking more difficult, historically some Unix sites
modified the crypt() function to be incompatible with the standard one.
This was easily achieved by initialising the data block to something
other than the standard all-bits-zero.  Another variation used was to
increase the number of encryption rounds, which makes cracking take
longer in addition to being non-standard.  Password hashes on such a
system looked normal but were not interoperable with stardard crypt()
implementations.  To interpret them properly it is necessary to know
the modified parameters.

BSDi standardised an extended DES-based scheme.  The salt is extended to
24 bits, and the number of encryption rounds is variable.  Passphrases
longer than 8 characters are handled by an additional step that folds
(hashes) them down to 8 characters, rather than just throwing away
the characters after the eighth.  Passphrase hashes in this scheme
are conventionally represented in ASCII as a "B<_>" followed by 19
characters of base 64.  The first four base 64 digits give the number
of encryption rounds, the next four give the salt, and the remaining
eleven give the hash.

=cut

package Authen::Passphrase::DESCrypt;

use warnings;
use strict;

use Carp qw(croak);
use Crypt::UnixCrypt_XS 0.05 qw(
	fold_password crypt_rounds
	base64_to_block block_to_base64
	base64_to_int24 int24_to_base64
	base64_to_int12 int12_to_base64
);

our $VERSION = "0.000";

use base qw(Authen::Passphrase);
use fields qw(fold initial nrounds salt hash);

=head1 CONSTRUCTOR

=over

=item Authen::Passphrase::DESCrypt->new(ATTR => VALUE, ...)

Generates a new passphrase recogniser object using the generalised
DES-based crypt() algorithm.  The following attributes may be given:

=over

=item B<fold>

Boolean indicating whether the BSDi passphrase folding scheme should be
used for long passphrases.  Default false, for compatibility with the
original DES-based scheme.

=item B<initial>

The initial data block to encrypt, as a string of exactly eight bytes.
Default all bits zero, for compatibility with the original DES-based
scheme.

=item B<initial_base64>

The initial data block to encrypt, as a string of eleven base 64 digits.

=item B<nrounds>

The number of encryption rounds to use, as a Perl integer.  Default 25,
for compatibility with the original DES-based scheme.

=item B<nrounds_base64>

The number of encryption rounds to use, as a string of four base 64
digits.

=item B<salt>

The salt, as an integer in the range [0, 16777216).

=item B<salt_base64>

The salt, as a string of two or four base 64 digits.

=item B<hash>

The hash (output of encryption), as a string of exactly eight bytes.

=item B<hash_base64>

The hash, as a string of eleven base 64 digits.

=back

The salt and hash must both be given.  The other parameters default to
those used in the original DES-based crypt().

=cut

sub new($@) {
	my $class = shift;
	my Authen::Passphrase::DESCrypt $self = fields::new($class);
	while(@_) {
		my $attr = shift;
		my $value = shift;
		if($attr eq "fold") {
			croak "foldness specified redundantly"
				if exists $self->{fold};
			$self->{fold} = !!$value;
		} elsif($attr eq "initial") {
			croak "initial block specified redundantly"
				if exists $self->{initial};
			$value =~ m#\A[\x{0}-\x{ff}]{8}\z#
				or croak "not a valid raw block";
			$self->{initial} = $value;
		} elsif($attr eq "initial_base64") {
			croak "initial block specified redundantly"
				if exists $self->{initial};
			$value =~ m#\A[./0-9A-Za-z]{10}[.26AEIMQUYcgkosw]\z#
				or croak "\"$value\" is not a valid ".
					"encoded block";
			$self->{initial} = base64_to_block($value);
		} elsif($attr eq "nrounds") {
			croak "number of rounds specified redundantly"
				if exists $self->{nrounds};
			croak "\"$value\" is not a valid number of rounds"
				unless $value == int($value) && $value >= 0;
			$self->{nrounds} = $value;
		} elsif($attr eq "nrounds_base64") {
			croak "number of rounds specified redundantly"
				if exists $self->{nrounds};
			croak "\"$value\" is not a valid number of rounds"
				unless $value =~ m#\A[./0-9A-Za-z]{4}\z#;
			$self->{nrounds} = base64_to_int24($value);
		} elsif($attr eq "salt") {
			croak "salt specified redundantly"
				if exists $self->{salt};
			croak "\"$value\" is not a valid salt"
				unless $value == int($value) &&
					$value >= 0 && $value < 16777216;
			$self->{salt} = $value;
		} elsif($attr eq "salt_base64") {
			croak "salt specified redundantly"
				if exists $self->{salt};
			$value =~ m#\A(?:[./0-9A-Za-z]{2}|[./0-9A-Za-z]{4})\z#
				or croak "\"$value\" is not a valid salt";
			$self->{salt} = length($value) == 2 ?
				base64_to_int12($value) :
				base64_to_int24($value);
		} elsif($attr eq "hash") {
			croak "hash specified redundantly"
				if exists $self->{hash};
			$value =~ m#\A[\x{0}-\x{ff}]{8}\z#
				or croak "not a valid raw hash";
			$self->{hash} = $value;
		} elsif($attr eq "hash_base64") {
			croak "hash specified redundantly"
				if exists $self->{hash};
			$value =~ m#\A[./0-9A-Za-z]{10}[.26AEIMQUYcgkosw]\z#
				or croak "\"$value\" is not a valid ".
					"encoded hash";
			$self->{hash} = base64_to_block($value);
		} else {
			croak "unrecognised attribute `$attr'";
		}
	}
	croak "salt not specified" unless exists $self->{salt};
	croak "hash not specified" unless exists $self->{hash};
	$self->{fold} = 0 unless exists $self->{fold};
	$self->{initial} = "\0\0\0\0\0\0\0\0" unless exists $self->{initial};
	$self->{nrounds} = 25 unless exists $self->{nrounds};
	return $self;
}

=back

=head1 METHODS

=over

=item $ppr->fold

Returns a boolean indicating whether passphrase folding is used.

=cut

sub fold($) {
	my Authen::Passphrase::DESCrypt $self = shift;
	return $self->{fold};
}

=item $ppr->initial

Returns the initial block, as a string of eight bytes.

=cut

sub initial($) {
	my Authen::Passphrase::DESCrypt $self = shift;
	return $self->{initial};
}

=item $ppr->initial_base64

Returns the initial block, as a string of eleven base 64 digits.

=cut

sub initial_base64($) {
	my Authen::Passphrase::DESCrypt $self = shift;
	return block_to_base64($self->{initial});
}

=item $ppr->nrounds

Returns the number of encryption rounds, as a Perl integer.

=cut

sub nrounds($) {
	my Authen::Passphrase::DESCrypt $self = shift;
	return $self->{nrounds};
}

=item $ppr->nrounds_base64_4

Returns the number of encryption rounds, as a string of four base
64 digits.

=cut

sub nrounds_base64_4($) {
	my Authen::Passphrase::DESCrypt $self = shift;
	return int24_to_base64($self->{nrounds});
}

=item $ppr->salt

Returns the salt, as a Perl integer.

=cut

sub salt($) {
	my Authen::Passphrase::DESCrypt $self = shift;
	return $self->{salt};
}

=item $ppr->salt_base64_2

Returns the salt, as a string of two base 64 digits.  C<die>s if it
doesn't fit into two digits.

=cut

sub salt_base64_2($) {
	my Authen::Passphrase::DESCrypt $self = shift;
	my $salt = $self->{salt};
	croak "salt $salt doesn't fit into two digits" if $salt >= 4096;
	return int12_to_base64($salt);
}

=item $ppr->salt_base64_4

Returns the salt, as a string of four base 64 digits.

=cut

sub salt_base64_4($) {
	my Authen::Passphrase::DESCrypt $self = shift;
	return int24_to_base64($self->{salt});
}

=item $ppr->hash

Returns the hash value, as a string of eight bytes.

=cut

sub hash($) {
	my Authen::Passphrase::DESCrypt $self = shift;
	return $self->{hash};
}

=item $ppr->hash_base64

Returns the hash value, as a string of eleven base 64 digits.

=cut

sub hash_base64($) {
	my Authen::Passphrase::DESCrypt $self = shift;
	return block_to_base64($self->{hash});
}

=item $ppr->match(PASSPHRASE)

=item $ppr->as_crypt

=item $ppr->as_rfc2307

These methods are part of the standard C<Authen::Passphrase> interface.

=cut

sub match($$) {
	my Authen::Passphrase::DESCrypt $self = shift;
	my($passphrase) = @_;
	$passphrase = fold_password($passphrase) if $self->{fold};
	return crypt_rounds($passphrase, $self->{nrounds}, $self->{salt},
			    $self->{initial}) eq
		$self->{hash};
}

sub as_crypt($) {
	my Authen::Passphrase::DESCrypt $self = shift;
	if(!$self->{fold} && $self->{initial} eq "\0\0\0\0\0\0\0\0" &&
			$self->{nrounds} == 25 && $self->{salt} < 4096) {
		return $self->salt_base64_2.$self->hash_base64;
	} elsif($self->{fold} && $self->{initial} eq "\0\0\0\0\0\0\0\0") {
		return "_".$self->nrounds_base64_4.$self->salt_base64_4.
			$self->hash_base64;
	} else {
		croak "passphrase can't be expressed as a crypt string";
	}
}

=back

=head1 SEE ALSO

L<Authen::Passphrase>,
L<Crypt::UnixCrypt_XS>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
