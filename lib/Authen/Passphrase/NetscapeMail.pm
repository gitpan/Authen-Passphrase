=head1 NAME

Authen::Passphrase::NetscapeMail - passphrases using Netscape Mail
Server's method

=head1 SYNOPSIS

	use Authen::Passphrase::NetscapeMail;

	$ppr = Authen::Passphrase::NetscapeMail->new(
		salt => "8fd9d0a03491ce8f99cfbc9ab39f0dd5",
		hash_hex => "983757d7b519e86d9b5d472aca4eea3a");

	$ppr = Authen::Passphrase::NetscapeMail->new(
		salt_random => 1,
		passphrase => "passphrase");

	$salt = $ppr->salt;
	$hash = $ppr->hash;
	$hash_hex = $ppr->hash_hex;

	if($ppr->match($passphrase)) { ...

	$userPassword = $ppr->as_rfc2307;

=head1 DESCRIPTION

An object of this class encapsulates a passphrase hashed using
the algorithm used by Netscape Mail Server.  This is a subclass of
C<Authen::Passphrase>, and this document assumes that the reader is
familiar with the documentation for that class.

The Netscape Mail Server scheme is based on the MD5 digest algorithm.
The passphrase and a salt are concatenated, along with some fixed
bytes, and this record is hashed through MD5.  The output of MD5 is the
password hash.

This algorithm is deprecated, and is supported for compatibility only.
Prefer the mechanism of L<Authen::Passphrase::SaltedDigest>.

=cut

package Authen::Passphrase::NetscapeMail;

use warnings;
use strict;

use Carp qw(croak);
use Data::Entropy::Algorithms 0.000 qw(rand_bits);
use Digest::MD5 1.99_53 ();

our $VERSION = "0.002";

use base qw(Authen::Passphrase);
use fields qw(salt hash);

=head1 CONSTRUCTOR

=over

=item Authen::Passphrase::NetscapeMail->new(ATTR => VALUE, ...)

Generates a new passphrase recogniser object using the Netscape Mail
Server algorithm.  The following attributes may be given:

=over

=item B<salt>

The salt, as a raw 32-byte string.  It may be any 32-byte string, but
it is conventionally limited to lowercase hexadecimal digits.

=item B<salt_random>

Causes salt to be generated randomly.  The value given for this attribute
is ignored.  The salt will be a string of 32 lowercase hexadecimal digits.
The source of randomness may be controlled by the facility described
in L<Data::Entropy>.

=item B<hash>

The hash, as a string of 16 bytes.

=item B<hash_hex>

The hash, as a string of 32 hexadecimal digits.

=item B<passphrase>

A passphrase that will be accepted.

=back

The salt must be given, and either the hash or the passphrase.

=cut

sub new($@) {
	my $class = shift;
	my __PACKAGE__ $self = fields::new($class);
	my $passphrase;
	while(@_) {
		my $attr = shift;
		my $value = shift;
		if($attr eq "salt") {
			croak "salt specified redundantly"
				if exists $self->{salt};
			$value =~ m#\A[\x{0}-\x{ff}]{32}\z#
				or croak "not a valid salt";
			$self->{salt} = $value;
		} elsif($attr eq "salt_random") {
			croak "salt specified redundantly"
				if exists $self->{salt};
			$self->{salt} = unpack("H*", rand_bits(128));
		} elsif($attr eq "hash") {
			croak "hash specified redundantly"
				if exists($self->{hash}) ||
					defined($passphrase);
			$value =~ m#\A[\x{0}-\x{ff}]{16}\z#
				or croak "not a valid MD5 hash";
			$self->{hash} = $value;
		} elsif($attr eq "hash_hex") {
			croak "hash specified redundantly"
				if exists($self->{hash}) ||
					defined($passphrase);
			$value =~ m#\A[0-9A-Fa-f]{32}\z#
				or croak "\"$value\" is not a valid ".
						"hex MD5 hash";
			$self->{hash} = pack("H*", $value);
		} elsif($attr eq "passphrase") {
			croak "passphrase specified redundantly"
				if exists($self->{hash}) ||
					defined($passphrase);
			$passphrase = $value;
		} else {
			croak "unrecognised attribute `$attr'";
		}
	}
	croak "salt not specified" unless exists $self->{salt};
	$self->{hash} = $self->_hash_of($passphrase) if defined $passphrase;
	croak "hash not specified" unless exists $self->{hash};
	return $self;
}

=back

=head1 METHODS

=over

=item $ppr->salt

Returns the salt value, as a string of 32 bytes.

=cut

sub salt($) {
	my __PACKAGE__ $self = shift;
	return $self->{salt};
}

=item $ppr->hash

Returns the hash value, as a string of 16 bytes.

=cut

sub hash($) {
	my __PACKAGE__ $self = shift;
	return $self->{hash};
}

=item $ppr->hash_hex

Returns the hash value, as a string of 32 hexadecimal digits.

=cut

sub hash_hex($) {
	my __PACKAGE__ $self = shift;
	return unpack("H*", $self->{hash});
}

=item $ppr->match(PASSPHRASE)

=item $ppr->as_rfc2307

These methods are part of the standard C<Authen::Passphrase> interface.

=cut

sub _hash_of($$) {
	my __PACKAGE__ $self = shift;
	my($passphrase) = @_;
	my $ctx = Digest::MD5->new;
	$ctx->add($self->{salt});
	$ctx->add("\x59");
	$ctx->add($passphrase);
	$ctx->add("\xf7");
	$ctx->add($self->{salt});
	return $ctx->digest;
}

sub match($$) {
	my __PACKAGE__ $self = shift;
	my($passphrase) = @_;
	return $self->_hash_of($passphrase) eq $self->{hash};
}

sub as_rfc2307($) {
	my __PACKAGE__ $self = shift;
	croak "can't put this salt into an RFC 2307 string"
		if $self->{salt} =~ /[^!-~]/;
	return "{NS-MTA-MD5}".$self->hash_hex.$self->{salt};
}

=back

=head1 SEE ALSO

L<Authen::Passphrase>,
L<Digest::MD5>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
