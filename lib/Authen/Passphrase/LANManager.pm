=head1 NAME

Authen::Passphrase::LANManager - passphrases using the LAN Manager
hash algorithm

=head1 SYNOPSIS

	use Authen::Passphrase::LANManager;

	$ppr = Authen::Passphrase::LANManager->new(
		hash_hex => "855c3697d9979e78ac404c4ba2c66533");

	$ppr = Authen::Passphrase::LANManager->new(
		passphrase => "passphrase");

	$hash = $ppr->hash;
	$hash_hex = $ppr->hash_hex;

	$ppr0 = $ppr->first_half;
	$ppr1 = $ppr->second_half;

	if($ppr->match($passphrase)) { ...

	$userPassword = $ppr->as_rfc2307;

=head1 DESCRIPTION

An object of this class encapsulates a passphrase hashed using
the Microsoft LAN Manager hash function.  This is a subclass of
C<Authen::Passphrase>, and this document assumes that the reader is
familiar with the documentation for that class.

The hash algorithm can be used on up to fourteen Latin-1 characters of
passphrase.  First the passphrase is folded to uppercase, and zero-padded
to fourteen bytes.  Then it is split into two halves.  Each seven-byte
half used as a 56-bit DES key, to encrypt the fixed plaintext block
"KGS!@#$%".  The eight-byte ciphertexts are concatenated to form the
sixteen-byte hash.  There is no salt.

Because the two halves of the passphrase are hashed separately, it
is possible to manipulate (e.g., crack) a half hash in isolation.
See L<Authen::Passphrase::LANManagerHalf>.

I<Warning:> Don't even think about using this seriously.  It's an
exceptionally weak design, flawed in pretty much every respect.

=cut

package Authen::Passphrase::LANManager;

use warnings;
use strict;

use Authen::Passphrase::LANManagerHalf;
use Carp qw(croak);

our $VERSION = "0.002";

use base qw(Authen::Passphrase);
use fields qw(first_half second_half);

=head1 CONSTRUCTOR

=over

=item Authen::Passphrase::LANManager->new(ATTR => VALUE, ...)

Generates a new passphrase recogniser object using the LAN Manager
hash algorithm.  The following attributes may be given:

=over

=item B<hash>

The hash, as a string of 16 bytes.

=item B<hash_hex>

The hash, as a string of 32 hexadecimal digits.

=item B<passphrase>

A passphrase that will be accepted.

=back

Either the hash or the passphrase must be given.

=cut

sub new($@) {
	my $class = shift;
	my __PACKAGE__ $self = fields::new($class);
	my $hash;
	my $passphrase;
	while(@_) {
		my $attr = shift;
		my $value = shift;
		if($attr eq "hash") {
			croak "hash specified redundantly"
				if defined($hash) || defined($passphrase);
			$value =~ m#\A[\x{0}-\x{ff}]{16}\z#
				or croak "not a valid LAN Manager hash";
			$hash = $value;
		} elsif($attr eq "hash_hex") {
			croak "hash specified redundantly"
				if defined($hash) || defined($passphrase);
			$value =~ m#\A[0-9A-Fa-f]{32}\z#
				or croak "\"$value\" is not a valid ".
						"hex LAN Manager hash";
			$hash = pack("H*", $value);
		} elsif($attr eq "passphrase") {
			croak "passphrase specified redundantly"
				if defined($hash) || defined($passphrase);
			$self->_passphrase_acceptable($value)
				or croak "can't accept a passphrase exceeding".
						" fourteen bytes";
			$passphrase = $value;
		} else {
			croak "unrecognised attribute `$attr'";
		}
	}
	if(defined $passphrase) {
		$self->{first_half} =
			Authen::Passphrase::LANManagerHalf
				->new(passphrase => substr($passphrase, 0, 7));
		$self->{second_half} =
			Authen::Passphrase::LANManagerHalf
				->new(passphrase =>
					length($passphrase) > 7 ?
						substr($passphrase, 7, 7) :
						"");
	} elsif(defined $hash) {
		$self->{first_half} = Authen::Passphrase::LANManagerHalf
					->new(hash => substr($hash, 0, 8));
		$self->{second_half} = Authen::Passphrase::LANManagerHalf
					->new(hash => substr($hash, 8, 8));
	} else {
		croak "hash not specified";
	}
	return $self;
}

=back

=head1 METHODS

=over

=item $ppr->hash

Returns the hash value, as a string of 16 bytes.

=cut

sub hash($) {
	my __PACKAGE__ $self = shift;
	return $self->{first_half}->hash.$self->{second_half}->hash;
}

=item $ppr->hash_hex

Returns the hash value, as a string of 32 hexadecimal digits.

=cut

sub hash_hex($) {
	my __PACKAGE__ $self = shift;
	return unpack("H*", $self->hash);
}

=item $ppr->first_half

Returns the hash of the first half of the passphrase, as an
C<Authen::Passphrase::LANManagerHalf> passphrase recogniser.

=cut

sub first_half($) {
	my __PACKAGE__ $self = shift;
	return $self->{first_half};
}

=item $ppr->second_half

Returns the hash of the second half of the passphrase, as an
C<Authen::Passphrase::LANManagerHalf> passphrase recogniser.

=cut

sub second_half($) {
	my __PACKAGE__ $self = shift;
	return $self->{second_half};
}

=item $ppr->match(PASSPHRASE)

=item $ppr->as_rfc2307

These methods are part of the standard C<Authen::Passphrase> interface.

=cut

sub _passphrase_acceptable($$) {
	my __PACKAGE__ $self = shift;
	my($passphrase) = @_;
	return $passphrase =~ /\A[\x{0}-\x{ff}]{0,14}\z/;
}

sub match($$) {
	my __PACKAGE__ $self = shift;
	my($passphrase) = @_;
	return $self->_passphrase_acceptable($passphrase) &&
		$self->{first_half}->match(substr($passphrase, 0, 7)) &&
		$self->{second_half}->match(
			length($passphrase) > 7 ?
				substr($passphrase, 7, 7) :
				"");
}

sub as_rfc2307($) {
	my __PACKAGE__ $self = shift;
	return "{LANMAN}".$self->hash_hex;
}

=back

=head1 SEE ALSO

L<Authen::Passphrase>,
L<Authen::Passphrase::LANManagerHalf>,
L<Crypt::DES>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
