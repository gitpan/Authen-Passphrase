=head1 NAME

Authen::Passphrase::NTHash - passphrases using the NT-Hash algorithm

=head1 SYNOPSIS

	use Authen::Passphrase::NTHash;

	$ppr = Authen::Passphrase::NTHash->new(
		hash_hex => "7f8fe03093cc84b267b109625f6bbf4b");

	$ppr = Authen::Passphrase::NTHash->new(
		passphrase => "passphrase");

	$hash = $ppr->hash;
	$hash_hex = $ppr->hash_hex;

	if($ppr->match($passphrase)) { ...

	$passwd = $ppr->as_crypt;
	$userPassword = $ppr->as_rfc2307;

=head1 DESCRIPTION

An object of this class encapsulates a passphrase hashed using the NT-Hash
function.  This is a subclass of C<Authen::Passphrase>, and this document
assumes that the reader is familiar with the documentation for that class.

The NT-Hash scheme is based on the MD4 digest algorithm.  Up to 128
characters of passphrase (characters beyond the 128th are ignored)
are represented in Unicode, and hashed using MD4.  No salt is used.

I<Warning:> MD4 is a weak hash algorithm by current standards, and the
lack of salt is a design flaw in this scheme.  Use this for compatibility
only, not by choice.

=cut

package Authen::Passphrase::NTHash;

use warnings;
use strict;

use Carp qw(croak);
use Digest::MD4 1.2 qw(md4);

our $VERSION = "0.002";

use base qw(Authen::Passphrase);
use fields qw(hash);

=head1 CONSTRUCTOR

=over

=item Authen::Passphrase::NTHash->new(ATTR => VALUE, ...)

Generates a new passphrase recogniser object using the NT-Hash algorithm.
The following attributes may be given:

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
	my $passphrase;
	while(@_) {
		my $attr = shift;
		my $value = shift;
		if($attr eq "hash") {
			croak "hash specified redundantly"
				if exists($self->{hash}) ||
					defined($passphrase);
			$value =~ m#\A[\x{0}-\x{ff}]{16}\z#
				or croak "not a valid MD4 hash";
			$self->{hash} = $value;
		} elsif($attr eq "hash_hex") {
			croak "hash specified redundantly"
				if exists($self->{hash}) ||
					defined($passphrase);
			$value =~ m#\A[0-9A-Fa-f]{32}\z#
				or croak "\"$value\" is not a valid ".
						"hex MD4 hash";
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
	$self->{hash} = $self->_hash_of($passphrase) if defined $passphrase;
	croak "hash not specified" unless exists $self->{hash};
	return $self;
}

=back

=head1 METHODS

=over

=item $ppr->hash

Returns the hash value, as a string of 16 bytes.

=cut

sub hash($) {
	my Authen::Passphrase::NTHash $self = shift;
	return $self->{hash};
}

=item $ppr->hash_hex

Returns the hash value, as a string of 32 hexadecimal digits.

=cut

sub hash_hex($) {
	my Authen::Passphrase::NTHash $self = shift;
	return unpack("H*", $self->{hash});
}

=item $ppr->match(PASSPHRASE)

=item $ppr->as_crypt

=item $ppr->as_rfc2307

These methods are part of the standard C<Authen::Passphrase> interface.

=cut

sub _hash_of($$) {
	my __PACKAGE__ $self = shift;
	my($passphrase) = @_;
	$passphrase = substr($passphrase, 0, 128);
	$passphrase =~ s/(.)/pack("v", ord($1))/eg;
	return md4($passphrase);
}

sub match($$) {
	my __PACKAGE__ $self = shift;
	my($passphrase) = @_;
	return $self->_hash_of($passphrase) eq $self->{hash};
}

sub as_crypt($) {
	my Authen::Passphrase::NTHash $self = shift;
	return "\$3\$\$".$self->hash_hex;
}

sub as_rfc2307($) {
	my Authen::Passphrase::NTHash $self = shift;
	return "{MSNT}".$self->hash_hex;
}

=back

=head1 SEE ALSO

L<Authen::Passphrase>,
L<Digest::MD4>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
