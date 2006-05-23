=head1 NAME

Authen::Passphrase::SaltedDigest - passphrases using the generic salted
digest algorithm

=head1 SYNOPSIS

	use Authen::Passphrase::SaltedDigest;

	$ppr = Authen::Passphrase::SaltedDigest->new(
		algorithm => "SHA-1", salt => "my",
		hash_hex => "301ce40d1b5ceb0919c9".
			    "f26e1d7aff880a886f7b");

	$algorithm = $ppr->algorithm;
	$salt = $ppr->salt;
	$salt_hex = $ppr->salt_hex;
	$hash = $ppr->hash;
	$hash_hex = $ppr->hash_hex;

	if($ppr->match($passphrase)) { ...

	$userPassword = $ppr->as_rfc2307;

=head1 DESCRIPTION

An object of this class encapsulates a passphrase hashed using
a generic digest-algorithm-based scheme.  This is a subclass of
C<Authen::Passphrase>, and this document assumes that the reader is
familiar with the documentation for that class.

The salt is an arbitrary string of bytes.  It is appended to passphrase,
and the combined string is passed through a specified message digest
algorithm.  The output of the message digest algorithm is the passphrase
hash.

The use of this passphrase scheme is recommended for new systems.
The strength depends entirely on the choice of digest algorithm, so
choose according to the level of security required.  SHA-1 is suitable for
most applications, but recent work has revealed weaknesses in the basic
structure of MD5, SHA-1, SHA-256, and all similar digest algorithms.
A new generation of digest algorithms will probably emerge sometime
around 2008.

=cut

package Authen::Passphrase::SaltedDigest;

use warnings;
use strict;

use Carp qw(croak);
use Digest;
use MIME::Base64 qw(encode_base64);

our $VERSION = "0.000";

use base qw(Authen::Passphrase);
use fields qw(algorithm salt hash);

=head1 CONSTRUCTOR

=over

=item Authen::Passphrase::SaltedDigest->new(ATTR => VALUE, ...)

Generates a new passphrase recogniser object using the generic salted
digest algorithm.  The following attributes may be given:

=over

=item B<algorithm>

A string identifying the message digest algorithm to use.  It must be
understood by C<< Digest->new >>.

=item B<salt>

The salt, as a raw string of bytes.  Defaults to the empty string,
yielding an unsalted scheme.

=item B<salt_hex>

The salt, as a string of hexadecimal digits.  Defaults to the empty
string, yielding an unsalted scheme.

=item B<hash>

The hash, as a string of bytes.

=item B<hash_hex>

The hash, as a string of hexadecimal digits.

=back

The digest algorithm and hash must both be given.

=cut

sub new($@) {
	my $class = shift;
	my Authen::Passphrase::SaltedDigest $self = fields::new($class);
	while(@_) {
		my $attr = shift;
		my $value = shift;
		if($attr eq "algorithm") {
			croak "algorithm specified redundantly"
				if exists $self->{algorithm};
			$self->{algorithm} = $value;
		} elsif($attr eq "salt") {
			croak "salt specified redundantly"
				if exists $self->{salt};
			$value =~ m#\A[\x{0}-\x{ff}]*\z#
				or croak "\"$value\" is not a valid salt";
			$self->{salt} = $value;
		} elsif($attr eq "salt_hex") {
			croak "salt specified redundantly"
				if exists $self->{salt};
			$value =~ m#\A(?:[0-9A-Fa-f]{2})+\z#
				or croak "\"$value\" is not a valid salt";
			$self->{salt} = pack("H*", $value);
		} elsif($attr eq "hash") {
			croak "hash specified redundantly"
				if exists $self->{hash};
			$value =~ m#\A[\x{0}-\x{ff}]*\z#
				or croak "\"$value\" is not a valid hash";
			$self->{hash} = $value;
		} elsif($attr eq "hash_hex") {
			croak "hash specified redundantly"
				if exists $self->{hash};
			$value =~ m#\A(?:[0-9A-Fa-f]{2})+\z#
				or croak "\"$value\" is not a valid hash";
			$self->{hash} = pack("H*", $value);
		} else {
			croak "unrecognised attribute `$attr'";
		}
	}
	croak "algorithm not specified" unless exists $self->{algorithm};
	croak "hash not specified" unless exists $self->{hash};
	$self->{salt} = "" unless exists $self->{salt};
	my $th = Digest->new($self->{algorithm})->digest;
	croak "not a valid ".$self->{algorithm}." hash"
		unless length($th) == length($self->{hash});
	return $self;
}

=back

=head1 METHODS

=over

=item $ppr->algorithm

Returns the digest algorithm, as a string that can be passed to C<<
Digest->new >>.

=cut

sub algorithm($) {
	my Authen::Passphrase::SaltedDigest $self = shift;
	return $self->{algorithm};
}

=item $ppr->salt

Returns the salt, in raw form.

=cut

sub salt($) {
	my Authen::Passphrase::SaltedDigest $self = shift;
	return $self->{salt};
}

=item $ppr->salt_hex

Returns the salt, as a string of hexadecimal digits.

=cut

sub salt_hex($) {
	my Authen::Passphrase::SaltedDigest $self = shift;
	return unpack("H*", $self->{salt});
}

=item $ppr->hash

Returns the hash value, in raw form.

=cut

sub hash($) {
	my Authen::Passphrase::SaltedDigest $self = shift;
	return $self->{hash};
}

=item $ppr->hash_hex

Returns the hash value, as a string of hexadecimal digits.

=cut

sub hash_hex($) {
	my Authen::Passphrase::SaltedDigest $self = shift;
	return unpack("H*", $self->{hash});
}

=item $ppr->match(PASSPHRASE)

=item $ppr->as_rfc2307

These methods are part of the standard C<Authen::Passphrase> interface.
Only passphrase recognisers using certain well-known digest algorithms
can be represented in RFC 2307 form.

=cut

sub match($$) {
	my Authen::Passphrase::SaltedDigest $self = shift;
	my($passphrase) = @_;
	my $ctx = Digest->new($self->{algorithm});
	$ctx->add($passphrase);
	$ctx->add($self->{salt});
	return $ctx->digest eq $self->{hash};
}

my %rfc2307_scheme = (
	"MD5" => "MD5",
	"SHA-1" => "SHA",
	"SHA1" => "SHA",
);

sub as_rfc2307($) {
	my Authen::Passphrase::SaltedDigest $self = shift;
	my $scheme = $rfc2307_scheme{$self->{algorithm}};
	croak "don't know RFC 2307 scheme identifier for digest algorithm ".
			$self->{algorithm}
		unless defined $scheme;
	return "{".($self->{salt} eq "" ? "" : "S").$scheme."}".
		encode_base64($self->{hash}.$self->{salt}, "");
}

=back

=head1 SEE ALSO

L<Authen::Passphrase>,
L<Crypt::Passwd>

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
