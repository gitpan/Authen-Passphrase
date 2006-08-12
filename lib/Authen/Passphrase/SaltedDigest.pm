=head1 NAME

Authen::Passphrase::SaltedDigest - passphrases using the generic salted
digest algorithm

=head1 SYNOPSIS

	use Authen::Passphrase::SaltedDigest;

	$ppr = Authen::Passphrase::SaltedDigest->new(
		algorithm => "SHA-1",
		salt_hex => "a9f524b1e819e96d8cc7".
			    "a04d5471e8b10c84e596",
		hash_hex => "8270d9d1a345d3806ab2".
			    "3b0385702e10f1acc943");

	$ppr = Authen::Passphrase::SaltedDigest->new(
		algorithm => "SHA-1", salt_random => 20,
		passphrase => "passphrase");

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

The strength depends entirely on the choice of digest algorithm, so
choose according to the level of security required.  SHA-1 is suitable for
most applications, but recent work has revealed weaknesses in the basic
structure of MD5, SHA-1, SHA-256, and all similar digest algorithms.
A new generation of digest algorithms will probably emerge sometime
around 2008.

Digest algorithms are generally designed to be as efficient to compute
as possible for their level of cryptographic strength.  An unbroken
digest algorithm makes brute force the most efficient way to attack it,
but makes no effort to resist a brute force attack.  This is a concern
in some passphrase-using applications.

The use of this kind of passphrase scheme is generally recommended for
new systems.  Choice of digest algorithm is important: SHA-1 is suitable
for most applications.  If efficiency of brute force attack is a concern,
see L<Authen::Passphrase::BlowfishCrypt> for an algorithm designed to
be expensive to compute.

=cut

package Authen::Passphrase::SaltedDigest;

use warnings;
use strict;

use Carp qw(croak);
use Data::Entropy::Algorithms 0.000 qw(rand_bits);
use Digest 1.00;
use MIME::Base64 2.21 qw(encode_base64);
use Module::Runtime 0.001 qw(is_valid_module_name use_module);
use Params::Classify 0.000 qw(is_string is_blessed);

our $VERSION = "0.002";

use base qw(Authen::Passphrase);
use fields qw(algorithm salt hash);

=head1 CONSTRUCTOR

=over

=item Authen::Passphrase::SaltedDigest->new(ATTR => VALUE, ...)

Generates a new passphrase recogniser object using the generic salted
digest algorithm.  The following attributes may be given:

=over

=item B<algorithm>

Specifies the algorithm to use.  If it is a reference to a blessed object,
it must be possible to call the C<new> method on that object to generate
a digest context object.

If it is a string containing the subsequence "::" then it specifies
a module to use.  A plain package name in bareword syntax, optionally
preceded by "::" (so that top-level packages can be recognised as such),
is taken as a class name, on which the C<new> method will be called to
generate a digest context object.  The package name may optionally be
followed by "-" to cause automatic loading of the module, and the "-"
(if present) may optionally be followed by a version number that will
be checked against.  For example, "Digest::MD5-1.99_53" would load the
C<Digest::MD5> module and check that it is at least version 1.99_53
(which is the first version that can be used by this module).

A string not containing "::" and which is understood by C<< Digest->new >>
will be passed to that function to generate a digest context object.

Any other type of algorithm specifier has undefined behaviour.

The digest context objects must support at least the standard C<add>
and C<digest> methods.

=item B<salt>

The salt, as a raw string of bytes.  Defaults to the empty string,
yielding an unsalted scheme.

=item B<salt_hex>

The salt, as a string of hexadecimal digits.  Defaults to the empty
string, yielding an unsalted scheme.

=item B<salt_random>

Causes salt to be generated randomly.  The value given for this
attribute must be a non-negative integer, giving the number of bytes
of salt to generate.  (The same length as the hash is recommended.)
The source of randomness may be controlled by the facility described
in L<Data::Entropy>.

=item B<hash>

The hash, as a string of bytes.

=item B<hash_hex>

The hash, as a string of hexadecimal digits.

=item B<passphrase>

A passphrase that will be accepted.

=back

The digest algorithm must be given, and either the hash or the passphrase.

=cut

sub new($@) {
	my $class = shift;
	my __PACKAGE__ $self = fields::new($class);
	my $passphrase;
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
		} elsif($attr eq "salt_random") {
			croak "salt specified redundantly"
				if exists $self->{salt};
			croak "\"$value\" is not a valid salt length"
				unless $value == int($value) && $value >= 0;
			$self->{salt} = rand_bits($value * 8);
		} elsif($attr eq "hash") {
			croak "hash specified redundantly"
				if exists($self->{hash}) ||
					defined($passphrase);
			$value =~ m#\A[\x{0}-\x{ff}]*\z#
				or croak "\"$value\" is not a valid hash";
			$self->{hash} = $value;
		} elsif($attr eq "hash_hex") {
			croak "hash specified redundantly"
				if exists($self->{hash}) ||
					defined($passphrase);
			$value =~ m#\A(?:[0-9A-Fa-f]{2})+\z#
				or croak "\"$value\" is not a valid hash";
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
	croak "algorithm not specified" unless exists $self->{algorithm};
	$self->{salt} = "" unless exists $self->{salt};
	if(defined $passphrase) {
		$self->{hash} = $self->_hash_of($passphrase);
	} elsif(exists $self->{hash}) {
		croak "not a valid ".$self->{algorithm}." hash"
			unless length($self->{hash}) ==
				length($self->_hash_of(""));
	} else {
		croak "hash not specified";
	}
	return $self;
}

=back

=head1 METHODS

=over

=item $ppr->algorithm

Returns the digest algorithm, in the same form as supplied to the
constructor.

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

sub _hash_of($$) {
	my __PACKAGE__ $self = shift;
	my($passphrase) = @_;
	my $alg = $self->{algorithm};
	my $ctx;
	if(is_string($alg)) {
		if($alg =~ /::/) {
			$alg =~ /\A(?:::)?([\w:]+)
				   (-(\d[\d_]*(?:\._*\d[\d_]*)?)?)?\z/x
				or croak "module spec `$alg' not understood";
			my($pkgname, $load_p, $modver) = ($1, $2, $3);
			croak "bad package name `$pkgname'"
				unless is_valid_module_name($pkgname);
			if($load_p) {
				if(defined $modver) {
					$modver =~ tr/_//d;
					use_module($pkgname, $modver);
				} else {
					use_module($pkgname);
				}
			}
			$ctx = $pkgname->new;
		} else {
			$ctx = Digest->new($alg);
		}
	} elsif(is_blessed($alg)) {
		$ctx = $alg->new;
	} else {
		croak "algorithm specifier `$alg' is of an unrecognised type";
	}
	$ctx->add($passphrase);
	$ctx->add($self->{salt});
	return $ctx->digest;
}

sub match($$) {
	my __PACKAGE__ $self = shift;
	my($passphrase) = @_;
	return $self->_hash_of($passphrase) eq $self->{hash};
}

my %rfc2307_scheme_for_digest_name = (
	"MD4" => "MD4",
	"MD5" => "MD5",
	"SHA-1" => "SHA",
	"SHA1" => "SHA",
);

my %rfc2307_scheme_for_package_name = (
	"Crypt::RIPEMD160" => "RMD160",
	"Digest::MD4" => "MD4",
	"Digest::MD5" => "MD5",
	"Digest::MD5::Perl" => "MD5",
	"Digest::Perl::MD4" => "MD4",
	"Digest::SHA" => "SHA",
	"Digest::SHA::PurePerl" => "SHA",
	"Digest::SHA1" => "SHA",
	"MD5" => "MD5",
	"RIPEMD160" => "RMD160",
);

sub as_rfc2307($) {
	my Authen::Passphrase::SaltedDigest $self = shift;
	my $alg = $self->{algorithm};
	my $scheme;
	if(is_string($alg)) {
		if($alg =~ /::/) {
			$scheme = $rfc2307_scheme_for_package_name{$1}
				if $alg =~ /\A(?:::)?([\w:]+)(?:-[0-9._]*)?\z/;
		} else {
			$scheme = $rfc2307_scheme_for_digest_name{$alg};
		}
	}
	croak "don't know RFC 2307 scheme identifier for digest algorithm $alg"
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
