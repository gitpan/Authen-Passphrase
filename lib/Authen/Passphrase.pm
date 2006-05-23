=head1 NAME

Authen::Passphrase - hashed passwords/passphrases as objects

=head1 SYNOPSIS

	use Authen::Passphrase;

	$ppr = Authen::Passphrase->from_crypt($passwd);
	$ppr = Authen::Passphrase->from_rfc2307($userPassword);

	if($ppr->match($passphrase)) { ...

	$passphrase = $ppr->passphrase;

	$crypt = $ppr->as_crypt;
	$userPassword = $ppr->as_rfc2307;

=head1 DESCRIPTION

This is the base class for a system of objects that encapsulate
passphrases.  An object of this type is a passphrase recogniser: its
job is to recognise whether an offered passphrase is the right one.
For security, such passphrase recognisers usually do not themselves know
the passphrase they are looking for; they can merely recognise it when
they see it.  There are many schemes in use to achieve this effect,
and the intent of this class is to provide a consistent interface to
them all, hiding the details.

The CPAN package Authen::Passphrase contains implementations of several
specific passphrase schemes in addition to the base class.

=head1 PASSPHRASE ENCODINGS

Because hashed passphrases frequently need to be stored, various encodings
of them have been devised.  This class has constructors and methods to
support these.

=head2 crypt encoding

The Unix crypt() function, which performs passphrase hashing, returns
hashes in a textual format intended to be stored in a text file.
In particular, such hashes are stored in /etc/passwd (and now /etc/shadow)
to control access to Unix user accounts.

For historical reasons, there are several different syntaxes used in this
format.  The original DES-based password scheme represents its hashes
simply as a string of thirteen base 64 digits.  An extended variant of
this scheme uses nineteen base 64 digits, preceded by an "B<_>" marker.
A more general syntax was developed later, which starts the string with
"B<$>", a numerical scheme identifier, and another "B<$>".

In addition to actual passphrase hashes, the crypt format can also
represent a couple of special cases.  The empty string indicates that
there is no access control; it is possible to login without giving a
passphrase.  Finally, any string that is not a possible output of crypt()
may be used to prevent login completely; "B<*>" is the usual choice,
but other strings are used too.

crypt strings are intended to be used in text files that use colon and
newline characters as delimiters.  This module treats the crypt string
syntax as being limited to ASCII printable characters excluding colon.

The crypt encoding is a poor choice for general encoding of passphrase
hashes.  It should be used only where required for compatibility.

=head2 RFC 2307 encoding

RFC 2307 describes an encoding system for passphrase hashes, to be used
in the "B<userPassword>" attribute in LDAP databases.  It encodes hashes
as ASCII text, and supports several passphrase schemes in an extensible
way by starting the encoding with an alphanumeric scheme identifier
enclosed in braces.  There are several standard scheme identifiers.
The "B<{CRYPT}>" scheme allows the use of any crypt encoding.

The RFC 2307 encoding is a good one, and is recommended for storage and
exchange of passphrase hashes.

=cut

package Authen::Passphrase;

use warnings;
use strict;

use Carp qw(croak);
use MIME::Base64 qw(decode_base64);

our $VERSION = "0.000";

=head1 CONSTRUCTORS

=over

=item Authen::Passphrase->from_crypt(PASSWD)

Returns a passphrase recogniser object matching the supplied crypt
encoding.

In the formats below, "I<b>" represents a base 64 digit, "I<h>" represents
a hexadecimal digit, and "I<d>" represents a decimal digit.  The following
formats are understood:

=over

=item "I<bbbbbbbbbbbbb>"

The original DES-based Unix password hash scheme.  See
L<Authen::Passphrase::DESCrypt>.

=item "B<_>I<bbbbbbbbbbbbbbbbbbb>"

Extended DES-based passphrase hash scheme from BSDi.  See
L<Authen::Passphrase::DESCrypt>.

=item "B<$1$>I<salt>B<$>I<bbbbbbbbbbbbbbbbbbbbbb>"

A baroque passphrase scheme based on MD5, originating in BSD.
See L<Authen::Passphrase::MD5Crypt>.

=item "B<$2$>I<dd>B<$>I<bbb...(53)...bbb>"

=item "B<$2a$>I<dd>B<$>I<bbb...(53)...bbb>"

Two versions of a passphrase scheme based on Blowfish, originating
in BSD.  Unimplemented at the time of writing, but if the
C<Authen::Passphrase::BlowfishCrypt> module exists at runtime then you
might be in luck.

=item "B<$3$$>I<hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh>"

The NT-Hash scheme, which stores the MD4 hash of the passphrase expressed
in Unicode.  See L<Authen::Passphrase::NTHash>.

=item ""

Accept any passphrase.  See L<Authen::Passphrase::AcceptAll>.

=item "B<*>"

To handle historical practice, anything non-empty but shorter than
13 characters is treated as deliberately rejecting all passphrases.
(See L<Authen::Passphrase::RejectAll>.)  Anything 13 characters or longer
that is not recognised as a hash is treated as an error.

=back

=cut

sub from_crypt($$) {
	my($class, $passwd) = @_;
	croak "invalid character in crypt string" if $passwd =~ /[^ -9;-~]/;
	if($passwd eq "") {
		require Authen::Passphrase::AcceptAll;
		return Authen::Passphrase::AcceptAll->new;
	} elsif(length($passwd) < 13) {
		require Authen::Passphrase::RejectAll;
		return Authen::Passphrase::RejectAll->new;
	} elsif($passwd =~ m#\A([./0-9A-Za-z]{2})([./0-9A-Za-z]{11})\z#) {
		require Authen::Passphrase::DESCrypt;
		return Authen::Passphrase::DESCrypt
				->new(salt_base64 => $1, hash_base64 => $2);
	} elsif($passwd =~ m#\A_([./0-9A-Za-z]{4})([./0-9A-Za-z]{4})
				([./0-9A-Za-z]{11})\z#x) {
		require Authen::Passphrase::DESCrypt;
		return Authen::Passphrase::DESCrypt
				->new(fold => 1, nrounds_base64 => $1,
				      salt_base64 => $2, hash_base64 => $3);
	} elsif($passwd =~ m#\A\$1\$([^\$]{0,8})\$([./0-9A-Za-z]{22})\z#) {
		require Authen::Passphrase::MD5Crypt;
		return Authen::Passphrase::MD5Crypt
				->new(salt => $1, hash_base64 => $2);
	} elsif($passwd =~ m#\A\$2(a)?\$([0-9]{2})\$
				([./A-Za-z0-9]{21}[.Oeu])
				([./A-Za-z0-9]{30}[.CGKOSWaeimquy26])\z#x) {
		require Authen::Passphrase::BlowfishCrypt;
		return Authen::Passphrase::BlowfishCrypt->new(
				key_nul => defined($1),
				keying_nrounds_log2 => $2,
				salt_base64 => $3,
				hash_base64 => $4);
	} elsif($passwd =~ m#\A\$3\$\$([0-9a-f]{32})\z#) {
		require Authen::Passphrase::NTHash;
		return Authen::Passphrase::NTHash->new(hash_hex => $1);
	} else {
		croak "\"$passwd\" is not a supported type of crypt string";
	}
}

=item Authen::Passphrase->from_rfc2307(USERPASSWORD)

Returns a passphrase recogniser object matching the supplied RFC 2307
encoding.  Known schemes:

=over

=item B<{CLEARTEXT}>

Passphrase stored in cleartext.  See L<Authen::Passphrase::Clear>.

=item B<{CRYPT}>

Any crypt encoding.

=item B<{MD5}>

The MD5 digest of the passphrase is stored.  See
L<Authen::Passphrase::SaltedDigest>.

=item B<{SHA}>

The SHA-1 digest of the passphrase is stored.  See
L<Authen::Passphrase::SaltedDigest>.

=item B<{SMD5}>

The MD5 digest of the passphrase plus a salt is stored.  See
L<Authen::Passphrase::SaltedDigest>.

=item B<{SSHA}>

The SHA-1 digest of the passphrase plus a salt is stored.
See L<Authen::Passphrase::SaltedDigest>.

=back

=cut

my %rfc2307_scheme_handler;

sub from_rfc2307($$) {
	my($class, $userpassword) = @_;
	$userpassword =~ /\A\{([0-9a-z]+)\}/i
		or croak "bad RFC 2307 syntax in \"$userpassword\"";
	my $scheme = uc($1);
	my $handler = $rfc2307_scheme_handler{$scheme};
	croak "unrecognised RFC 2307 scheme {$scheme}" unless defined $handler;
	return $handler->($userpassword);
}

$rfc2307_scheme_handler{CLEARTEXT} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{CLEARTEXT\}//i;
	require Authen::Passphrase::Clear;
	return Authen::Passphrase::Clear->new($userpassword);
};

$rfc2307_scheme_handler{CRYPT} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{CRYPT\}//i;
	return Authen::Passphrase->from_crypt($userpassword);
};

$rfc2307_scheme_handler{MD5} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{MD5\}//i;
	require Authen::Passphrase::SaltedDigest;
	return Authen::Passphrase::SaltedDigest->new(algorithm => "MD5",
		hash => decode_base64($userpassword));
};

$rfc2307_scheme_handler{SHA} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{SHA\}//i;
	require Authen::Passphrase::SaltedDigest;
	return Authen::Passphrase::SaltedDigest->new(algorithm => "SHA-1",
		hash => decode_base64($userpassword));
};

$rfc2307_scheme_handler{SMD5} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{SMD5\}//i;
	my $hash_and_salt = decode_base64($userpassword);
	croak "not a valid MD5 hash" if length($hash_and_salt) < 16;
	require Authen::Passphrase::SaltedDigest;
	return Authen::Passphrase::SaltedDigest->new(algorithm => "MD5",
		salt => substr($hash_and_salt, 16),
		hash => substr($hash_and_salt, 0, 16));
};

$rfc2307_scheme_handler{SSHA} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{SSHA\}//i;
	my $hash_and_salt = decode_base64($userpassword);
	croak "not a valid SHA-1 hash" if length($hash_and_salt) < 20;
	require Authen::Passphrase::SaltedDigest;
	return Authen::Passphrase::SaltedDigest->new(algorithm => "SHA-1",
		salt => substr($hash_and_salt, 20),
		hash => substr($hash_and_salt, 0, 20));
};

=back

=head1 METHODS

=over

=item $ppr->match(PASSPHRASE)

Checks whether the supplied passphrase is correct.  Returns a boolean.

=item $ppr->passphrase

If a matching passphrase can be easily determined by the passphrase
recogniser then this method will return it.  This is only feasible for
very weak passphrase schemes.  The method C<die>s if it is infeasible.

=item $ppr->as_crypt

Encodes the passphrase recogniser in crypt format and returns the encoded
result.  C<die>s if the passphrase recogniser cannot be represented in
this form.

=item $ppr->as_rfc2307

Encodes the passphrase recogniser in RFC 2307 format and returns
the encoded result.  C<die>s if the passphrase recogniser cannot be
represented in this form.

=cut

sub as_rfc2307($) { "{CRYPT}".$_[0]->as_crypt }

=back

=head1 SUBCLASSING

This class is designed to be subclassed, and cannot be instantiated alone.
Any subclass must implement the C<match> method.  That is the minimum
required.

Subclasses should implement the C<as_crypt> and C<as_rfc2307> methods
wherever possible, with the following exception.  If a passphrase scheme
has a crypt encoding but no native RFC 2307 encoding, so it can be RFC
2307 encoded only by using the "B<{CRYPT}>" scheme, then C<as_rfc2307>
should I<not> be implemented by the class.  There is a default
implementation of the C<as_rfc_2307> method that uses "B<{CRYPT}>"
automatically for passphrase schemes that do not have a native RFC
2307 encoding.

Implementation of the C<passphrase> method is entirely optional.
It should be attempted only for schemes that are so ludicrously weak as
to allow passphrases to be cracked reliably in a short time.  Dictionary
attacks are not appropriate implementations.

=head1 SEE ALSO

L<crypt(3)>,
RFC 2307

=head1 AUTHOR

Andrew Main (Zefram) <zefram@fysh.org>

=head1 COPYRIGHT

Copyright (C) 2006 Andrew Main (Zefram) <zefram@fysh.org>

This module is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;
