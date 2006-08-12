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
to control access to Unix user accounts.  The same textual format has
been adopted and extended by other passphrase-handling software such as
password crackers.

For historical reasons, there are several different syntaxes used in this
format.  The original DES-based password scheme represents its hashes
simply as a string of thirteen base 64 digits.  An extended variant of
this scheme uses nineteen base 64 digits, preceded by an "B<_>" marker.
A more general syntax was developed later, which starts the string with
"B<$>", an alphanumeric scheme identifier, and another "B<$>".

In addition to actual passphrase hashes, the crypt format can also
represent a couple of special cases.  The empty string indicates that
there is no access control; it is possible to login without giving a
passphrase.  Finally, any string that is not a possible output of crypt()
may be used to prevent login completely; "B<*>" is the usual choice,
but other strings are used too.

crypt strings are intended to be used in text files that use colon and
newline characters as delimiters.  This module treats the crypt string
syntax as being limited to ASCII graphic characters excluding colon.

=head2 RFC 2307 encoding

RFC 2307 describes an encoding system for passphrase hashes, to be used
in the "B<userPassword>" attribute in LDAP databases.  It encodes hashes
as ASCII text, and supports several passphrase schemes in an extensible
way by starting the encoding with an alphanumeric scheme identifier
enclosed in braces.  There are several standard scheme identifiers.
The "B<{CRYPT}>" scheme allows the use of any crypt encoding.

This module treats the RFC 2307 string syntax as being limited to ASCII
graphic characters.

The RFC 2307 encoding is a good one, and is recommended for storage and
exchange of passphrase hashes.

=cut

package Authen::Passphrase;

use warnings;
use strict;

use Carp qw(croak);
use MIME::Base64 2.21 qw(decode_base64);

our $VERSION = "0.002";

=head1 CONSTRUCTORS

=over

=item Authen::Passphrase->from_crypt(PASSWD)

Returns a passphrase recogniser object matching the supplied crypt
encoding.  This constructor may only be called on the base class, not
any subclass.

The specific passphrase recogniser class is loaded at runtime, so
successfully loading C<Authen::Passphrase> does not guarantee that
it will be possible to use a specific type of passphrase recogniser.
If necessary, check separately for presence and loadability of the
recogniser class.

Known scheme identifiers:

=over

=cut

my %crypt_scheme_handler;

=item B<$1$>

A baroque passphrase scheme based on MD5, designed by
Poul-Henning Kamp and originally implemented in FreeBSD.  See
L<Authen::Passphrase::MD5Crypt>.

=cut

$crypt_scheme_handler{"1"} = sub($) {
	my($passwd) = @_;
	$passwd =~ m#\A\$1\$([!-~]{0,8})\$([./0-9A-Za-z]{22})\z#
		or croak "malformed \$1\$ data";
	require Authen::Passphrase::MD5Crypt;
	return Authen::Passphrase::MD5Crypt
		->new(salt => $1, hash_base64 => $2);
};

=item B<$2$>

=item B<$2a$>

Two versions of a passphrase scheme based on Blowfish,
designed by Niels Provos and David Mazieres for OpenBSD.  See
L<Authen::Passphrase::BlowfishCrypt>.

=cut

$crypt_scheme_handler{"2"} = sub($) {
	my($passwd) = @_;
	$passwd =~ m#\A\$2(a?)\$([0-9]{2})\$
			([./A-Za-z0-9]{22})([./A-Za-z0-9]{31})\z#x
		or croak "malformed \$2\$ data";
	require Authen::Passphrase::BlowfishCrypt;
	return Authen::Passphrase::BlowfishCrypt->new(
			key_nul => $1, cost => $2,
			salt_base64 => $3, hash_base64 => $4);
};

$crypt_scheme_handler{"2a"} = $crypt_scheme_handler{"2"};

=item B<$3$>

The NT-Hash scheme, which stores the MD4 hash of the passphrase expressed
in Unicode.  See L<Authen::Passphrase::NTHash>.

=cut

$crypt_scheme_handler{"3"} = sub($) {
	my($passwd) = @_;
	$passwd =~ m#\A\$3\$\$([0-9a-f]{32})\z#
		or croak "malformed \$3\$ data";
	require Authen::Passphrase::NTHash;
	return Authen::Passphrase::NTHash->new(hash_hex => $1);
};

=item B<$IPB2$>

Invision Power Board 2.x salted MD5

=item B<$K4$>

Kerberos AFS DES

=item B<$LM$>

Half of the Microsoft LAN Manager hash scheme.  The two
halves of a LAN Manager hash can be separated and manipulated
independently; this represents such an isolated half.  See
L<Authen::Passphrase::LANManagerHalf>.

=cut

$crypt_scheme_handler{"LM"} = sub($) {
	my($passwd) = @_;
	$passwd =~ m#\A\$LM\$([0-9a-f]{16})\z#
		or croak "malformed \$LM\$ data";
	require Authen::Passphrase::LANManagerHalf;
	return Authen::Passphrase::LANManagerHalf->new(hash_hex => $1);
};

=item B<$NT$>

The NT-Hash scheme, which stores the MD4 hash of the passphrase expressed
in Unicode.  See L<Authen::Passphrase::NTHash>.

The B<$3$> identifier refers to the same hash algorithm, but has a
slightly different textual format (an extra "B<$>").

=cut

$crypt_scheme_handler{"NT"} = sub($) {
	my($passwd) = @_;
	$passwd =~ m#\A\$NT\$([0-9a-f]{32})\z#
		or croak "malformed \$NT\$ data";
	require Authen::Passphrase::NTHash;
	return Authen::Passphrase::NTHash->new(hash_hex => $1);
};

=item B<$P$>

Portable PHP password hash (see L<http://www.openwall.com/phpass/>)

=item B<$VMS1$>

=item B<$VMS2$>

=item B<$VMS3$>

Three variants of the Purdy polynomial system used in VMS.

=item B<$af$>

Kerberos v4 TGT

=item B<$apr1$>

A variant of the B<$1$> scheme, used by Apache.

=item B<$krb5$>

Kerberos v5 TGT

=back

The historical formats supported are:

=over

=item "I<bbbbbbbbbbbbb>"

("I<b>" represents a base 64 digit.)  The original DES-based Unix password
hash scheme.  See L<Authen::Passphrase::DESCrypt>.

=item "B<_>I<bbbbbbbbbbbbbbbbbbb>"

("I<b>" represents a base 64 digit.)  Extended DES-based passphrase hash
scheme from BSDi.  See L<Authen::Passphrase::DESCrypt>.

=item ""

Accept any passphrase.  See L<Authen::Passphrase::AcceptAll>.

=item "B<*>"

To handle historical practice, anything non-empty but shorter than 13
characters and not starting with "B<$>" is treated as deliberately
rejecting all passphrases.  (See L<Authen::Passphrase::RejectAll>.)
Anything 13 characters or longer, or starting with "B<$>", that is not
recognised as a hash is treated as an error.

=back

There are also two different passphrase schemes that use a crypt string
consisting of 24 base 64 digits.  One is named "bigcrypt" and appears in
HP-UX, Digital Unix, and OSF/1 (see L<Authen::Passphrase::BigCrypt>).
The other is named "crypt16" and appears in Ultrix and Tru64 (see
L<Authen::Passphrase::Crypt16>).  These schemes conflict.  Neither of
them is accepted as a crypt string by this constructor; such strings
are regarded as invalid encodings.

=cut

sub from_crypt($$) {
	my($class, $passwd) = @_;
	croak "from_crypt constructor called on $class instead of ".__PACKAGE__
		unless $class eq __PACKAGE__;
	croak "invalid character in crypt string" if $passwd =~ /[^!-9;-~]/;
	if($passwd =~ /\A\$([0-9A-Za-z]+)\$/) {
		my $scheme = $1;
		my $handler = $crypt_scheme_handler{$scheme};
		croak "unrecognised crypt scheme \$$scheme\$"
			unless defined $handler;
		return $handler->($passwd);
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
	} elsif($passwd eq "") {
		require Authen::Passphrase::AcceptAll;
		return Authen::Passphrase::AcceptAll->new;
	} elsif(length($passwd) < 13 && $passwd !~ /\A\$/) {
		require Authen::Passphrase::RejectAll;
		return Authen::Passphrase::RejectAll->new;
	} else {
		croak "bad crypt syntax in \"$passwd\"";
	}
}

=item Authen::Passphrase->from_rfc2307(USERPASSWORD)

Returns a passphrase recogniser object matching the supplied RFC 2307
encoding.  This constructor may only be called on the base class, not
any subclass.

The specific passphrase recogniser class is loaded at runtime.  See the
note about this for the C<from_crypt> constructor above.

Known scheme identifiers:

=over

=cut

my %rfc2307_scheme_handler;

my $rfc2307_placeholder = sub($) {
	my($userpassword) = @_;
	$userpassword =~ /\A\{(.*?)\}/;
	my $scheme = uc($1);
	croak "{$scheme} is a placeholder";
};

=item B<{CLEARTEXT}>

Passphrase stored in cleartext.  See L<Authen::Passphrase::Clear>.

=cut

$rfc2307_scheme_handler{CLEARTEXT} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{.*?\}//;
	require Authen::Passphrase::Clear;
	return Authen::Passphrase::Clear->new($userpassword);
};

=item B<{CRYPT}>

Any crypt encoding.

=cut

$rfc2307_scheme_handler{CRYPT} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{.*?\}//;
	return Authen::Passphrase->from_crypt($userpassword);
};

=item B<{K5KEY}>

Not a real passphrase scheme, but a placeholder to indicate that a
Kerberos key stored separately should be checked against.  No data
follows the scheme identifier.

=cut

$rfc2307_scheme_handler{K5KEY} = $rfc2307_placeholder;

=item B<{KERBEROS}>

Not a real passphrase scheme, but a placeholder to indicate that
Kerberos should be invoked to check against a user's passphrase.
The scheme identifier is followed by the user's username, in the form
"I<name>B<@>I<realm>".

=cut

$rfc2307_scheme_handler{KERBEROS} = $rfc2307_placeholder;

=item B<{LANM}>

Synonym for B<{LANMAN}>, used by CommuniGate Pro.

=cut

$rfc2307_scheme_handler{"LANM"} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ /\A\{.*?\}([0-9a-fA-F]{32})\z/
		or croak "malformed {LANMAN} data";
	require Authen::Passphrase::LANManager;
	return Authen::Passphrase::LANManager->new(hash_hex => $1);
};

=item B<{LANMAN}>

The Microsoft LAN Manager hash scheme.  See
L<Authen::Passphrase::LANManager>.

=cut

$rfc2307_scheme_handler{"LANMAN"} = $rfc2307_scheme_handler{"LANM"};

=item B<{MD4}>

The MD4 digest of the passphrase is stored.  See
L<Authen::Passphrase::SaltedDigest>.

=cut

$rfc2307_scheme_handler{MD4} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{.*?\}//;
	require Authen::Passphrase::SaltedDigest;
	return Authen::Passphrase::SaltedDigest->new(algorithm => "MD4",
		hash => decode_base64($userpassword));
};

=item B<{MD5}>

The MD5 digest of the passphrase is stored.  See
L<Authen::Passphrase::SaltedDigest>.

=cut

$rfc2307_scheme_handler{MD5} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{.*?\}//;
	require Authen::Passphrase::SaltedDigest;
	return Authen::Passphrase::SaltedDigest->new(algorithm => "MD5",
		hash => decode_base64($userpassword));
};

=item B<{MSNT}>

The NT-Hash scheme, which stores the MD4 hash of the passphrase expressed
in Unicode.  See L<Authen::Passphrase::NTHash>.

=cut

$rfc2307_scheme_handler{"MSNT"} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ m#\A\{.*?\}([0-9A-Fa-f]{32})\z#
		or croak "malformed {MSNT} data";
	require Authen::Passphrase::NTHash;
	return Authen::Passphrase::NTHash->new(hash_hex => $1);
};

=item B<{NS-MTA-MD5}>

An MD5-based scheme used by Netscape Mail Server.  See
L<Authen::Passphrase::NetscapeMail>.

=cut

$rfc2307_scheme_handler{"NS-MTA-MD5"} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ /\A\{.*?\}([0-9a-f]{32})([!-~]{32})\z/
		or croak "malformed {NS-MTA-MD5} data";
	require Authen::Passphrase::NetscapeMail;
	return Authen::Passphrase::NetscapeMail
		->new(salt => $2, hash_hex => $1);
};

=item B<{RMD160}>

The RIPEMD-160 digest of the passphrase is stored.  See
L<Authen::Passphrase::SaltedDigest>.

=cut

$rfc2307_scheme_handler{RMD160} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{.*?\}//;
	require Authen::Passphrase::SaltedDigest;
	return Authen::Passphrase::SaltedDigest->new(
		algorithm => "Crypt::RIPEMD160-",
		hash => decode_base64($userpassword));
};

=item B<{SASL}>

Not a real passphrase scheme, but a placeholder to indicate that SASL
should be invoked to check against a user's passphrase.  The scheme
identifier is followed by the user's username.

=cut

$rfc2307_scheme_handler{SASL} = $rfc2307_placeholder;

=item B<{SHA}>

The SHA-1 digest of the passphrase is stored.  See
L<Authen::Passphrase::SaltedDigest>.

=cut

$rfc2307_scheme_handler{SHA} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{.*?\}//;
	require Authen::Passphrase::SaltedDigest;
	return Authen::Passphrase::SaltedDigest->new(algorithm => "SHA-1",
		hash => decode_base64($userpassword));
};

=item B<{SMD5}>

The MD5 digest of the passphrase plus a salt is stored.  See
L<Authen::Passphrase::SaltedDigest>.

=cut

$rfc2307_scheme_handler{SMD5} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{.*?\}//;
	my $hash_and_salt = decode_base64($userpassword);
	croak "not a valid MD5 hash" if length($hash_and_salt) < 16;
	require Authen::Passphrase::SaltedDigest;
	return Authen::Passphrase::SaltedDigest->new(algorithm => "MD5",
		salt => substr($hash_and_salt, 16),
		hash => substr($hash_and_salt, 0, 16));
};

=item B<{SSHA}>

The SHA-1 digest of the passphrase plus a salt is stored.
See L<Authen::Passphrase::SaltedDigest>.

=cut

$rfc2307_scheme_handler{SSHA} = sub($) {
	my($userpassword) = @_;
	$userpassword =~ s/\A\{.*?\}//;
	my $hash_and_salt = decode_base64($userpassword);
	croak "not a valid SHA-1 hash" if length($hash_and_salt) < 20;
	require Authen::Passphrase::SaltedDigest;
	return Authen::Passphrase::SaltedDigest->new(algorithm => "SHA-1",
		salt => substr($hash_and_salt, 20),
		hash => substr($hash_and_salt, 0, 20));
};

=item B<{UNIX}>

Not a real passphrase scheme, but a placeholder to indicate that Unix
mechanisms should be used to check against a Unix user's login passphrase.
The scheme identifier is followed by the user's username.

=cut

$rfc2307_scheme_handler{UNIX} = $rfc2307_placeholder;

=item B<{WM-CRY}>

Synonym for B<{CRYPT}>, used by CommuniGate Pro.

=cut

$rfc2307_scheme_handler{"WM-CRY"} = $rfc2307_scheme_handler{CRYPT};

=back

=cut

sub from_rfc2307($$) {
	my($class, $userpassword) = @_;
	croak "from_rfc2307 constructor called on $class instead of ".
			__PACKAGE__
		unless $class eq __PACKAGE__;
	croak "invalid character in RFC 2307 string"
		if $userpassword =~ /[^!-~]/;
	$userpassword =~ /\A\{([-0-9a-z]+)\}/i
		or croak "bad RFC 2307 syntax in \"$userpassword\"";
	my $scheme = uc($1);
	my $handler = $rfc2307_scheme_handler{$scheme};
	croak "unrecognised RFC 2307 scheme {$scheme}" unless defined $handler;
	return $handler->($userpassword);
}

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
