use Test::More tests => 46;

BEGIN { use_ok "Authen::Passphrase::SaltedDigest"; }

SKIP: {
eval { Digest->new("SHA-1"); };
skip "no SHA-1 facility", 45 unless $@ eq "";

my %pprs;
while(<DATA>) {
	chomp;
	s/(\S+) (\S+) *//;
	my($salt, $hash) = ($1, $2);
	my $ppr = Authen::Passphrase::SaltedDigest
			->new(algorithm => "SHA-1",
			      salt_hex => $salt, hash_hex => $hash);
	ok $ppr;
	is $ppr->salt_hex, $salt;
	is $ppr->hash_hex, $hash;
	eval { $ppr->passphrase };
	isnt $@, "";
	$pprs{$_} = $ppr;
}

foreach my $rightphrase (sort keys %pprs) {
	my $ppr = $pprs{$rightphrase};
	foreach my $passphrase (sort keys %pprs) {
		ok ($ppr->match($passphrase) xor $passphrase ne $rightphrase);
	}
}

}

__DATA__
616263 a9993e364706816aba3e25717850c26c9cd0d89d
717765 7cd928d1e6457c57c01f3c9442177fc62cafa56f 0
212121 2fee6a4e9b98f3bd6de8b1960cfb37f8b44d8bb1 1
787878 76cdd1408a02a44687fe87c98f8dc43678c4ef5f foo
707966 b264504de2719cebf898608cf950e1da5f3ae28f supercalifragilisticexpialidocious
