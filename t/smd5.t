use Test::More tests => 46;

BEGIN { use_ok "Authen::Passphrase::SaltedDigest"; }

SKIP: {
eval { Digest->new("MD5"); };
skip "no MD5 facility", 45 unless $@ eq "";

my %pprs;
while(<DATA>) {
	chomp;
	s/(\S+) (\S+) *//;
	my($salt, $hash) = ($1, $2);
	my $ppr = Authen::Passphrase::SaltedDigest
			->new(algorithm => "MD5",
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
616263 900150983cd24fb0d6963f7d28e17f72
717765 ce97e12b13baef6403b5456f8fc2ce99 0
212121 b097f957c235fd286364dc2084b2546d 1
787878 097412258a515fc61cfe73f421f58b8f foo
707966 c676f3ddf4b4ed188a89d73525ff678e supercalifragilisticexpialidocious
