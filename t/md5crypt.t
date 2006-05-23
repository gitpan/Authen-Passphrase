use Test::More tests => 56;

BEGIN { use_ok "Authen::Passphrase::MD5Crypt"; }

my %pprs;
while(<DATA>) {
	chomp;
	s/(\S+) (\S+) *//;
	my($salt, $hash) = ($1, $2);
	my $ppr = Authen::Passphrase::MD5Crypt
			->new(salt => $salt, hash_base64 => $hash);
	ok $ppr;
	is $ppr->salt, $salt;
	is $ppr->hash_base64, $hash;
	eval { $ppr->passphrase };
	isnt $@, "";
	is $ppr->as_crypt, "\$1\$".$salt."\$".$hash;
	is $ppr->as_rfc2307, "{CRYPT}\$1\$".$salt."\$".$hash;
	$pprs{$_} = $ppr;
}

foreach my $rightphrase (sort keys %pprs) {
	my $ppr = $pprs{$rightphrase};
	foreach my $passphrase (sort keys %pprs) {
		ok ($ppr->match($passphrase) xor $passphrase ne $rightphrase);
	}
}

__DATA__
.ek8tjGw JlwHaPpGUeCpzvx6DSYt.0
ZoDb0wM1 TSZxQ/qndpG1yB9HqCMHg/ 0
Z7/4DX0p 6IBWggA5iXUKnYI7xhl6R1 1
RveEKWw9 //PkU.geQpEJRr7JoK7ey/ foo
Tdb1JRjV CTqZJJGDNwtm6ScQ2w6md/ supercalifragilisticexpialidocious
