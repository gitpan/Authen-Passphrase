use Test::More tests => 51;

BEGIN { use_ok "Authen::Passphrase::NTHash"; }

my %pprs;
while(<DATA>) {
	chomp;
	s/(\S+) *//;
	my $hash = $1;
	my $ppr = Authen::Passphrase::NTHash->new(hash_hex => $hash);
	ok $ppr;
	is $ppr->hash_hex, $hash;
	eval { $ppr->passphrase };
	isnt $@, "";
	is $ppr->as_crypt, "\$3\$\$".$hash;
	is $ppr->as_rfc2307, "{CRYPT}\$3\$\$".$hash;
	$pprs{$_} = $ppr;
}

foreach my $rightphrase (sort keys %pprs) {
	my $ppr = $pprs{$rightphrase};
	foreach my $passphrase (sort keys %pprs) {
		ok ($ppr->match($passphrase) xor $passphrase ne $rightphrase);
	}
}

__DATA__
31d6cfe0d16ae931b73c59d7e0c089c0
7bc26760a19fc23e0996daa99744ca80 0
69943c5e63b4d2c104dbbcc15138b72b 1
ac8e657f83df82beea5d43bdaf7800cc foo
f5295d5b0a47abecb70ed08bdb6d4e6e supercalifragilisticexpialidocious
