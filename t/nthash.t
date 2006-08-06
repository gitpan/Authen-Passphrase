use Test::More tests => 56;

BEGIN { use_ok "Authen::Passphrase::NTHash"; }

my %pprs;
my $i = 0;
while(<DATA>) {
	chomp;
	s/(\S+) *//;
	my $hash_hex = $1;
	my $hash = pack("H*", $hash_hex);
	my $ppr = ($i++ & 1) ?
			Authen::Passphrase::NTHash->new(hash => $hash) :
			Authen::Passphrase::NTHash->new(hash_hex => $hash_hex);
	ok $ppr;
	is $ppr->hash_hex, $hash_hex;
	is $ppr->hash, $hash;
	eval { $ppr->passphrase };
	isnt $@, "";
	is $ppr->as_crypt, "\$3\$\$".$hash_hex;
	is $ppr->as_rfc2307, "{CRYPT}\$3\$\$".$hash_hex;
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
