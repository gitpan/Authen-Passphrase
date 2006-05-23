use Test::More tests => 10;

BEGIN { use_ok "Authen::Passphrase::AcceptAll"; }

my $ppr = Authen::Passphrase::AcceptAll->new;
ok $ppr;

foreach my $passphrase("", qw(0 1 foo supercalifragilisticexpialidocious)) {
	ok $ppr->match($passphrase);
}

is $ppr->passphrase, "";

is $ppr->as_crypt, "";
is $ppr->as_rfc2307, "{CRYPT}";
