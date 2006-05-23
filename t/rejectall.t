use Test::More tests => 10;

BEGIN { use_ok "Authen::Passphrase::RejectAll"; }

my $ppr = Authen::Passphrase::RejectAll->new;
ok $ppr;

foreach my $passphrase("", qw(0 1 foo supercalifragilisticexpialidocious)) {
	ok !$ppr->match($passphrase);
}

eval { $ppr->passphrase };
isnt $@, "";

is $ppr->as_crypt, "*";
is $ppr->as_rfc2307, "{CRYPT}*";
