use ExtUtils::MakeMaker;

WriteMakefile(
	NAME => "Authen::Passphrase",
	VERSION_FROM => "lib/Authen/Passphrase.pm",
	PREREQ_PM => {
		"Crypt::PasswdMD5" => "1.0",
		"Crypt::UnixCrypt_XS" => "0.05",
		"Digest" => undef,
		"Digest::MD4" => undef,
	},
);
