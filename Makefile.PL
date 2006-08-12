use ExtUtils::MakeMaker;

WriteMakefile(
	NAME => "Authen::Passphrase",
	VERSION_FROM => "lib/Authen/Passphrase.pm",
	PREREQ_PM => {
		Crypt::DES => 0,
		Crypt::Eksblowfish => "0.000",
		Crypt::PasswdMD5 => "1.0",
		Crypt::UnixCrypt_XS => "0.05",
		Data::Entropy::Algorithms => "0.000",
		Digest => "1.00",
		Digest::MD4 => "1.2",
		Digest::MD5 => "1.9953",
		MIME::Base64 => "2.21",
		Module::Runtime => "0.001",
		Params::Classify => "0.000",
	},
);
