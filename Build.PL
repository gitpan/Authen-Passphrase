use warnings;
use strict;

use Module::Build;

Module::Build->new(
	module_name => "Authen::Passphrase",
	license => "perl",
	build_requires => {
		"MIME::Base64" => "2.21",
		"Module::Build" => 0,
		"Test::More" => 0,
		"perl" => "5.006",
		"strict" => 0,
		"warnings" => 0,
	},
	requires => {
		"Authen::DecHpwd" => "2.003",
		"Carp" => 0,
		"Crypt::Blowfish" => "2.00",
		"Crypt::DES" => 0,
		"Crypt::Eksblowfish::Bcrypt" => "0.005",
		"Crypt::MySQL" => "0.03",
		"Crypt::PasswdMD5" => "1.0",
		"Crypt::UnixCrypt_XS" => "0.08",
		"Data::Entropy::Algorithms" => 0,
		"Digest" => "1.00",
		"Digest::MD4" => "1.2",
		"Digest::MD5" => "1.9953",
		"Digest::SHA1" => 0,
		"MIME::Base64" => "2.21",
		"Module::Runtime" => "0.005",
		"Params::Classify" => 0,
		"base" => 0,
		"fields" => 0,
		"perl" => "5.006",
		"strict" => 0,
		"warnings" => 0,
	},
	dynamic_config => 0,
	meta_add => { distribution_type => "module" },
	create_makefile_pl => "passthrough",
	sign => 1,
)->create_build_script;

exit 0;
