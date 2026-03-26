use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;

my $orig_stdout;
my $orig_stderr;

BEGIN {
	open($orig_stdout, '>&', \*STDOUT) or die $!;
	open($orig_stderr, '>&', \*STDERR) or die $!;
}

my $node = PostgreSQL::Test::Cluster->new('regress');
$node->init;
$node->append_conf('postgresql.conf', "shared_preload_libraries = 'pg_tde'");
$node->start;

open(STDOUT, '>&', $orig_stdout) or die $!;
open(STDERR, '>&', $orig_stderr) or die $!;

my @tests = qw(
	access_control
	alter_index
	cache_alloc
	change_access_method
	create_database
	default_principal_key
	delete_principal_key
	insert_update_delete
	key_provider
	kmip_test
	partition_table
	pg_tde_is_encrypted
	recreate_storage
	relocate
	tablespace
	toast_decrypt
	vault_v2_test
	version
);

system(
	$ENV{PG_REGRESS},
	'--host' => $node->host,
	'--port' => $node->port,
	@tests,
);

$node->stop;
