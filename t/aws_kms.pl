use strict;
use warnings FATAL => 'all';
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

unless ($ENV{'AWS_KEY_ID'})
{
	if ($ENV{PG_TEST_REQUIRE_AWS})
	{
		BAIL_OUT('AWS required but not configured (PG_TEST_REQUIRE_AWS=1 set)');
	}
	plan skip_all => "AWS_KEY_ID not set";
}

my $aws_region = $ENV{'AWS_REGION'} or die "AWS_REGION not configured";
my $aws_server = $ENV{'AWS_SERVER'} || "https://kms.$aws_region.amazonaws.com";
my $aws_access_key = $ENV{'AWS_ACCESS_KEY'} or die "AWS_ACCESS_KEY not configured";;
my $aws_secret_key = $ENV{'AWS_SECRET_KEY'} or die "AWS_SECRET_KEY not configured";;
my $aws_key_id = $ENV{'AWS_KEY_ID'};

my $stdout;

my $node = PostgreSQL::Test::Cluster->new('main');
$node->init;
$node->append_conf('postgresql.conf', "shared_preload_libraries = 'pg_tde'");
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION pg_tde;');

$node->safe_psql(
	'postgres', qq(
	SELECT pg_tde_add_database_key_provider('aws-kms', 'aws',
											json_object(
												'server' VALUE '$aws_server',
												'region' VALUE '$aws_region',
												'accessKey' VALUE '$aws_access_key',
												'secretKey' VALUE '$aws_secret_key',
												'keyId' VALUE '$aws_key_id'));
	SELECT pg_tde_create_key_using_database_key_provider('key', 'aws');
	SELECT pg_tde_set_key_using_database_key_provider('key', 'aws');

	CREATE TABLE test_enc (x int PRIMARY KEY) USING tde_heap;
	INSERT INTO test_enc (x) VALUES (1), (2);
));

$stdout = $node->safe_psql('postgres', 'SELECT * FROM test_enc;');
is($stdout, "1\n2", 'can read test_enc');

$stdout = $node->safe_psql('postgres', 'SELECT pg_tde_verify_key();');
is($stdout, '', 'key verification succeeds');

$node->stop;

done_testing();
