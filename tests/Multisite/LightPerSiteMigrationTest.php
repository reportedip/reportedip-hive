<?php
/**
 * Multisite tests of the update from Hive Light activated per site: v25
 * copies the rows of each sub-site's Light tables into the network tables,
 * v24 and the attempt merge work on a real network database.
 *
 * The sub-site and its Light tables are created once per class (DDL commits
 * the test transaction); every v25 test seeds its rows inside the
 * transaction, which the test case rolls back. The v24 and merge tests
 * change the network schema and restore it themselves.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Light_Per_Site_Migration_Test extends WP_UnitTestCase {

	/**
	 * Sub-site that ran Light.
	 *
	 * @var int
	 */
	private static $site = 0;

	/**
	 * Light 1.3.9 table definitions, verbatim from its `install_schema()`.
	 *
	 * @param string $prefix Site prefix.
	 * @return string[]
	 */
	private static function light_schema( $prefix ) {
		return array(
			"CREATE TABLE {$prefix}reportedip_hive_attempts ( id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, ip_address VARCHAR(45) NOT NULL, attempt_type VARCHAR(32) NOT NULL DEFAULT 'login', username_hash CHAR(64) DEFAULT NULL, user_agent VARCHAR(255) DEFAULT NULL, attempt_count INT UNSIGNED NOT NULL DEFAULT 1, window_start DATETIME NOT NULL, last_attempt DATETIME NOT NULL, PRIMARY KEY  (id), UNIQUE KEY uniq_ip_type_user (ip_address, attempt_type, username_hash), KEY idx_last_attempt (last_attempt) )",
			"CREATE TABLE {$prefix}reportedip_hive_blocked ( id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, ip_address VARCHAR(45) NOT NULL, reason VARCHAR(255) NOT NULL, block_type VARCHAR(20) NOT NULL DEFAULT 'automatic', blocked_until DATETIME DEFAULT NULL, failed_attempts INT UNSIGNED NOT NULL DEFAULT 0, is_active TINYINT(1) NOT NULL DEFAULT 1, created_at DATETIME NOT NULL, PRIMARY KEY  (id), UNIQUE KEY uniq_ip (ip_address), KEY idx_active (is_active, blocked_until) )",
			"CREATE TABLE {$prefix}reportedip_hive_api_queue ( id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, ip_address VARCHAR(45) NOT NULL, category_ids VARCHAR(64) NOT NULL, comment TEXT DEFAULT NULL, attempts INT UNSIGNED NOT NULL DEFAULT 0, max_attempts INT UNSIGNED NOT NULL DEFAULT 3, submitted_at DATETIME DEFAULT NULL, status VARCHAR(20) NOT NULL DEFAULT 'pending', error_message VARCHAR(255) DEFAULT NULL, created_at DATETIME NOT NULL, PRIMARY KEY  (id), KEY idx_status_created (status, created_at) )",
			"CREATE TABLE {$prefix}reportedip_hive_whitelist ( id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, ip_address VARCHAR(45) NOT NULL, reason VARCHAR(255) DEFAULT NULL, added_by BIGINT UNSIGNED DEFAULT NULL, expires_at DATETIME DEFAULT NULL, is_active TINYINT(1) NOT NULL DEFAULT 1, created_at DATETIME NOT NULL, PRIMARY KEY  (id), UNIQUE KEY uniq_ip (ip_address), KEY idx_active (is_active, expires_at) )",
		);
	}

	public static function wpSetUpBeforeClass( $factory ) {
		global $wpdb;
		if ( ! is_multisite() ) {
			return;
		}
		self::$site = (int) $factory->blog->create();
		$prefix     = $wpdb->get_blog_prefix( self::$site );
		foreach ( ReportedIP_Hive_Schema::LIGHT_SITE_SUFFIXES as $suffix ) {
			$wpdb->query( "DROP TABLE IF EXISTS {$prefix}{$suffix}" );
		}
		foreach ( self::light_schema( $prefix ) as $sql ) {
			$wpdb->query( $sql );
		}
	}

	public static function wpTearDownAfterClass() {
		global $wpdb;
		if ( ! self::$site ) {
			return;
		}
		$prefix = $wpdb->get_blog_prefix( self::$site );
		foreach ( ReportedIP_Hive_Schema::LIGHT_SITE_SUFFIXES as $suffix ) {
			$wpdb->query( "DROP TABLE IF EXISTS {$prefix}{$suffix}" );
		}
		remove_action( 'wp_delete_site', array( 'ReportedIP_Hive', 'on_site_deleted' ) );
		wp_delete_site( self::$site );
		add_action( 'wp_delete_site', array( 'ReportedIP_Hive', 'on_site_deleted' ), 10, 1 );
	}

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		global $wpdb;
		foreach ( ReportedIP_Hive_Schema::LIGHT_SITE_SUFFIXES as $suffix ) {
			$wpdb->query( 'DELETE FROM ' . ReportedIP_Hive_Schema::table( $suffix ) );
		}
		update_blog_option( self::$site, ReportedIP_Hive_Migration_Manager::VERSION_OPTION, '1.2.0' );
		delete_site_option( 'reportedip_hive_api_key' );
	}

	/**
	 * Invoke a private migration step.
	 *
	 * @param int $version Step number.
	 * @return void
	 */
	private function run_step( $version ) {
		$method = new ReflectionMethod( ReportedIP_Hive_Migration_Manager::class, 'migrate_to_v' . $version );
		$method->invoke( null );
	}

	/**
	 * Fully qualified per-site Light table.
	 *
	 * @param string $suffix Table suffix.
	 * @return string
	 */
	private function light( $suffix ) {
		global $wpdb;
		return $wpdb->get_blog_prefix( self::$site ) . $suffix;
	}

	/**
	 * Seed the sub-site's Light tables the way Light 1.3.9 wrote them, and
	 * the network tables with rows that collide with them.
	 *
	 * @return void
	 */
	private function seed() {
		global $wpdb;
		$soon  = gmdate( 'Y-m-d H:i:s', time() + HOUR_IN_SECONDS );
		$later = gmdate( 'Y-m-d H:i:s', time() + DAY_IN_SECONDS );
		$now   = gmdate( 'Y-m-d H:i:s' );

		foreach ( array(
			array( '203.0.113.7', '0000-00-00 00:00:00', 5 ),
			array( '10.20.0.0/16', '0000-00-00 00:00:00', null ),
			array( '2001:db8::1', $later, 5 ),
			array( '192.0.2.44', '0000-00-00 00:00:00', 5 ),
		) as $row ) {
			$wpdb->query( $wpdb->prepare( 'INSERT INTO ' . $this->light( 'reportedip_hive_whitelist' ) . ' (ip_address, reason, added_by, expires_at, is_active, created_at) VALUES (%s, %s, ' . ( null === $row[2] ? 'NULL' : (int) $row[2] ) . ', %s, 1, %s)', $row[0], 'light', $row[1], $now ) );
		}
		$wpdb->insert(
			ReportedIP_Hive_Schema::table( 'reportedip_hive_whitelist' ),
			array(
				'ip_address' => '192.0.2.44',
				'ip_type'    => 'ipv4',
				'reason'     => 'network',
				'added_by'   => 1,
				'expires_at' => $soon,
				'is_active'  => 1,
			)
		);

		foreach ( array(
			array( '198.51.100.1', $later, 1 ),
			array( '198.51.100.2', $soon, 1 ),
			array( '198.51.100.3', $later, 1 ),
			array( '198.51.100.4', null, 0 ),
		) as $row ) {
			$wpdb->insert(
				$this->light( 'reportedip_hive_blocked' ),
				array(
					'ip_address'      => $row[0],
					'reason'          => 'light',
					'block_type'      => 'automatic',
					'blocked_until'   => $row[1],
					'failed_attempts' => 3,
					'is_active'       => $row[2],
					'created_at'      => $now,
				)
			);
		}
		foreach ( array( array( '198.51.100.2', $later ), array( '198.51.100.3', $soon ), array( '198.51.100.4', $later ) ) as $row ) {
			$wpdb->insert(
				ReportedIP_Hive_Schema::table( 'reportedip_hive_blocked' ),
				array(
					'ip_address'    => $row[0],
					'reason'        => 'network',
					'block_type'    => 'manual',
					'blocked_until' => $row[1],
					'is_active'     => 1,
				)
			);
		}

		foreach ( array( array( 'alice', 2 ), array( 'bob', 3 ), array( null, 1 ) ) as $row ) {
			$wpdb->insert(
				$this->light( 'reportedip_hive_attempts' ),
				array(
					'ip_address'    => '203.0.113.99',
					'attempt_type'  => 'login',
					'username_hash' => null === $row[0] ? null : hash( 'sha256', $row[0] ),
					'attempt_count' => $row[1],
					'window_start'  => $now,
					'last_attempt'  => $now,
				)
			);
		}
		$wpdb->insert(
			ReportedIP_Hive_Schema::table( 'reportedip_hive_attempts' ),
			array(
				'ip_address'    => '203.0.113.99',
				'attempt_type'  => 'login',
				'attempt_count' => 4,
				'first_attempt' => $now,
				'last_attempt'  => $now,
			)
		);

		foreach ( array( 'pending', 'completed' ) as $status ) {
			$wpdb->insert(
				$this->light( 'reportedip_hive_api_queue' ),
				array(
					'ip_address'   => '203.0.113.50',
					'category_ids' => '18',
					'comment'      => 'light ' . $status,
					'status'       => $status,
					'created_at'   => $now,
				)
			);
		}
	}

	/**
	 * Network rows of a table keyed by IP.
	 *
	 * @param string $suffix Table suffix.
	 * @return array<string,object>
	 */
	private function network_rows( $suffix ) {
		global $wpdb;
		$out = array();
		foreach ( (array) $wpdb->get_results( 'SELECT * FROM ' . ReportedIP_Hive_Schema::table( $suffix ) . ' ORDER BY id' ) as $row ) {
			$out[ (string) $row->ip_address ] = $row;
		}
		return $out;
	}

	public function test_v25_copies_every_light_row_of_a_sub_site() {
		$this->seed();
		$this->run_step( 25 );

		$whitelist = $this->network_rows( 'reportedip_hive_whitelist' );
		$this->assertCount( 4, $whitelist );
		$this->assertNull( $whitelist['203.0.113.7']->expires_at, 'zero date becomes permanent' );
		$this->assertSame( 'ipv4', $whitelist['203.0.113.7']->ip_type );
		$this->assertSame( 'cidr', $whitelist['10.20.0.0/16']->ip_type );
		$this->assertSame( '0', (string) $whitelist['10.20.0.0/16']->added_by );
		$this->assertSame( 'ipv6', $whitelist['2001:db8::1']->ip_type );
		$this->assertNull( $whitelist['192.0.2.44']->expires_at, 'the permanent Light entry outlasts the network one' );
		$this->assertSame( 'network', $whitelist['192.0.2.44']->reason );
		$this->assertTrue( ReportedIP_Hive_IP_Manager::get_instance()->is_whitelisted( '10.20.3.4' ) );

		$blocked = $this->network_rows( 'reportedip_hive_blocked' );
		$this->assertCount( 4, $blocked );
		$this->assertSame( 'light', $blocked['198.51.100.1']->reason );
		$this->assertSame( 'manual', $blocked['198.51.100.2']->block_type, 'the longer network block stays' );
		$this->assertSame( 'light', $blocked['198.51.100.3']->reason, 'the longer Light block wins' );
		$this->assertSame( 'automatic', $blocked['198.51.100.3']->block_type );
		$this->assertSame( 'network', $blocked['198.51.100.4']->reason, 'an inactive Light row never replaces an active block' );
		$this->assertSame( '1', (string) $blocked['198.51.100.4']->is_active );

		$attempts = $this->network_rows( 'reportedip_hive_attempts' );
		$this->assertCount( 1, $attempts );
		$this->assertSame( 10, (int) $attempts['203.0.113.99']->attempt_count, '2 + 3 + 1 from Light, 4 from the network' );

		global $wpdb;
		$queue = (array) $wpdb->get_results( 'SELECT * FROM ' . ReportedIP_Hive_Schema::table( 'reportedip_hive_api_queue' ) . ' ORDER BY id' );
		$this->assertCount( 2, $queue );
		$this->assertSame( (string) self::$site, (string) $queue[0]->blog_id );
		$this->assertSame( 'pending', $queue[0]->status );
		$this->assertSame( 'negative', $queue[0]->report_type );
	}

	public function test_v25_rerun_copies_nothing_twice() {
		$this->seed();
		$this->run_step( 25 );
		$this->run_step( 25 );

		global $wpdb;
		$this->assertSame( 10, (int) $wpdb->get_var( 'SELECT attempt_count FROM ' . ReportedIP_Hive_Schema::table( 'reportedip_hive_attempts' ) . " WHERE ip_address = '203.0.113.99'" ) );
		$this->assertSame( 2, (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . ReportedIP_Hive_Schema::table( 'reportedip_hive_api_queue' ) ) );
		$cursor = get_blog_option( self::$site, ReportedIP_Hive_Migration_Manager::LIGHT_MERGE_OPTION );
		$this->assertSame( (int) $wpdb->get_var( 'SELECT MAX(id) FROM ' . $this->light( 'reportedip_hive_attempts' ) ), $cursor['reportedip_hive_attempts'] );
	}

	public function test_v25_resumes_after_the_stored_cursor() {
		$this->seed();
		global $wpdb;
		$first = (int) $wpdb->get_var( 'SELECT MIN(id) FROM ' . $this->light( 'reportedip_hive_api_queue' ) );
		update_blog_option( self::$site, ReportedIP_Hive_Migration_Manager::LIGHT_MERGE_OPTION, array( 'reportedip_hive_api_queue' => $first ) );
		$this->run_step( 25 );

		$this->assertSame( array( 'light completed' ), $wpdb->get_col( 'SELECT comment FROM ' . ReportedIP_Hive_Schema::table( 'reportedip_hive_api_queue' ) ) );
	}

	public function test_v25_leaves_the_light_tables_and_skips_a_site_that_never_ran_light() {
		$this->seed();
		update_blog_option( self::$site, ReportedIP_Hive_Migration_Manager::VERSION_OPTION, 25 );
		$this->run_step( 25 );
		$this->assertSame( 4, (int) $this->network_rows( 'reportedip_hive_attempts' )['203.0.113.99']->attempt_count, 'untouched without a Light version' );

		update_blog_option( self::$site, ReportedIP_Hive_Migration_Manager::VERSION_OPTION, '1.2.0' );
		$this->run_step( 25 );
		global $wpdb;
		$this->assertSame( 4, (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $this->light( 'reportedip_hive_whitelist' ) ), 'Light rows stay as a backup' );
	}

	public function test_v25_takes_the_light_key_only_while_the_network_has_none() {
		update_blog_option( self::$site, 'reportedip_hive_api_key', 'lightkey123' );
		update_site_option( 'reportedip_hive_api_key', '' );
		$this->run_step( 25 );
		$this->assertSame( 'lightkey123', get_site_option( 'reportedip_hive_api_key' ) );

		update_site_option( 'reportedip_hive_api_key', 'networkkey' );
		$this->run_step( 25 );
		$this->assertSame( 'networkkey', get_site_option( 'reportedip_hive_api_key' ) );
		delete_blog_option( self::$site, 'reportedip_hive_api_key' );
	}

	public function test_maybe_run_from_v24_reaches_v25_and_copies() {
		$this->seed();
		update_site_option( ReportedIP_Hive_Migration_Manager::VERSION_OPTION, 24 );
		ReportedIP_Hive_Migration_Manager::maybe_run();

		$this->assertSame( ReportedIP_Hive_Migration_Manager::CURRENT_VERSION, (int) get_site_option( ReportedIP_Hive_Migration_Manager::VERSION_OPTION ) );
		$this->assertCount( 4, $this->network_rows( 'reportedip_hive_whitelist' ) );
	}

	public function test_v24_and_the_attempt_merge_on_the_network_tables() {
		global $wpdb;
		$whitelist = ReportedIP_Hive_Schema::table( 'reportedip_hive_whitelist' );
		$attempts  = ReportedIP_Hive_Schema::table( 'reportedip_hive_attempts' );
		$now       = gmdate( 'Y-m-d H:i:s' );

		$wpdb->query( "ALTER TABLE $attempts DROP INDEX unique_ip_type" );
		$wpdb->query( "ALTER TABLE $attempts ADD COLUMN window_start datetime NOT NULL" );
		try {
			$wpdb->query( "INSERT INTO $whitelist (ip_address, ip_type, reason, added_by, expires_at, is_active) VALUES ('10.30.0.0/16', 'ipv4', 'light', 0, '0000-00-00 00:00:00', 1), ('2001:db8::9', 'ipv4', 'light', 0, '0000-00-00 00:00:00', 1)" );
			foreach ( array( 2, 3, 1 ) as $count ) {
				$wpdb->query( $wpdb->prepare( "INSERT INTO $attempts (ip_address, attempt_type, attempt_count, window_start, first_attempt, last_attempt) VALUES ('203.0.113.77', 'login', %d, %s, %s, %s)", $count, $now, $now, $now ) );
			}

			$this->run_step( 24 );
			ReportedIP_Hive_Schema::merge_duplicate_attempts();
			$this->run_step( 15 );

			$rows = $this->network_rows( 'reportedip_hive_whitelist' );
			$this->assertNull( $rows['10.30.0.0/16']->expires_at );
			$this->assertSame( 'cidr', $rows['10.30.0.0/16']->ip_type );
			$this->assertSame( 'ipv6', $rows['2001:db8::9']->ip_type );
			$this->assertSame( 'YES', $wpdb->get_var( $wpdb->prepare( 'SELECT IS_NULLABLE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s', $attempts, 'window_start' ) ) );
			$this->assertSame( array( '6' ), $wpdb->get_col( "SELECT attempt_count FROM $attempts WHERE ip_address = '203.0.113.77'" ) );
			$this->assertTrue( ReportedIP_Hive_Schema::index_exists( 'reportedip_hive_attempts', 'unique_ip_type' ) );
		} finally {
			$wpdb->query( "DELETE FROM $whitelist" );
			$wpdb->query( "DELETE FROM $attempts" );
			if ( ReportedIP_Hive_Schema::column_exists( 'reportedip_hive_attempts', 'window_start' ) ) {
				$wpdb->query( "ALTER TABLE $attempts DROP COLUMN window_start" );
			}
			if ( ! ReportedIP_Hive_Schema::index_exists( 'reportedip_hive_attempts', 'unique_ip_type' ) ) {
				$wpdb->query( "ALTER TABLE $attempts ADD UNIQUE KEY unique_ip_type (ip_address, attempt_type)" );
			}
		}
	}

	public function test_uninstall_drop_removes_the_per_site_light_tables() {
		global $wpdb;
		$probe = $this->light( 'reportedip_hive_attempts' );
		remove_filter( 'query', array( $this, '_drop_temporary_tables' ) );
		remove_filter( 'query', array( $this, '_create_temporary_tables' ) );
		ReportedIP_Hive_Schema::drop_all_tables();
		$gone = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $probe ) ) );

		ReportedIP_Hive_Schema::ensure_tables();
		foreach ( self::light_schema( $wpdb->get_blog_prefix( self::$site ) ) as $sql ) {
			$wpdb->query( $sql );
		}
		add_filter( 'query', array( $this, '_create_temporary_tables' ) );
		add_filter( 'query', array( $this, '_drop_temporary_tables' ) );
		$this->assertNull( $gone );
		$this->assertSame( $probe, $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $probe ) ) ) );
	}
}
