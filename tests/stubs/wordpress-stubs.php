<?php
/**
 * WordPress Function Stubs for Unit Testing
 *
 * These stubs allow unit tests to run without loading WordPress.
 * They provide minimal implementations of common WordPress functions.
 *
 * @package ReportedIP_Hive
 * @subpackage Tests\Stubs
 */

// Prevent direct execution
if ( ! defined( 'REPORTEDIP_HIVE_TESTING' ) ) {
	exit;
}

// Storage arrays for mocked data
global $wp_options, $wp_transients, $wp_actions, $wp_filters, $wp_current_user_id;
$wp_options         = array();
$wp_transients      = array();
$wp_actions         = array();
$wp_filters         = array();
$wp_current_user_id = 1;

// =============================================================================
// Option Functions
// =============================================================================

if ( ! function_exists( 'get_option' ) ) {
	/**
	 * Retrieves an option value based on an option name.
	 *
	 * @param string $option  Name of the option to retrieve.
	 * @param mixed  $default Default value to return if the option does not exist.
	 * @return mixed
	 */
	function get_option( $option, $default = false ) {
		global $wp_options;
		return isset( $wp_options[ $option ] ) ? $wp_options[ $option ] : $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	/**
	 * Updates the value of an option.
	 *
	 * @param string $option   Name of the option to update.
	 * @param mixed  $value    Option value.
	 * @param bool   $autoload Whether to load the option when WordPress starts up.
	 * @return bool
	 */
	function update_option( $option, $value, $autoload = null ) {
		global $wp_options;
		$wp_options[ $option ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_option' ) ) {
	/**
	 * Removes an option by name.
	 *
	 * @param string $option Name of the option to delete.
	 * @return bool
	 */
	function delete_option( $option ) {
		global $wp_options;
		if ( isset( $wp_options[ $option ] ) ) {
			unset( $wp_options[ $option ] );
			return true;
		}
		return false;
	}
}

// =============================================================================
// Transient Functions
// =============================================================================

if ( ! function_exists( 'get_transient' ) ) {
	/**
	 * Retrieves the value of a transient.
	 *
	 * @param string $transient Transient name.
	 * @return mixed
	 */
	function get_transient( $transient ) {
		global $wp_transients;
		if ( ! isset( $wp_transients[ $transient ] ) ) {
			return false;
		}
		$data = $wp_transients[ $transient ];
		if ( $data['expires'] > 0 && $data['expires'] < time() ) {
			unset( $wp_transients[ $transient ] );
			return false;
		}
		return $data['value'];
	}
}

if ( ! function_exists( 'set_transient' ) ) {
	/**
	 * Sets/updates the value of a transient.
	 *
	 * @param string $transient  Transient name.
	 * @param mixed  $value      Transient value.
	 * @param int    $expiration Time until expiration in seconds.
	 * @return bool
	 */
	function set_transient( $transient, $value, $expiration = 0 ) {
		global $wp_transients;
		$wp_transients[ $transient ] = array(
			'value'   => $value,
			'expires' => $expiration > 0 ? time() + $expiration : 0,
		);
		return true;
	}
}

if ( ! function_exists( 'delete_transient' ) ) {
	/**
	 * Deletes a transient.
	 *
	 * @param string $transient Transient name.
	 * @return bool
	 */
	function delete_transient( $transient ) {
		global $wp_transients;
		if ( isset( $wp_transients[ $transient ] ) ) {
			unset( $wp_transients[ $transient ] );
			return true;
		}
		return false;
	}
}

// =============================================================================
// Hook Functions
// =============================================================================

if ( ! function_exists( 'add_action' ) ) {
	/**
	 * Adds a callback function to an action hook.
	 *
	 * @param string   $hook_name     The name of the action to add the callback to.
	 * @param callable $callback      The callback to be run when the action is called.
	 * @param int      $priority      The priority of the callback.
	 * @param int      $accepted_args The number of arguments the callback accepts.
	 * @return true
	 */
	function add_action( $hook_name, $callback, $priority = 10, $accepted_args = 1 ) {
		global $wp_actions;
		if ( ! isset( $wp_actions[ $hook_name ] ) ) {
			$wp_actions[ $hook_name ] = array();
		}
		$wp_actions[ $hook_name ][] = array(
			'callback'      => $callback,
			'priority'      => $priority,
			'accepted_args' => $accepted_args,
		);
		return true;
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	/**
	 * Adds a callback function to a filter hook.
	 *
	 * @param string   $hook_name     The name of the filter to add the callback to.
	 * @param callable $callback      The callback to be run when the filter is applied.
	 * @param int      $priority      The priority of the callback.
	 * @param int      $accepted_args The number of arguments the callback accepts.
	 * @return true
	 */
	function add_filter( $hook_name, $callback, $priority = 10, $accepted_args = 1 ) {
		global $wp_filters;
		if ( ! isset( $wp_filters[ $hook_name ] ) ) {
			$wp_filters[ $hook_name ] = array();
		}
		$wp_filters[ $hook_name ][] = array(
			'callback'      => $callback,
			'priority'      => $priority,
			'accepted_args' => $accepted_args,
		);
		return true;
	}
}

if ( ! function_exists( 'do_action' ) ) {
	/**
	 * Calls the callback functions that have been added to an action hook.
	 *
	 * @param string $hook_name The name of the action to be executed.
	 * @param mixed  ...$args   Additional arguments which are passed to the functions hooked to the action.
	 */
	function do_action( $hook_name, ...$args ) {
		global $wp_actions;
		if ( ! isset( $wp_actions[ $hook_name ] ) ) {
			return;
		}
		foreach ( $wp_actions[ $hook_name ] as $action ) {
			call_user_func_array( $action['callback'], array_slice( $args, 0, $action['accepted_args'] ) );
		}
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	/**
	 * Calls the callback functions that have been added to a filter hook.
	 *
	 * @param string $hook_name The name of the filter hook.
	 * @param mixed  $value     The value to filter.
	 * @param mixed  ...$args   Additional arguments passed to the filter functions.
	 * @return mixed
	 */
	function apply_filters( $hook_name, $value, ...$args ) {
		global $wp_filters;
		if ( ! isset( $wp_filters[ $hook_name ] ) ) {
			return $value;
		}
		foreach ( $wp_filters[ $hook_name ] as $filter ) {
			$filter_args   = array_merge( array( $value ), $args );
			$value         = call_user_func_array( $filter['callback'], array_slice( $filter_args, 0, $filter['accepted_args'] ) );
		}
		return $value;
	}
}

if ( ! function_exists( 'register_shutdown_function' ) ) {
	// This is a PHP function, but we stub it to prevent issues in tests
}

// =============================================================================
// User Functions
// =============================================================================

if ( ! function_exists( 'get_current_user_id' ) ) {
	/**
	 * Gets the current user's ID.
	 *
	 * @return int
	 */
	function get_current_user_id() {
		global $wp_current_user_id;
		return $wp_current_user_id;
	}
}

if ( ! function_exists( 'get_user_by' ) ) {
	/**
	 * Retrieves user info by a given field.
	 *
	 * @param string     $field The field to retrieve the user with.
	 * @param int|string $value A value for $field.
	 * @return object|false
	 */
	function get_user_by( $field, $value ) {
		// Return a basic mock user object
		return (object) array(
			'ID'         => 1,
			'user_login' => 'admin',
			'user_email' => 'admin@example.org',
		);
	}
}

// =============================================================================
// Date/Time Functions
// =============================================================================

if ( ! function_exists( 'current_time' ) ) {
	/**
	 * Retrieves the current time based on specified type.
	 *
	 * @param string $type   Type of time to retrieve.
	 * @param bool   $gmt    Whether to use GMT timezone.
	 * @return int|string
	 */
	function current_time( $type, $gmt = false ) {
		$timezone = $gmt ? new DateTimeZone( 'UTC' ) : new DateTimeZone( date_default_timezone_get() );
		$datetime = new DateTime( 'now', $timezone );

		switch ( $type ) {
			case 'mysql':
				return $datetime->format( 'Y-m-d H:i:s' );
			case 'timestamp':
			case 'U':
				return $datetime->getTimestamp();
			default:
				return $datetime->format( $type );
		}
	}
}

// =============================================================================
// Sanitization Functions
// =============================================================================

if ( ! function_exists( 'sanitize_text_field' ) ) {
	/**
	 * Sanitizes a string from user input or from the database.
	 *
	 * @param string $str String to sanitize.
	 * @return string
	 */
	function sanitize_text_field( $str ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.strip_tags_strip_tags -- Stub mirrors WordPress core sanitize_text_field() in unit-test runs without WP loaded.
		return htmlspecialchars( strip_tags( trim( $str ) ), ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'wp_kses_post' ) ) {
	/**
	 * Sanitizes content for allowed HTML tags for post content.
	 *
	 * @param string $data Post content to filter.
	 * @return string
	 */
	function wp_kses_post( $data ) {
		return strip_tags( $data, '<a><b><strong><i><em><ul><ol><li><p><br><span><div>' );
	}
}

if ( ! function_exists( 'sanitize_email' ) ) {
	/**
	 * Stub: trim + filter against a permissive email pattern.
	 *
	 * @param string $email Address.
	 * @return string Empty when invalid, sanitized otherwise.
	 */
	function sanitize_email( $email ) {
		$email = trim( (string) $email );
		return preg_match( '/^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/', $email ) ? $email : '';
	}
}

if ( ! function_exists( 'is_email' ) ) {
	/**
	 * Stub: same permissive check as sanitize_email().
	 *
	 * @param string $email Candidate.
	 * @return bool
	 */
	function is_email( $email ) {
		return (bool) preg_match( '/^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/', (string) $email );
	}
}

if ( ! function_exists( 'absint' ) ) {
	/**
	 * Converts a value to non-negative integer.
	 *
	 * @param mixed $maybeint Data you wish to have converted to a non-negative integer.
	 * @return int
	 */
	function absint( $maybeint ) {
		return abs( (int) $maybeint );
	}
}

// =============================================================================
// Escaping Functions
// =============================================================================

if ( ! function_exists( 'esc_html' ) ) {
	/**
	 * Escaping for HTML blocks.
	 *
	 * @param string $text Text to escape.
	 * @return string
	 */
	function esc_html( $text ) {
		return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_attr' ) ) {
	/**
	 * Escaping for HTML attributes.
	 *
	 * @param string $text Text to escape.
	 * @return string
	 */
	function esc_attr( $text ) {
		return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_url' ) ) {
	/**
	 * Checks and cleans a URL.
	 *
	 * @param string $url The URL to be cleaned.
	 * @return string
	 */
	function esc_url( $url ) {
		return filter_var( $url, FILTER_SANITIZE_URL );
	}
}

if ( ! function_exists( 'esc_sql' ) ) {
	/**
	 * Escapes data for use in a MySQL query.
	 *
	 * @param string|array $data Unescaped data.
	 * @return string|array
	 */
	function esc_sql( $data ) {
		if ( is_array( $data ) ) {
			return array_map( 'esc_sql', $data );
		}
		return addslashes( $data );
	}
}

// =============================================================================
// i18n Functions
// =============================================================================

if ( ! function_exists( '__' ) ) {
	/**
	 * Retrieves the translation of $text.
	 *
	 * @param string $text   Text to translate.
	 * @param string $domain Optional. Text domain.
	 * @return string
	 */
	function __( $text, $domain = 'default' ) {
		return $text;
	}
}

if ( ! function_exists( '_e' ) ) {
	/**
	 * Displays the translation of $text.
	 *
	 * @param string $text   Text to translate.
	 * @param string $domain Optional. Text domain.
	 */
	function _e( $text, $domain = 'default' ) {
		echo $text; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Stub mirrors WordPress core _e(); escaping is the caller's responsibility.
	}
}

if ( ! function_exists( 'esc_html__' ) ) {
	/**
	 * Retrieves the translation of $text and escapes it for safe use in HTML output.
	 *
	 * @param string $text   Text to translate.
	 * @param string $domain Optional. Text domain.
	 * @return string
	 */
	function esc_html__( $text, $domain = 'default' ) {
		return esc_html( $text );
	}
}

if ( ! function_exists( 'esc_attr__' ) ) {
	/**
	 * Retrieves the translation of $text and escapes it for safe use in an attribute.
	 *
	 * @param string $text   Text to translate.
	 * @param string $domain Optional. Text domain.
	 * @return string
	 */
	function esc_attr__( $text, $domain = 'default' ) {
		return esc_attr( $text );
	}
}

// =============================================================================
// Path/URL Functions
// =============================================================================

if ( ! function_exists( 'plugin_dir_path' ) ) {
	/**
	 * Get the filesystem directory path for a plugin.
	 *
	 * @param string $file A path within a plugin.
	 * @return string
	 */
	function plugin_dir_path( $file ) {
		return trailingslashit( dirname( $file ) );
	}
}

if ( ! function_exists( 'plugin_dir_url' ) ) {
	/**
	 * Get the URL directory path for a plugin.
	 *
	 * @param string $file A path within a plugin.
	 * @return string
	 */
	function plugin_dir_url( $file ) {
		return 'http://example.org/wp-content/plugins/' . basename( dirname( $file ) ) . '/';
	}
}

if ( ! function_exists( 'plugin_basename' ) ) {
	/**
	 * Gets the basename of a plugin.
	 *
	 * @param string $file The filename of the plugin.
	 * @return string
	 */
	function plugin_basename( $file ) {
		return basename( dirname( $file ) ) . '/' . basename( $file );
	}
}

if ( ! function_exists( 'trailingslashit' ) ) {
	/**
	 * Appends a trailing slash.
	 *
	 * @param string $string What to add the trailing slash to.
	 * @return string
	 */
	function trailingslashit( $string ) {
		return rtrim( $string, '/\\' ) . '/';
	}
}

// =============================================================================
// Misc Functions
// =============================================================================

if ( ! function_exists( 'wp_json_encode' ) ) {
	/**
	 * Encodes a variable into JSON.
	 *
	 * @param mixed $data    Variable to encode as JSON.
	 * @param int   $options Optional. Options to be passed to json_encode().
	 * @param int   $depth   Optional. Maximum depth to walk through $data.
	 * @return string|false
	 */
	function wp_json_encode( $data, $options = 0, $depth = 512 ) {
		return json_encode( $data, $options, $depth );
	}
}

if ( ! function_exists( 'wp_parse_args' ) ) {
	/**
	 * Merges user defined arguments into defaults array.
	 *
	 * @param string|array|object $args     Value to merge with $defaults.
	 * @param array               $defaults Optional. Array that serves as the defaults.
	 * @return array
	 */
	function wp_parse_args( $args, $defaults = array() ) {
		if ( is_object( $args ) ) {
			$parsed_args = get_object_vars( $args );
		} elseif ( is_array( $args ) ) {
			$parsed_args = $args;
		} else {
			parse_str( $args, $parsed_args );
		}
		return array_merge( $defaults, $parsed_args );
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	/**
	 * Checks whether the given variable is a WordPress Error.
	 *
	 * @param mixed $thing Variable to check.
	 * @return bool
	 */
	function is_wp_error( $thing ) {
		return $thing instanceof WP_Error;
	}
}

// =============================================================================
// Mailer-related stubs (used by MailerTemplateTest)
// =============================================================================

if ( ! function_exists( 'esc_html_e' ) ) {
	function esc_html_e( $text, $domain = 'default' ) { // phpcs:ignore
		echo esc_html( $text );
	}
}

if ( ! function_exists( 'wp_strip_all_tags' ) ) {
	function wp_strip_all_tags( $string, $remove_breaks = false ) { // phpcs:ignore
		$string = preg_replace( '/<script[^>]*?>.*?<\/script>/si', '', (string) $string );
		$string = preg_replace( '/<style[^>]*?>.*?<\/style>/si', '', (string) $string );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.strip_tags_strip_tags -- This stub IS wp_strip_all_tags() for unit-test runs; it has to call PHP's strip_tags().
		$string = strip_tags( (string) $string );
		return $remove_breaks ? preg_replace( '/[\r\n\t ]+/', ' ', $string ) : trim( $string );
	}
}

if ( ! function_exists( 'get_bloginfo' ) ) {
	function get_bloginfo( $show = '' ) { // phpcs:ignore
		return 'Example Site';
	}
}

if ( ! function_exists( 'home_url' ) ) {
	function home_url( $path = '' ) { // phpcs:ignore
		return 'https://example.org' . $path;
	}
}

if ( ! function_exists( 'wp_specialchars_decode' ) ) {
	function wp_specialchars_decode( $string, $quote_style = ENT_NOQUOTES ) { // phpcs:ignore
		return htmlspecialchars_decode( (string) $string, (int) $quote_style );
	}
}

if ( ! function_exists( 'wp_mail' ) ) {
	function wp_mail( $to, $subject, $message, $headers = array(), $attachments = array() ) { // phpcs:ignore
		$GLOBALS['rip_test_wp_mail_calls'][] = compact( 'to', 'subject', 'message', 'headers', 'attachments' );
		return true;
	}
}

if ( ! function_exists( 'remove_action' ) ) {
	function remove_action( $hook_name, $callback, $priority = 10 ) { // phpcs:ignore
		global $wp_actions;
		if ( ! isset( $wp_actions[ $hook_name ] ) ) {
			return false;
		}
		foreach ( $wp_actions[ $hook_name ] as $i => $action ) {
			if ( $action['callback'] === $callback && (int) $action['priority'] === (int) $priority ) {
				unset( $wp_actions[ $hook_name ][ $i ] );
			}
		}
		return true;
	}
}

// =============================================================================
// WP_Error Class
// =============================================================================

if ( ! class_exists( 'WP_Error' ) ) {
	/**
	 * WordPress Error class.
	 */
	class WP_Error {
		/**
		 * Stores the list of errors.
		 *
		 * @var array
		 */
		public $errors = array();

		/**
		 * Stores the most recently added data for each error code.
		 *
		 * @var array
		 */
		public $error_data = array();

		/**
		 * Initializes the error.
		 *
		 * @param string|int $code    Error code.
		 * @param string     $message Error message.
		 * @param mixed      $data    Optional. Error data.
		 */
		public function __construct( $code = '', $message = '', $data = '' ) {
			if ( empty( $code ) ) {
				return;
			}

			$this->add( $code, $message, $data );
		}

		/**
		 * Adds an error or appends an additional message to an existing error.
		 *
		 * @param string|int $code    Error code.
		 * @param string     $message Error message.
		 * @param mixed      $data    Optional. Error data.
		 */
		public function add( $code, $message, $data = '' ) {
			$this->errors[ $code ][] = $message;
			if ( ! empty( $data ) ) {
				$this->error_data[ $code ] = $data;
			}
		}

		/**
		 * Retrieves all error codes.
		 *
		 * @return array
		 */
		public function get_error_codes() {
			if ( empty( $this->errors ) ) {
				return array();
			}
			return array_keys( $this->errors );
		}

		/**
		 * Retrieves the first error code available.
		 *
		 * @return string|int
		 */
		public function get_error_code() {
			$codes = $this->get_error_codes();
			if ( empty( $codes ) ) {
				return '';
			}
			return $codes[0];
		}

		/**
		 * Retrieves all error messages.
		 *
		 * @param string|int $code Error code.
		 * @return array
		 */
		public function get_error_messages( $code = '' ) {
			if ( empty( $code ) ) {
				$all_messages = array();
				foreach ( (array) $this->errors as $code => $messages ) {
					$all_messages = array_merge( $all_messages, $messages );
				}
				return $all_messages;
			}

			if ( isset( $this->errors[ $code ] ) ) {
				return $this->errors[ $code ];
			}
			return array();
		}

		/**
		 * Gets a single error message.
		 *
		 * @param string|int $code Error code.
		 * @return string
		 */
		public function get_error_message( $code = '' ) {
			if ( empty( $code ) ) {
				$code = $this->get_error_code();
			}
			$messages = $this->get_error_messages( $code );
			if ( empty( $messages ) ) {
				return '';
			}
			return $messages[0];
		}

		/**
		 * Retrieves the error data.
		 *
		 * @param string|int $code Error code.
		 * @return mixed
		 */
		public function get_error_data( $code = '' ) {
			if ( empty( $code ) ) {
				$code = $this->get_error_code();
			}

			if ( isset( $this->error_data[ $code ] ) ) {
				return $this->error_data[ $code ];
			}
			return null;
		}

		/**
		 * Verifies if the instance contains errors.
		 *
		 * @return bool
		 */
		public function has_errors() {
			return ! empty( $this->errors );
		}
	}
}
