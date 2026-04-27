#!/usr/bin/env bash
#
# WordPress Test Suite Installation Script
#/new
# This script installs the WordPress test suite for running integration tests.
# It downloads WordPress core and the test library, then configures the test database.
#
# Usage: bash bin/install-wp-tests.sh <db-name> <db-user> <db-pass> [db-host] [wp-version] [skip-database-creation]
#
# Example:
#   bash bin/install-wp-tests.sh wordpress_test root '' localhost latest false
#
# For local development with MySQL:
#   bash bin/install-wp-tests.sh wordpress_test root password
#
# For CI/CD environments:
#   bash bin/install-wp-tests.sh wordpress_test root root 127.0.0.1 latest true
#

set -e

if [ $# -lt 3 ]; then
	echo "Usage: $0 <db-name> <db-user> <db-pass> [db-host] [wp-version] [skip-database-creation]"
	echo ""
	echo "Arguments:"
	echo "  db-name     - Name of the test database (will be created if it doesn't exist)"
	echo "  db-user     - MySQL username"
	echo "  db-pass     - MySQL password (use '' for no password)"
	echo "  db-host     - MySQL host (default: localhost)"
	echo "  wp-version  - WordPress version to test against (default: latest)"
	echo "  skip-db     - Set to 'true' to skip database creation (default: false)"
	echo ""
	echo "Example:"
	echo "  $0 wordpress_test root mypassword localhost latest false"
	exit 1
fi

DB_NAME=$1
DB_USER=$2
DB_PASS=$3
DB_HOST=${4-localhost}
WP_VERSION=${5-latest}
SKIP_DB_CREATE=${6-false}

# Determine the temp directory
TMPDIR=${TMPDIR-/tmp}
TMPDIR=$(echo $TMPDIR | sed -e "s/\/$//")

# WordPress and test suite directories
WP_TESTS_DIR=${WP_TESTS_DIR-$TMPDIR/wordpress-tests-lib}
WP_CORE_DIR=${WP_CORE_DIR-$TMPDIR/wordpress/}

echo "============================================"
echo "WordPress Test Suite Installation"
echo "============================================"
echo "Database: $DB_NAME"
echo "User: $DB_USER"
echo "Host: $DB_HOST"
echo "WP Version: $WP_VERSION"
echo "Tests Dir: $WP_TESTS_DIR"
echo "Core Dir: $WP_CORE_DIR"
echo "============================================"

# Download helper function
download() {
	if [ `which curl` ]; then
		curl -s "$1" > "$2";
	elif [ `which wget` ]; then
		wget -nv -O "$2" "$1"
	fi
}

# Get the WordPress version to download
if [[ $WP_VERSION =~ ^[0-9]+\.[0-9]+\-(beta|RC)[0-9]+$ ]]; then
	WP_BRANCH=${WP_VERSION%\-*}
	WP_TESTS_TAG="branches/$WP_BRANCH"
elif [[ $WP_VERSION =~ ^[0-9]+\.[0-9]+$ ]]; then
	WP_TESTS_TAG="branches/$WP_VERSION"
elif [[ $WP_VERSION =~ [0-9]+\.[0-9]+\.[0-9]+ ]]; then
	if [[ $WP_VERSION =~ [0-9]+\.[0-9]+\.[0] ]]; then
		# Version x.x.0 maps to branch x.x
		WP_BRANCH=${WP_VERSION%\.0}
		WP_TESTS_TAG="branches/$WP_BRANCH"
	else
		WP_TESTS_TAG="tags/$WP_VERSION"
	fi
elif [[ $WP_VERSION == 'trunk' ]]; then
	WP_TESTS_TAG="trunk"
else
	# Assume latest if not specified
	download http://api.wordpress.org/core/version-check/1.7/ /tmp/wp-latest.json
	grep '[0-9]+\.[0-9]+(\.[0-9]+)?' /tmp/wp-latest.json
	LATEST_VERSION=$(grep -o '"version":"[^"]*' /tmp/wp-latest.json | sed 's/"version":"//' | head -1)

	if [[ -z "$LATEST_VERSION" ]]; then
		echo "Error: Could not determine latest WordPress version."
		exit 1
	fi

	WP_TESTS_TAG="tags/$LATEST_VERSION"
fi

echo "Using WordPress tests tag: $WP_TESTS_TAG"

# Set up WordPress test directory
set_up_wp_tests_dir() {
	# Clean up any existing installation
	if [ -d $WP_TESTS_DIR ]; then
		echo "Removing existing test directory..."
		rm -rf $WP_TESTS_DIR
	fi

	mkdir -p $WP_TESTS_DIR

	# Check out the test suite via svn
	echo "Downloading WordPress test suite..."
	svn co --quiet https://develop.svn.wordpress.org/${WP_TESTS_TAG}/tests/phpunit/includes/ $WP_TESTS_DIR/includes
	svn co --quiet https://develop.svn.wordpress.org/${WP_TESTS_TAG}/tests/phpunit/data/ $WP_TESTS_DIR/data
}

# Install WordPress core
install_wp() {
	if [ -d $WP_CORE_DIR ]; then
		echo "Removing existing WordPress installation..."
		rm -rf $WP_CORE_DIR
	fi

	mkdir -p $WP_CORE_DIR

	echo "Downloading WordPress..."

	if [[ $WP_VERSION == 'trunk' ]]; then
		# Download trunk
		svn co --quiet https://develop.svn.wordpress.org/trunk/src/ $WP_CORE_DIR
	else
		# Download specific version
		if [ $WP_VERSION == 'latest' ]; then
			local ARCHIVE_URL='https://wordpress.org/latest.tar.gz'
		else
			local ARCHIVE_URL="https://wordpress.org/wordpress-$WP_VERSION.tar.gz"
		fi

		download $ARCHIVE_URL $TMPDIR/wordpress.tar.gz
		tar --strip-components=1 -zxmf $TMPDIR/wordpress.tar.gz -C $WP_CORE_DIR
	fi

	# Download wp-content directory for tests
	download https://raw.github.com/markoheijnen/wp-mysqli/master/db.php $WP_CORE_DIR/wp-content/db.php
}

# Install the test config file
install_test_suite() {
	echo "Creating wp-tests-config.php..."

	# Portable sed command
	if [ $(uname -s) == 'Darwin' ]; then
		local ioption='-i.bak'
	else
		local ioption='-i'
	fi

	# Download config template
	download https://develop.svn.wordpress.org/${WP_TESTS_TAG}/wp-tests-config-sample.php $WP_TESTS_DIR/wp-tests-config.php

	# Fill in the config values
	sed $ioption "s:dirname( __FILE__ ) . '/src/':'$WP_CORE_DIR':" $WP_TESTS_DIR/wp-tests-config.php
	sed $ioption "s/youremptytestdbnamehere/$DB_NAME/" $WP_TESTS_DIR/wp-tests-config.php
	sed $ioption "s/yourusernamehere/$DB_USER/" $WP_TESTS_DIR/wp-tests-config.php
	sed $ioption "s/yourpasswordhere/$DB_PASS/" $WP_TESTS_DIR/wp-tests-config.php
	sed $ioption "s|localhost|${DB_HOST}|" $WP_TESTS_DIR/wp-tests-config.php

	# Clean up backup files if on macOS
	if [ -f $WP_TESTS_DIR/wp-tests-config.php.bak ]; then
		rm $WP_TESTS_DIR/wp-tests-config.php.bak
	fi
}

# Create the test database
create_db() {
	if [ $SKIP_DB_CREATE = 'true' ]; then
		echo "Skipping database creation (SKIP_DB_CREATE=true)"
		return 0
	fi

	echo "Creating test database '$DB_NAME'..."

	# Prepare password argument
	local EXTRA=""
	if [ -n "$DB_PASS" ]; then
		EXTRA=" -p$DB_PASS"
	fi

	# Try to drop existing database
	mysqladmin drop $DB_NAME --force --silent --user="$DB_USER"$EXTRA --host="$DB_HOST" 2>/dev/null || true

	# Create new database
	mysqladmin create $DB_NAME --user="$DB_USER"$EXTRA --host="$DB_HOST" || {
		echo ""
		echo "Error: Could not create database '$DB_NAME'."
		echo ""
		echo "Make sure:"
		echo "  1. MySQL is running"
		echo "  2. User '$DB_USER' has CREATE DATABASE privileges"
		echo "  3. The credentials are correct"
		echo ""
		echo "For local development, you can also create the database manually:"
		echo "  mysql -u root -p -e 'CREATE DATABASE IF NOT EXISTS $DB_NAME;'"
		echo ""
		exit 1
	}
}

# Main installation sequence
echo ""
echo "Step 1/4: Setting up WordPress test directory..."
set_up_wp_tests_dir

echo ""
echo "Step 2/4: Installing WordPress core..."
install_wp

echo ""
echo "Step 3/4: Creating database..."
create_db

echo ""
echo "Step 4/4: Installing test suite configuration..."
install_test_suite

echo ""
echo "============================================"
echo "WordPress Test Suite Installation Complete!"
echo "============================================"
echo ""
echo "Test suite location: $WP_TESTS_DIR"
echo "WordPress core location: $WP_CORE_DIR"
echo "Database: $DB_NAME"
echo ""
echo "To run integration tests:"
echo "  export WP_TESTS_DIR=$WP_TESTS_DIR"
echo "  export WP_TESTS_SUITE=integration"
echo "  vendor/bin/phpunit --testsuite integration"
echo ""
echo "Or run unit tests (no WordPress needed):"
echo "  vendor/bin/phpunit --testsuite unit"
echo ""
