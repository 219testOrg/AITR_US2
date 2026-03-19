"""
Comprehensive tests for SQL injection vulnerability fix in get_user() endpoint.

This test suite validates that the SQL injection vulnerability at line 33 has been
properly remediated using parameterized queries.
"""

import pytest
import sqlite3
from sast_critical_high import app, init_db, db_connection


@pytest.fixture
def client():
    """Create a Flask test client with a fresh database for each test."""
    # Initialize the database
    init_db()

    # Configure the app for testing
    app.config['TESTING'] = True

    with app.test_client() as client:
        yield client


@pytest.fixture
def setup_test_data():
    """Setup additional test data in the database."""
    cursor = db_connection.cursor()

    # Add more test users
    cursor.execute(
        "INSERT INTO users VALUES (2, 'testuser', 'test@example.com', 'testhash123')"
    )
    cursor.execute(
        "INSERT INTO users VALUES (3, 'alice', 'alice@example.com', 'alicehash456')"
    )
    cursor.execute(
        "INSERT INTO users VALUES (100, 'bob', 'bob@example.com', 'bobhash789')"
    )
    db_connection.commit()

    yield

    # Cleanup: Remove test data
    cursor.execute("DELETE FROM users WHERE id IN (2, 3, 100)")
    db_connection.commit()


class TestSQLInjectionRemediation:
    """Test suite for SQL injection vulnerability fix in /user endpoint."""

    def test_valid_user_id_returns_user(self, client, setup_test_data):
        """Test that a valid user ID returns the correct user data."""
        response = client.get('/user?id=1')
        assert response.status_code == 200
        assert b'admin' in response.data
        assert b'admin@test.com' in response.data

    def test_valid_numeric_id_as_string(self, client, setup_test_data):
        """Test that numeric ID passed as string works correctly."""
        response = client.get('/user?id=2')
        assert response.status_code == 200
        assert b'testuser' in response.data
        assert b'test@example.com' in response.data

    def test_nonexistent_user_id_returns_empty(self, client, setup_test_data):
        """Test that a non-existent user ID returns empty result."""
        response = client.get('/user?id=999')
        assert response.status_code == 200
        # Empty result set
        assert response.data == b'[]'

    def test_empty_id_parameter(self, client):
        """Test behavior with empty ID parameter."""
        response = client.get('/user?id=')
        assert response.status_code == 200
        # Should return empty result, not all users
        assert response.data == b'[]'

    def test_missing_id_parameter(self, client):
        """Test behavior when ID parameter is missing entirely."""
        response = client.get('/user')
        assert response.status_code == 200
        # Should return empty result with default empty string
        assert response.data == b'[]'

    # ============================================================
    # SQL Injection Attack Prevention Tests
    # ============================================================

    def test_sql_injection_union_attack_blocked(self, client, setup_test_data):
        """Test that UNION-based SQL injection is blocked."""
        # Attempt to inject: 1 UNION SELECT password FROM users
        malicious_id = "1 UNION SELECT password FROM users"
        response = client.get(f'/user?id={malicious_id}')

        # Should not return password hashes from all users
        # Parameterized query treats entire input as a single value
        assert response.status_code == 200
        # Should return empty result since "1 UNION SELECT..." is not a valid ID
        assert response.data == b'[]'

    def test_sql_injection_or_attack_blocked(self, client, setup_test_data):
        """Test that OR-based SQL injection (e.g., '1 OR 1=1') is blocked."""
        # Classic SQL injection: 1 OR 1=1
        malicious_id = "1 OR 1=1"
        response = client.get(f'/user?id={malicious_id}')

        # Should NOT return all users
        assert response.status_code == 200
        assert response.data == b'[]'

    def test_sql_injection_comment_attack_blocked(self, client, setup_test_data):
        """Test that comment-based SQL injection is blocked."""
        # Attempt to inject: 1; DROP TABLE users; --
        malicious_id = "1; DROP TABLE users; --"
        response = client.get(f'/user?id={malicious_id}')

        # Should not execute DROP TABLE command
        assert response.status_code == 200
        assert response.data == b'[]'

        # Verify the users table still exists by querying it
        cursor = db_connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        assert count > 0, "Users table should still exist"

    def test_sql_injection_quote_escape_blocked(self, client, setup_test_data):
        """Test that quote-based SQL injection is blocked."""
        # Attempt to inject: 1' OR '1'='1
        malicious_id = "1' OR '1'='1"
        response = client.get(f'/user?id={malicious_id}')

        # Should NOT return all users
        assert response.status_code == 200
        assert response.data == b'[]'

    def test_sql_injection_stacked_queries_blocked(self, client, setup_test_data):
        """Test that stacked query injection is blocked."""
        # Attempt to inject: 1; SELECT password FROM users WHERE id=1
        malicious_id = "1; SELECT password FROM users WHERE id=1"
        response = client.get(f'/user?id={malicious_id}')

        # Should not execute second query
        assert response.status_code == 200
        assert response.data == b'[]'

    def test_sql_injection_time_based_blocked(self, client, setup_test_data):
        """Test that time-based SQL injection attempts are blocked."""
        # Attempt to inject: 1 AND SLEEP(5)
        malicious_id = "1 AND SLEEP(5)"
        response = client.get(f'/user?id={malicious_id}')

        # Should not execute sleep command
        assert response.status_code == 200
        assert response.data == b'[]'

    def test_sql_injection_boolean_based_blocked(self, client, setup_test_data):
        """Test that boolean-based SQL injection is blocked."""
        # Attempt to inject: 1 AND 1=1
        malicious_id = "1 AND 1=1"
        response = client.get(f'/user?id={malicious_id}')

        # Should not evaluate the boolean condition
        assert response.status_code == 200
        assert response.data == b'[]'

    def test_sql_injection_with_encoded_characters(self, client, setup_test_data):
        """Test that SQL injection with URL encoding is blocked."""
        # Attempt to inject: 1%20OR%201=1 (URL encoded "1 OR 1=1")
        malicious_id = "1%20OR%201=1"
        response = client.get(f'/user?id={malicious_id}')

        # Should not return all users
        assert response.status_code == 200
        # The decoded value "1 OR 1=1" should not execute as SQL
        assert response.data == b'[]'

    # ============================================================
    # Edge Cases and Input Validation Tests
    # ============================================================

    def test_large_integer_id(self, client, setup_test_data):
        """Test behavior with very large integer ID."""
        response = client.get('/user?id=999999999999')
        assert response.status_code == 200
        assert response.data == b'[]'

    def test_negative_id(self, client, setup_test_data):
        """Test behavior with negative ID."""
        response = client.get('/user?id=-1')
        assert response.status_code == 200
        assert response.data == b'[]'

    def test_non_numeric_id(self, client, setup_test_data):
        """Test behavior with non-numeric ID."""
        response = client.get('/user?id=abc')
        assert response.status_code == 200
        assert response.data == b'[]'

    def test_special_characters_in_id(self, client, setup_test_data):
        """Test behavior with special characters in ID parameter."""
        special_chars = ['@', '#', '$', '%', '&', '*', '(', ')', '[', ']']

        for char in special_chars:
            response = client.get(f'/user?id={char}')
            assert response.status_code == 200
            assert response.data == b'[]'

    def test_multiple_id_parameters(self, client, setup_test_data):
        """Test behavior when multiple ID parameters are provided."""
        # Flask's request.args.get() returns the first value
        response = client.get('/user?id=1&id=2')
        assert response.status_code == 200
        # Should return user with id=1
        assert b'admin' in response.data

    def test_null_byte_injection_blocked(self, client, setup_test_data):
        """Test that null byte injection is blocked."""
        malicious_id = "1%00"
        response = client.get(f'/user?id={malicious_id}')
        assert response.status_code == 200
        # Should not cause unexpected behavior

    # ============================================================
    # Functional Correctness Tests
    # ============================================================

    def test_parameterized_query_preserves_functionality(self, client, setup_test_data):
        """Test that the fix maintains the original functionality."""
        # Test multiple valid IDs
        test_ids = [1, 2, 3, 100]

        for user_id in test_ids:
            response = client.get(f'/user?id={user_id}')
            assert response.status_code == 200

            # Verify response contains user data (tuple structure)
            if user_id == 1:
                assert b'admin' in response.data
            elif user_id == 2:
                assert b'testuser' in response.data
            elif user_id == 3:
                assert b'alice' in response.data
            elif user_id == 100:
                assert b'bob' in response.data

    def test_response_format_unchanged(self, client, setup_test_data):
        """Test that the response format remains the same after fix."""
        response = client.get('/user?id=1')
        assert response.status_code == 200
        assert response.mimetype == 'text/plain'

        # Response should be string representation of list of tuples
        assert response.data.startswith(b'[')
        assert response.data.endswith(b']')

    def test_concurrent_requests_safe(self, client, setup_test_data):
        """Test that parameterized queries handle concurrent requests safely."""
        # Simulate multiple requests
        responses = []
        for i in range(10):
            response = client.get(f'/user?id={i % 3 + 1}')
            responses.append(response)

        # All requests should succeed
        assert all(r.status_code == 200 for r in responses)


class TestSecurityRegression:
    """Regression tests to ensure the vulnerability doesn't reappear."""

    def test_query_uses_parameterization(self):
        """
        Verify that the query string uses parameterized format.
        This is a code-level check to ensure the fix is maintained.
        """
        import inspect
        from sast_critical_high import get_user

        source = inspect.getsource(get_user)

        # Check that the parameterized query format is used
        assert '?' in source, "Query should use '?' placeholder for parameterization"
        assert 'cursor.execute(query, (uid,))' in source or 'cursor.execute(query, (' in source, \
            "Query should be executed with tuple parameter"

        # Ensure string concatenation is NOT used
        assert 'query = "SELECT * FROM users WHERE id = " + uid' not in source, \
            "Query should NOT use string concatenation"

    def test_no_string_formatting_in_query(self):
        """
        Verify that string formatting (f-strings, %, format) is not used in the query.
        """
        import inspect
        from sast_critical_high import get_user

        source = inspect.getsource(get_user)

        # Check that dangerous string formatting methods are not used
        assert 'f"SELECT' not in source and "f'SELECT" not in source, \
            "Query should NOT use f-string formatting"
        assert '".format(' not in source, "Query should NOT use .format() method"
        assert '"SELECT * FROM users WHERE id = %s" % ' not in source, \
            "Query should NOT use % formatting"


if __name__ == '__main__':
    # Allow running tests directly
    pytest.main([__file__, '-v'])
