# EmailLM Test Suite

This directory contains the pytest-based unit tests for EmailLM.

## Running Tests

### Basic Test Run
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_config_validation.py

# Run specific test function
pytest tests/test_config_validation.py::TestValidateFolderName::test_valid_folder_name
```

### Running with Coverage
```bash
# Run tests with coverage report
pytest --cov=emaillm --cov-report=term-missing

# Generate HTML coverage report
pytest --cov=emaillm --cov-report=html:htmlcov
# Then open htmlcov/index.html in a browser

# Generate XML coverage report (for CI/CD)
pytest --cov=emaillm --cov-report=xml:coverage.xml
```

### Test Coverage Thresholds
The `pyproject.toml` configuration sets coverage thresholds. To adjust:
```bash
# Run with specific coverage threshold
pytest --cov=emaillm --cov-fail-under=80
```

## Test Organization

### Test Files
- `test_config_validation.py` - Configuration and folder name validation
- `test_email_parsing.py` - Email message parsing and extraction
- `test_domain_matching.py` - Domain matching and allowlist logic
- `test_authentication_validation.py` - DKIM, SPF, and header validation
- `test_dataclasses.py` - Dataclass and configuration structures
- `test_uninstaller.py` - Uninstaller script tests

### Fixtures
Common test fixtures are defined in `conftest.py`:
- `sample_email_plain` - Plain text email
- `sample_email_html` - HTML email
- `sample_email_with_auth` - Email with authentication headers
- `sample_email_spoofed` - Email with failed authentication
- `sample_multipart_email` - Multipart email
- `sample_email_with_attachments` - Email with attachments
- `sample_email_reply` - Reply email with In-Reply-To headers

## Writing New Tests

### Test Structure
```python
import pytest
from emaillm import function_to_test

class TestFunctionName:
    """Test class for function_to_test."""
    
    def test_case_name(self, fixture_name):
        """Test description."""
        # Arrange
        # Act
        result = function_to_test(fixture_name)
        # Assert
        assert result == expected_value
```

### Using Fixtures
```python
def test_parsing(sample_email_plain):
    """Use a fixture from conftest.py."""
    email = EmailMessage.from_raw_bytes(sample_email_plain)
    assert email.subject == "Test Email"
```

### Mocking External Dependencies
```python
from unittest.mock import patch, MagicMock

@patch("emaillm.requests.post")
def test_vllm_integration(mock_post):
    """Mock external API calls."""
    mock_post.return_value = MagicMock(
        status_code=200,
        json=lambda: {"choices": [{"message": {"content": "spam"}}]}
    )
    
    result = classify_email_vllm(...)
    assert result.category == "spam"
```

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests with coverage
        run: pytest --cov=emaillm --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Test Coverage Goals

- **Target**: 80%+ code coverage
- **Critical paths**: 100% coverage for:
  - Email parsing
  - Authentication validation
  - Domain matching
  - Configuration loading
  - Security validations

## Debugging Tests

### Run with Python Debugger
```bash
# Set breakpoint and debug
pytest --pdb tests/test_file.py::test_function

# Debug on failure
pytest -vv --tb=long tests/test_file.py
```

### Enable Logging in Tests
```python
def test_with_logging(caplog):
    with caplog.at_level(logging.DEBUG):
        function_to_test()
        assert "debug message" in caplog.text
```

## Best Practices

1. **One assertion per test** - Makes failures easier to understand
2. **Descriptive test names** - `test_dkim_pass_returns_valid` not `test_dkim_1`
3. **Use fixtures** - Don't duplicate test data
4. **Mock external dependencies** - Don't call real APIs in tests
5. **Test edge cases** - Empty inputs, invalid data, boundary conditions
6. **Keep tests independent** - Tests should not depend on each other's state
7. **Use parametrization** for similar test cases:
```python
@pytest.mark.parametrize("input,expected", [
    ("example.com", True),
    ("other.com", False),
])
def test_domain_matching(input, expected):
    assert domain_matches(input, "example.com") == expected
```
