# GitHub Actions & Dependabot Configuration

This directory contains GitHub Actions workflows and Dependabot configuration for the WhiteRabbitMCP project.

## Files Overview

### 🤖 `dependabot.yml`
Configures Dependabot to automatically create pull requests for dependency updates:

- **Python dependencies**: Weekly updates on Mondays at 9:00 AM
- **Docker dependencies**: Weekly updates on Mondays at 9:30 AM  
- **GitHub Actions**: Weekly updates on Mondays at 10:00 AM

**Auto-merge Configuration:**
- Patch updates are allowed for auto-merge
- Development dependencies can auto-merge minor updates
- Major updates require manual review

### 🔄 `dependabot-auto-merge.yml`
Automatically merges Dependabot PRs that meet safety criteria:

**Auto-merge Conditions:**
- ✅ Patch updates (e.g., 1.0.1 → 1.0.2)
- ✅ Minor updates for dev dependencies (e.g., 1.0.0 → 1.1.0)
- ❌ Major updates require manual review (e.g., 1.0.0 → 2.0.0)

**Safety Checks:**
- Python import tests
- Toolkit module validation
- Docker build verification
- Basic functionality tests

### 🔒 `security-checks.yml`
Comprehensive security and quality analysis:

**Security Tools:**
- **Safety**: Checks for known vulnerabilities in Python dependencies
- **Bandit**: Static security analysis for Python code
- **Trivy**: Container and filesystem vulnerability scanning
- **Secret Detection**: Scans for hardcoded secrets and API keys

**Container Security:**
- Validates Docker build process
- Checks container user permissions
- Scans for security misconfigurations

### 🧪 `ci.yml`
Continuous integration pipeline:

**Test Matrix:**
- Python versions: 3.10, 3.11, 3.12
- Cross-platform compatibility testing

**Quality Checks:**
- Code linting with flake8
- Import validation
- Docker build verification
- Security scanning with Trivy

## How Auto-merge Works

1. **Dependabot creates a PR** for dependency updates
2. **CI pipeline runs** basic tests and security checks
3. **Auto-merge workflow evaluates** the update type:
   - **Patch updates**: Auto-merged after tests pass
   - **Minor dev updates**: Auto-merged after tests pass
   - **Major updates**: Flagged for manual review
4. **Labels are applied** based on update severity
5. **Comments are added** for major updates requiring attention

## Security Features

### 🛡️ Multi-layer Security
- Dependency vulnerability scanning
- Static code analysis
- Container security validation
- Secret detection
- Supply chain security monitoring

### 🏷️ Automated Labeling
- `patch-update, auto-mergeable`: Safe for auto-merge
- `minor-update`: Minor changes, may auto-merge
- `major-update, needs-review`: Requires manual review

### 📊 Reporting
- Security scan results uploaded as artifacts
- SARIF reports integrated with GitHub Security tab
- Detailed logs for all security checks

## Configuration Customization

### Adjusting Auto-merge Rules
Edit `.github/workflows/dependabot-auto-merge.yml`:

```yaml
# Example: Allow minor updates for production dependencies
- name: Auto-merge minor updates for production
  if: ${{ steps.metadata.outputs.update-type == 'version-update:semver-minor' && steps.metadata.outputs.dependency-type == 'direct:production' }}
```

### Modifying Dependabot Schedule
Edit `.github/dependabot.yml`:

```yaml
schedule:
  interval: "daily"  # Options: daily, weekly, monthly
  time: "06:00"      # UTC time
  day: "sunday"      # For weekly interval
```

### Adding Custom Security Checks
Edit `.github/workflows/security-checks.yml`:

```yaml
- name: Custom security check
  run: |
    # Add your custom security validation here
    echo "Running custom security checks..."
```

## Permissions Required

The workflows require the following GitHub token permissions:

```yaml
permissions:
  contents: write          # For auto-merging PRs
  pull-requests: write     # For PR management
  security-events: write   # For security reporting
  checks: read            # For status checks
  actions: read           # For workflow access
```

## Monitoring & Maintenance

### 📈 Metrics to Monitor
- Auto-merge success rate
- Security scan findings
- Dependency update frequency
- Build failure rates

### 🔧 Regular Maintenance
- Review security scan results weekly
- Update workflow dependencies monthly
- Audit auto-merge rules quarterly
- Review and update security policies

## Troubleshooting

### Auto-merge Not Working
1. Check if branch protection rules allow auto-merge
2. Verify GitHub token permissions
3. Review workflow logs for errors
4. Ensure all required status checks pass

### Security Scans Failing
1. Review security scan artifacts
2. Check for new vulnerabilities in dependencies
3. Update security scanning tools
4. Review and fix any security issues found

### False Positives
1. Add exceptions to security scanning tools
2. Update scanning configurations
3. Document known false positives
4. Consider allowlisting specific findings

## Best Practices

✅ **Do:**
- Review major updates manually
- Monitor security scan results
- Keep workflow dependencies updated
- Test auto-merge rules in staging

❌ **Don't:**
- Auto-merge major version updates
- Ignore security scan findings
- Disable security checks for speed
- Skip manual review of critical dependencies
