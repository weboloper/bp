# 🔧 Code Quality & Pre-commit Hooks Guide

Takım çalışmasında kod kalitesi ve tutarlılığını sağlamak için pre-commit hooks rehberi.

## 🤔 Pre-commit Hooks Nedir?

### Problem
```bash
😤 Takım üyeleri farklı code style kullanıyor
🐛 Syntax hatalar commit'leniyor  
📝 Import'lar düzensiz ve karışık
🔥 Debug print'leri production'a gidiyor
💥 Linting hatalar CI/CD'yi bozuyor
⏱️ Code review'lerde format tartışmaları
```

### Çözüm
```bash
✅ Otomatik code formatting (Black)
✅ Import organizing (isort)  
✅ Linting checks (flake8)
✅ Security scanning (Bandit)
✅ Git hygiene controls
✅ Django best practices
```

Pre-commit hooks, **git commit öncesi otomatik çalışan** kod kalitesi kontrolleridir.

---

## 🛠️ Nasıl Çalışır?

### Workflow
```bash
1. Developer: git commit -m "new feature"
2. Pre-commit: "Dur! Önce kontrol edeyim..."
3. Pre-commit: Code'u otomatik düzelt/kontrol et
4. Eğer sorun varsa: ❌ Commit DURUR
5. Developer: Sorunları düzeltir  
6. Pre-commit: ✅ "Tamam, commit'leyebilirsin!"
```

### Example Flow
```bash
$ git commit -m "add user model"

black....................................................................Failed
- hook id: black
- files were modified by this hook

reformatted users/models.py
1 file reformatted.

flake8...................................................................Failed  
- hook id: flake8
- exit code: 1

users/models.py:15:80: E501 line too long (89 > 79 characters)
users/models.py:23:1: F401 'os' imported but unused

# ❌ Commit başarısız! Sorunları düzelt:
$ git add .  # Black otomatik düzeltti
$ vim users/models.py  # Manuel düzeltmeler
$ git commit -m "add user model"  
# ✅ Tüm kontroller geçti, commit başarılı!
```

---

## 🚀 Setup (One-time)

### Option 1: Automatic Setup (Recommended)
```bash
# Pre-commit'i otomatik kur
./scripts/setup_precommit.sh
```

### Option 2: Manual Setup
```bash
# 1. Containers'ı başlat
make up

# 2. Pre-commit'i kur
make precommit-install

# 3. İlk çalıştırma (tüm dosyalar)
make precommit-run
```

### Verification
```bash
# Pre-commit kurulumunu test et
git add .
git commit -m "test commit"
# Hooks çalışmalı (geçerse veya düzeltmeler yaparsa ✅)
```

---

## 📋 Configured Hooks

### 🎨 Code Formatting
```yaml
black:
  - Purpose: Python code formatting (PEP8)
  - Auto-fix: ✅ Yes
  - Config: 88 character line length
  - Files: backend/**/*.py

isort:
  - Purpose: Import statement organizing  
  - Auto-fix: ✅ Yes
  - Config: Black-compatible profile
  - Files: backend/**/*.py
```

### 🔍 Code Quality
```yaml
flake8:
  - Purpose: Style guide enforcement (PEP8)
  - Auto-fix: ❌ No (manual fix required)
  - Checks: Line length, unused imports, syntax errors
  - Files: backend/**/*.py

django-upgrade:
  - Purpose: Modern Django patterns
  - Auto-fix: ✅ Yes
  - Target: Django 5.0+ features
  - Files: backend/**/*.py
```

### 🛡️ Security & Safety
```yaml
bandit:
  - Purpose: Security vulnerability scanning
  - Auto-fix: ❌ No (manual review required)
  - Checks: SQL injection, hardcoded passwords, etc.
  - Files: backend/**/*.py

detect-private-key:
  - Purpose: Prevents committing private keys
  - Auto-fix: ❌ No (remove manually)
  - Files: All files
```

### 🧹 Git Hygiene
```yaml
trailing-whitespace:
  - Purpose: Remove trailing whitespace
  - Auto-fix: ✅ Yes

end-of-file-fixer:
  - Purpose: Ensure files end with newline
  - Auto-fix: ✅ Yes

check-merge-conflict:
  - Purpose: Detect merge conflict markers
  - Auto-fix: ❌ No (resolve conflicts)

check-added-large-files:
  - Purpose: Prevent large files (>500KB)
  - Auto-fix: ❌ No (use Git LFS or remove)
```

### 🔧 Validation
```yaml
check-json:
  - Purpose: JSON syntax validation
  - Files: *.json

check-yaml:
  - Purpose: YAML syntax validation  
  - Files: *.yml, *.yaml (except docker-compose)

debug-statements:
  - Purpose: Detect debug prints/breakpoints
  - Files: *.py
```

---

## 💻 Daily Usage

### Normal Development Workflow
```bash
# 1. Write your code
vim backend/apps/users/models.py

# 2. Stage changes  
git add .

# 3. Commit (pre-commit runs automatically)
git commit -m "add user authentication"

# 4a. If successful: ✅ Done!
# 4b. If failed: Fix issues and commit again
```

### Manual Code Quality Checks
```bash
# Format code manually
make format

# Run linting checks
make lint

# Run all quality checks
make code-check

# Run pre-commit on all files
make precommit-run
```

---

## 🔧 Available Commands

### Makefile Commands
```bash
make format              # Auto-format with Black + isort
make lint               # Run flake8 linting
make code-check         # Run all quality checks
make precommit-install  # Install pre-commit hooks
make precommit-run      # Run hooks on all files
make precommit-update   # Update hook versions
```

### Direct Docker Commands
```bash
# Format specific file
docker compose exec backend black /app/users/models.py

# Check specific file
docker compose exec backend flake8 /app/users/models.py

# Run security scan
docker compose exec backend bandit -r /app

# Check imports
docker compose exec backend isort /app --check-only
```

---

## 🚨 Common Issues & Solutions

### Issue 1: Black Reformatted Files
```bash
Problem: 
  black....................................................................Failed
  - files were modified by this hook

Solution:
  git add .  # Add the reformatted files
  git commit -m "your message"  # Commit again
  
Why: Black automatically fixed formatting, just need to stage changes
```

### Issue 2: Line Too Long (flake8)
```bash
Problem:
  E501 line too long (95 > 88 characters)

Solutions:
  # Option 1: Break line manually
  very_long_variable_name = (
      "very long string that exceeds "
      "the character limit"
  )
  
  # Option 2: Use parentheses
  result = some_function(
      parameter1, parameter2, 
      parameter3, parameter4
  )
  
  # Option 3: Ignore specific line (use sparingly)
  long_line = "..."  # noqa: E501
```

### Issue 3: Unused Imports (flake8)
```bash
Problem:
  F401 'os' imported but unused

Solution:
  # Remove the unused import
  # import os  ← Remove this line
  
  # Or if used in comments/docstrings:
  import os  # noqa: F401
```

### Issue 4: Security Issues (bandit)
```bash
Problem:
  B101 Test for use of assert
  B601 shell_injection_via_subprocess

Solutions:
  # Review security warning carefully
  # Either fix the issue or add # nosec comment if false positive
  subprocess.call(cmd, shell=True)  # nosec B602
```

### Issue 5: Large Files
```bash
Problem:
  check-added-large-files..............................................Failed
  - files were modified by this hook

Solution:
  # Use Git LFS for large files
  git lfs track "*.pdf"
  git lfs track "*.zip"
  
  # Or remove large files from repo
  git rm large_file.zip
```

---

## ⚙️ Configuration

### Skip Hooks for Specific Commits
```bash
# Skip all hooks (emergency only)
git commit -m "hotfix" --no-verify

# Skip specific files (in .pre-commit-config.yaml)
exclude: |
  (?x)^(
    .*migrations/.*\.py|
    .*__pycache__/.*|
    legacy_code/.*\.py
  )$
```

### Custom Hook Configuration
```yaml
# Edit .pre-commit-config.yaml

# Adjust Black line length
- repo: https://github.com/psf/black
  hooks:
    - id: black
      args: [--line-length=100]  # Change from 88 to 100

# Add custom flake8 ignores  
- repo: https://github.com/pycqa/flake8
  hooks:
    - id: flake8
      args: [--max-line-length=88, --extend-ignore=E203,W503,F401]
```

### Environment-specific Setup
```bash
# Development only (default)
# Pre-commit works in development containers

# Production
# Pre-commit hooks don't run in production
# Code quality ensured before deployment

# CI/CD Integration
# Add to GitHub Actions:
- name: Run pre-commit
  uses: pre-commit/action@v3.0.0
```

---

## 🎯 Best Practices

### Team Adoption
```bash
✅ Setup pre-commit on day 1 of project
✅ Run initial formatting on entire codebase  
✅ Document the process for new team members
✅ Include pre-commit in onboarding checklist
✅ Use consistent IDE settings (Black, isort plugins)
```

### Code Review Process
```bash
✅ Pre-commit reduces formatting discussions
✅ Focus reviews on logic, not style
✅ Security issues caught before review
✅ Faster CI/CD (pre-filtered code)
✅ Higher code quality standards
```

### Configuration Management
```bash
✅ Keep .pre-commit-config.yaml in version control
✅ Update hooks quarterly: make precommit-update  
✅ Test new hooks in feature branch first
✅ Document any custom configurations
✅ Align with IDE settings (Black, flake8)
```

### Performance Tips
```bash
✅ Pre-commit only runs on changed files (fast)
✅ Use make format for quick manual formatting
✅ Run make precommit-run after major refactors
✅ Skip hooks for emergency hotfixes only
✅ Keep hook configuration minimal
```

---

## 📊 Benefits

### Individual Developer
```bash
🚀 Automatic code improvement
📚 Learn best practices gradually
🐛 Catch bugs before they reach production
⚡ Faster development (less manual formatting)
🛡️ Security awareness (Bandit warnings)
```

### Team Collaboration  
```bash
🤝 Consistent code style across team
🔄 No more "fix formatting" commits
📋 Standardized import organization
⚡ Faster code reviews (focus on logic)
🎯 Professional development standards
```

### Project Quality
```bash
📈 Higher code quality scores
🛡️ Security vulnerabilities caught early  
🚀 Faster CI/CD pipeline (pre-filtered)
📚 Better maintainability
🏆 Industry-standard development practices
```

---

## 🔄 Integration with BP Boilerplate

### Works With
```bash
✅ All environments (dev/staging/prod)
✅ Docker development workflow
✅ Existing Makefile commands
✅ Django project structure
✅ Team development process
```

### File Coverage
```bash
🎯 Backend Python files (.py)
🎯 Configuration files (.json, .yaml)  
🎯 All files (whitespace, large files)
❌ Frontend files (not covered)
❌ Docker files (syntax only)
```

### CI/CD Integration Ready
```bash
# GitHub Actions example:
name: Code Quality
on: [push, pull_request]
jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: 3.11
      - uses: pre-commit/action@v3.0.0
```

---

## 🎯 Quick Reference

### First Time Setup
```bash
1. ./scripts/setup_precommit.sh
2. git add .
3. git commit -m "initial commit"
4. Fix any issues and commit again
```

### Daily Commands
```bash
# Normal workflow (automatic)
git add . && git commit -m "feature"

# Manual checks
make code-check

# Fix formatting
make format
```

### Troubleshooting
```bash
# Reset hooks
make precommit-install

# Update hooks  
make precommit-update

# Skip once (emergency)
git commit --no-verify
```

### Configuration Files
```bash
.pre-commit-config.yaml    # Hook configuration
backend/requirements.txt   # Dependencies
Makefile                  # Easy commands
scripts/setup_precommit.sh # Setup script
```

---

**🎯 Bottom Line:** Pre-commit hooks takım çalışmasında kod kalitesi için **game-changer**! İlk kurulumdan sonra otomatik çalışır ve profesyonel development standartları sağlar. 🏆

Bu rehber ile BP Boilerplate'de enterprise-grade kod kalitesi standardını uygulayabilirsiniz! 🚀
