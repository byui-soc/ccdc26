# CCDC26 Application Discoveries

**Early Access Session:** January 21, 2026

---

## Ubuntu Ecom Server (172.20.242.30)

### Application: OpenCart E-Commerce Platform

**Discovered:** nmap scan shows Apache httpd 2.4.58 on port 80

**Admin Panel:** `http://172.20.242.30/admin`
- Username/password login form
- **CRITICAL:** This is a primary target for red team attacks

**Confirmed Database Details (from MySQL inspection):**
- Database name: `opencart`
- Admin table: `oc_user`
- Admin user: `admin`
- Admin email: `admin@example.com`
- Password hashing: **bcrypt** (`$2y$10$...`)
- User status: Active (1)
- Account created: 2025-10-17

**Suspicious Files Found in /home/sysadmin:**
- `install-ssh-req.sh` - Script that installs python3-paramiko and openssh-server
  - **WARNING:** Paramiko is used by the startup_check malware for SSH connections
  - This script may be related to malware installation
- `opencart-master/` directory and `master.zip` - OpenCart source files
  - May be leftover from manual installation
  - Could potentially be used by red team for version information

**Common OpenCart Default Credentials to Try:**
- `admin / admin`
- `admin / password`
- `admin / demo`
- `demo / demo`

**OpenCart Security Concerns:**
1. **Admin Panel Access** - Red team will brute force this
2. **SQL Injection** - Older versions have SQLi vulnerabilities
3. **File Upload** - Can be exploited for web shells
4. **Default Files** - Install directories may still be present
5. **Database Credentials** - Stored in `config.php`

---

## 🚨 IMMEDIATE ACTIONS ON GAME START

### 1. Secure Admin Panel (Minute 5-10)

**SSH to Ecom server:**

```bash
ssh sysadmin@172.20.242.30
# Password: changeme (or new team password after reset)

# Navigate to web root
cd /var/www/html  # or check Apache config
ls -la

# Find OpenCart admin directory
ls -la admin/
ls -la opencart/
```

**Try to login to admin panel:**
- URL: http://172.20.242.30/admin
- Try common credentials listed above
- **Document the working credentials**

### 2. Change Admin Password (HIGH PRIORITY)

**If you can access the admin panel:**

1. Login to OpenCart admin
2. Navigate to: System → Users → Users
3. Change the admin password to your team password
4. **Document this in competition notes**

**If you can't login (forgotten password):**

**IMPORTANT: OpenCart uses bcrypt password hashing (confirmed from database inspection)**

```bash
# Reset admin password via MySQL
sudo mysql -u root -p

# Use OpenCart database (confirmed name: opencart)
USE opencart;

# List admin users (confirmed table: oc_user)
SELECT user_id, username, email, status FROM oc_user;

# Confirmed admin user:
# - username: admin
# - email: admin@example.com
# - password: bcrypt hash ($2y$10$...)

# Generate bcrypt hash for new password
# Option 1: Use PHP on the server
php -r "echo password_hash('YourNewTeamPassword', PASSWORD_BCRYPT) . PHP_EOL;"

# Option 2: Use Python
python3 -c "import bcrypt; print(bcrypt.hashpw(b'YourNewTeamPassword', bcrypt.gensalt(rounds=10)).decode())"

# Copy the generated hash, then update in MySQL:
UPDATE oc_user SET password = '$2y$10$GENERATED_HASH_HERE' WHERE username = 'admin';
EXIT;
```

**Quick password reset with PHP (easier):**

```bash
# One-liner to reset admin password
sudo mysql -u root -p -e "USE opencart; UPDATE oc_user SET password = '$(php -r "echo password_hash('YourNewTeamPassword', PASSWORD_BCRYPT);")' WHERE username = 'admin';"
```

### 3. Harden OpenCart Installation

**Remove installation directory (CRITICAL):**

```bash
# Check if install directory exists
ls -la /var/www/html/install/

# Remove it (prevents reinstallation attacks)
sudo rm -rf /var/www/html/install/
```

**Rename admin directory (obfuscation):**

```bash
# Rename admin to something non-obvious
sudo mv /var/www/html/admin /var/www/html/admin_ccdc2024

# Update config file
sudo nano /var/www/html/config.php
# Find: define('HTTP_ADMIN', 'http://yourdomain.com/admin/');
# Change to: define('HTTP_ADMIN', 'http://yourdomain.com/admin_ccdc2024/');

# Also update admin config
sudo nano /var/www/html/admin_ccdc2024/config.php
```

**Set proper permissions:**

```bash
# Config files should NOT be writable by web server
sudo chmod 644 /var/www/html/config.php
sudo chmod 644 /var/www/html/admin*/config.php

# Image directories need to be writable
sudo chown -R www-data:www-data /var/www/html/image/
sudo chown -R www-data:www-data /var/www/html/system/storage/

# Everything else should be read-only
find /var/www/html -type d -exec sudo chmod 755 {} \;
find /var/www/html -type f -exec sudo chmod 644 {} \;
```

### 4. Rate Limit Admin Login (Prevent Brute Force)

**Option A: Use fail2ban (recommended):**

```bash
# Install fail2ban
sudo apt install -y fail2ban

# Create OpenCart jail
sudo nano /etc/fail2ban/jail.d/opencart.conf
```

Add:
```ini
[opencart-admin]
enabled = true
port = http,https
filter = opencart-admin
logpath = /var/log/apache2/access.log
maxretry = 3
bantime = 3600
findtime = 600
```

**Create filter:**
```bash
sudo nano /etc/fail2ban/filter.d/opencart-admin.conf
```

Add:
```ini
[Definition]
failregex = ^<HOST> .* "POST /admin.*/login HTTP/.*" 200
ignoreregex =
```

**Restart fail2ban:**
```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status opencart-admin
```

**Option B: Use ModSecurity (WAF):**

```bash
# Install ModSecurity
sudo apt install -y libapache2-mod-security2

# Enable module
sudo a2enmod security2
sudo systemctl restart apache2
```

### 5. Database Security

**Find database credentials:**

```bash
# OpenCart stores DB creds in config.php
sudo grep -i "db_" /var/www/html/config.php

# Confirmed database configuration:
# - Database name: opencart
# - Admin table: oc_user
# - Admin username: admin
# - Admin email: admin@example.com

# Typical format in config.php:
# define('DB_HOSTNAME', 'localhost');
# define('DB_USERNAME', 'opencart_user');  # Check actual username
# define('DB_PASSWORD', 'password123');    # Current password
# define('DB_DATABASE', 'opencart');        # Confirmed database name
```

**Change database password:**

```bash
# Login to MySQL
sudo mysql -u root -p

# Change OpenCart DB user password
ALTER USER 'opencart_user'@'localhost' IDENTIFIED BY 'NewStrongPassword!';
FLUSH PRIVILEGES;
EXIT;

# Update config.php with new password
sudo nano /var/www/html/config.php
# Update: define('DB_PASSWORD', 'NewStrongPassword!');
```

### 6. Check for Malicious Extensions/Modifications

**Check for backdoors in uploads:**

```bash
# Search for suspicious PHP files
sudo find /var/www/html -type f -name "*.php" -exec grep -l "eval\|base64_decode\|system\|exec\|shell_exec" {} \;

# Check recently modified files
sudo find /var/www/html -type f -mtime -1 -ls

# Look for suspicious files in upload directories
sudo ls -la /var/www/html/image/
sudo ls -la /var/www/html/system/storage/upload/
```

**Review installed extensions:**
1. Login to admin panel
2. Navigate to: Extensions → Extensions
3. Check for unfamiliar or suspicious extensions
4. Disable/uninstall anything suspicious

### 7. Enable Apache Security Headers

```bash
# Edit Apache config
sudo nano /etc/apache2/sites-available/000-default.conf

# Add inside <VirtualHost> block:
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>

# Enable headers module
sudo a2enmod headers
sudo systemctl restart apache2
```

---

## 🔍 MONITORING OPENCART

### Watch for Attack Patterns

**Check Apache logs:**

```bash
# Watch access log in real-time
sudo tail -f /var/log/apache2/access.log | grep -i "admin"

# Look for brute force attempts (many POST to /admin/login)
sudo grep "POST.*admin.*login" /var/log/apache2/access.log | wc -l

# Find IPs attacking admin panel
sudo grep "POST.*admin.*login" /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn
```

**Block attacking IPs:**

```bash
# Using UFW
sudo ufw deny from <attacking_ip>

# Using iptables
sudo iptables -A INPUT -s <attacking_ip> -j DROP
```

**Check for SQL injection attempts:**

```bash
# Look for SQLi patterns in logs
sudo grep -iE "union.*select|concat\(|0x[0-9a-f]" /var/log/apache2/access.log
```

---

## 📊 OPENCART HEALTH CHECKS

### Verify Scored Service (HTTP/HTTPS)

```bash
# Test from another machine
curl http://172.20.242.30
curl -k https://172.20.242.30

# Check Apache is running
sudo systemctl status apache2

# Check Apache error log
sudo tail -50 /var/log/apache2/error.log
```

### Performance Check

```bash
# Check Apache connections
sudo netstat -tuln | grep :80

# Monitor Apache processes
sudo ps aux | grep apache2

# Check system resources
top
df -h
```

---

## 🛡️ OPENCART HARDENING SCRIPT

**Create automated hardening script:**

```bash
sudo nano /opt/ccdc26/linux-scripts/service-hardening/harden-opencart.sh
```

```bash
#!/bin/bash
# OpenCart Hardening Script

set -e

WEBROOT="/var/www/html"
ADMIN_DIR="$WEBROOT/admin"
NEW_ADMIN_DIR="$WEBROOT/admin_ccdc2024"

echo "=== Hardening OpenCart Installation ==="

# 1. Remove install directory
if [ -d "$WEBROOT/install" ]; then
    echo "[1/6] Removing install directory..."
    rm -rf "$WEBROOT/install"
    echo "  ✓ Install directory removed"
else
    echo "[1/6] Install directory not found (good)"
fi

# 2. Rename admin directory
if [ -d "$ADMIN_DIR" ] && [ ! -d "$NEW_ADMIN_DIR" ]; then
    echo "[2/6] Renaming admin directory..."
    mv "$ADMIN_DIR" "$NEW_ADMIN_DIR"
    echo "  ✓ Admin directory renamed to: admin_ccdc2024"
    echo "  ⚠️  Update config.php HTTP_ADMIN setting manually!"
else
    echo "[2/6] Admin directory already renamed or not found"
fi

# 3. Set secure permissions
echo "[3/6] Setting secure file permissions..."
find "$WEBROOT" -type d -exec chmod 755 {} \;
find "$WEBROOT" -type f -exec chmod 644 {} \;
chmod 644 "$WEBROOT/config.php"
[ -d "$NEW_ADMIN_DIR" ] && chmod 644 "$NEW_ADMIN_DIR/config.php"
chown -R www-data:www-data "$WEBROOT"
echo "  ✓ Permissions set"

# 4. Install fail2ban
echo "[4/6] Installing fail2ban..."
apt-get install -y fail2ban &>/dev/null
echo "  ✓ fail2ban installed"

# 5. Enable Apache security headers
echo "[5/6] Enabling Apache security headers..."
a2enmod headers &>/dev/null
# Headers config would need to be added to Apache conf separately
echo "  ✓ Headers module enabled"

# 6. Restart Apache
echo "[6/6] Restarting Apache..."
systemctl restart apache2
echo "  ✓ Apache restarted"

echo ""
echo "=== OpenCart Hardening Complete ==="
echo ""
echo "MANUAL STEPS REQUIRED:"
echo "  1. Login to admin panel and change admin password"
echo "  2. Update config.php with new admin directory path"
echo "  3. Review and disable unnecessary extensions"
echo "  4. Change database password"
echo ""
```

---

## 📝 NOTES

### OpenCart Vulnerabilities to Watch For

**Known CVEs (check version):**
- CVE-2020-10596 - SQL Injection
- CVE-2020-12256 - Arbitrary File Upload
- CVE-2021-22143 - XSS
- CVE-2022-27598 - Authentication Bypass

**Version Detection:**

```bash
# Check OpenCart version
sudo grep -i "version" /var/www/html/index.php
sudo grep -i "version" /var/www/html/system/startup.php

# Check via curl (if version displayed in HTML)
curl http://172.20.242.30 | grep -i "opencart"
```

### Backup Before Changes

```bash
# Backup web directory
sudo tar -czf /tmp/opencart_backup_$(date +%Y%m%d_%H%M%S).tar.gz /var/www/html/

# Backup database
sudo mysqldump -u root -p opencart_db > /tmp/opencart_db_backup_$(date +%Y%m%d_%H%M%S).sql
```

---

## 🔧 TROUBLESHOOTING COMMON ERRORS

### Stylesheet Not Loading / NS_ERROR_CONNECTION

**Symptoms:**
- Admin panel won't load
- Stylesheet errors in browser console
- Connection refused errors
- Unstyled/blank pages

**Quick Fix Script:**

```bash
ssh sysadmin@172.20.242.30
cd /opt/ccdc26/linux-scripts/service-hardening
sudo ./fix-opencart-errors.sh
```

**Manual Steps:**

1. **Check Apache is running:**
   ```bash
   sudo systemctl status apache2
   sudo systemctl restart apache2
   ```

2. **Enable required Apache modules:**
   ```bash
   sudo a2enmod rewrite
   sudo a2enmod headers
   sudo systemctl restart apache2
   ```

3. **Fix file permissions:**
   ```bash
   sudo chown -R www-data:www-data /var/www/html
   sudo find /var/www/html -type d -exec chmod 755 {} \;
   sudo find /var/www/html -type f -exec chmod 644 {} \;
   sudo chmod -R 777 /var/www/html/image/
   sudo chmod -R 777 /var/www/html/system/storage/
   ```

4. **Enable .htaccess support:**
   ```bash
   sudo nano /etc/apache2/sites-available/000-default.conf
   
   # Add inside <VirtualHost>:
   <Directory /var/www/html>
       AllowOverride All
       Require all granted
   </Directory>
   
   sudo systemctl restart apache2
   ```

5. **Check config.php URLs:**
   ```bash
   sudo grep "HTTP_SERVER" /var/www/html/config.php
   # Should be: define('HTTP_SERVER', 'http://172.20.242.30/');
   ```

6. **Test from command line:**
   ```bash
   curl -I http://localhost/
   curl http://localhost/ | head -20
   ```

7. **Check logs:**
   ```bash
   sudo tail -50 /var/log/apache2/error.log
   sudo tail -50 /var/log/apache2/access.log
   ```

---

**Last Updated:** January 21, 2026  
**Discovered By:** Early access session reconnaissance  
**Priority:** HIGH - Scored service (HTTP/HTTPS) with vulnerable admin panel
