# snowflizzle

A mapping tool from User's login_name to Snowflake roles.

exmaple mapping file:

```yaml
roles:
  example_role_ro:
    - <login_name>
```

roles.yaml

```yaml
roles:
  example_role_ro:
    - user1@example.com
    - user2@example.com
  example_role_rw:
    - user1@example.com
    - user2@example.com
```

Prepare snowflizzle service user in snowflake

<https://docs.snowflake.com/en/user-guide/key-pair-auth>
<https://docs.snowflake.com/en/user-guide/security-access-control-overview#label-access-control-overview-roles-system>

Create a service user in Snowflake using the public key generated above. Make sure to replace `<paste contents of rsa_key.pub>` with the actual contents of your `rsa_key.pub` file.
Do not include `-----BEGIN PUBLIC KEY-----` or `-----END PUBLIC KEY-----`. Paste that single-line string directly into the RSA_PUBLIC_KEY parameter, enclosed in single quotes.

```sql
CREATE USER IF NOT EXISTS SNOWFLIZZLE_SVC
    DISPLAY_NAME = 'SNOWFLIZZLE_SVC'
    COMMENT = 'Service user for automation'
    RSA_PUBLIC_KEY = '<paste contents of rsa_key.pub>'
    DEFAULT_ROLE =  'SECURITYADMIN'
    DEFAULT_WAREHOUSE = 'SNOWFLIZZLE'
    TYPE = 'SERVICE';

GRANT ROLE ACCOUNTADMIN TO USER SNOWFLIZZLE_SVC;

CREATE WAREHOUSE IF NOT EXISTS SNOWFLIZZLE
    WAREHOUSE_SIZE = 'XSMALL'
    AUTO_SUSPEND = 60
    AUTO_RESUME = TRUE
    INITIALLY_SUSPENDED = TRUE;
```

<https://pkg.go.dev/github.com/snowflakedb/gosnowflake#hdr-JWT_authentication>

## Usage

```bash
# Build the tool

git clone git@github.com:ApplauseOSS/snowflizzle.git
cd snowflizzle
make

# Export values or prepare .env file
export SNOWFLAKE_ACCOUNT=<your_snowflake_account>
export SNOWFLAKE_USER=SNOWFLIZZLE_SVC
export SNOWFLAKE_PRIVATE_KEY_PATH=./rsa_key

# Run the tool
./snowflizzle sync roles.yaml
```

Roles validation

```bash
./snowflizzle validate roles.yaml
```

Dry run

```bash
./snowflizzle sync roles.yaml --dry-run
```
