# Snowflizzle

Snowflizzle is a tool for declaratively managing Snowflake roles, users, and their permissions using a YAML configuration file. It enables mapping users (by login name or email) to Snowflake roles, and automates the granting and revoking of database, schema, table, and workspace privileges, including support for wildcards and partial name matching. The tool is designed for automation and integrates with Snowflake using a service user and key-pair authentication.

## Key Features

- Declarative YAML configuration for roles, members, and permissions
- Grant and revoke privileges on databases, schemas, tables, views, and workspaces
- Supports wildcard and partial matching for schema and table names
- Dry-run mode for previewing changes without applying them
- Validation of configuration files before applying changes
- Automated warehouse creation and role assignment
- Designed for integration with CI/CD and automation workflows

```yaml
# snowflizzle roles mapping example roles.yaml
---
roles:
  - name: team_role
    members:
      - email: exemployee1@example.com
      - email: exemployee2@example.com
        remove: true
      - username: svc_account  # login_name without '@' (alternative to email)
    permissions:
      # Option for names
      # - database_name
      databases:
        - name: test_a_db
          grants:
            - USAGE
        - name: test_b_db
          remove: true
      schemas:
        # Options for names
        # - database_name.schema_name
        # - database_name.*
        # - database_name.*schema_partial
        # - database_name.schema_partial*
        - name: test_c_db.credentials
          grants:
            - USAGE
        - name: test_b_db.assets
      tables:
        # Options for names
        # - database_name.*.*
        # - database_name.schema_name.*
        # - database_name.schema_partial_*.*
        # - database_name.*_schema_partial.*
        # - database_name.schema_name.table_name
        - name: test_c_db.credentials
          grants:
            - SELECT
        - name: test_b_db.*.*
      workspaces:
        # Name must be a 3-part identifier: database_name.schema_name.workspace_name
        # Quote the value if the workspace name contains spaces.
        # Supported grants: USAGE, READ, WRITE
        - name: "test_a_db.my_schema.My Workspace"
          grants:
            - USAGE
            - READ
            - WRITE
```

### Role members

Members are matched against the Snowflake `LOGIN_NAME` column via one of two mutually-exclusive fields — `email` or `username`. Exactly one must be provided per member. The tool resolves the matched user's `NAME` and uses it in the `GRANT ROLE ... TO USER` statement.

| Field | Description |
| ----- | ----------- |
| `email` | A `LOGIN_NAME` containing `@` (e.g. `user@example.com`). Matched case-insensitively. |
| `username` | A `LOGIN_NAME` without `@` (e.g. a service account like `svc_account`). Matched case-insensitively. |
| `remove` | Optional. If `true`, revokes the role from this user. Defaults to `false` (grant the role). |

Example mixing email and username:

```yaml
members:
  - email: user@example.com
  - username: svc_account
  - email: departed_user@example.com
    remove: true
```

For more examples, see [`example-username-members.yaml`](example-username-members.yaml).

### Workspace grants

Snowflake [workspaces](https://docs.snowflake.com/en/user-guide/ui-snowsight-workspaces) are managed under the `workspaces` key in `permissions`. Each entry requires a 3-part name (`DATABASE.SCHEMA.WORKSPACE_NAME`) and one or more of the following privileges:

| Privilege | Description                                  |
| --------- | -------------------------------------------- |
| `USAGE`   | Allows the role to see the workspace         |
| `READ`    | Allows the role to read workspace contents   |
| `WRITE`   | Allows the role to modify workspace contents |

If a workspace name contains spaces, wrap the entire `name` value in single quotes:

```yaml
workspaces:
  - name: "MY_DATABASE.MY_SCHEMA.SALESOPS WORKSPACE"
    grants:
      - USAGE
      - READ
      - WRITE
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
    DEFAULT_ROLE =  'ACCOUNTADMIN'
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
