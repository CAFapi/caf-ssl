!not-ready-for-release!

#### Version Number
${version-number}

#### New Features
- US969005: Add support for getting secrets from configurable sources.  
  - The `SSL_KEYSTORE_PASSWORD` can now be retrieved from the following sources:
    - Environment variables (direct value) - enabled via `CAF_GET_SECRETS_FROM_ENV` (defaults to `true`)
    - File content (path specified by environment variable with `_FILE` suffix) - enabled via `CAF_GET_SECRETS_FROM_FILE` (defaults to `false`)

#### Known Issues
