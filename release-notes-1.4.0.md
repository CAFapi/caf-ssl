!not-ready-for-release!

#### Version Number
${version-number}

#### New Features
- **US1212260**: Added `caf-ssl-spring`, a Spring Boot module that enables the `X25519MLKEM768` post-quantum hybrid
  key exchange on a service's TLS endpoint simply by adding the dependency (auto-registered via an
  `EnvironmentPostProcessor`).
- **US1212260**: Extracted the shared TLS JCE provider selection and BouncyCastle registration logic into a new
  `caf-ssl-core` module, now used by both `caf-ssl-dropwizard` and `caf-ssl-spring`.

#### Known Issues
