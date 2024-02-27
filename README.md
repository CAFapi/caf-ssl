# caf-ssl

This project provides SSL utility code.

## caf-ssl-dropwizard

This module provides a dropwizard bundle to enable SSL for a dropwizard service.

To use, import the dependency into your project:

```
<dependency>
    <groupId>com.github.cafapi.ssl</groupId>
    <artifactId>caf-ssl-dropwizard</artifactId>
    <version>ENTER_VERSION_HERE</version>
</dependency>
```

Then, add the bundle to your dropwizard service, for example in the `initialize` method of your `Application` class:

```
import com.github.cafapi.ssl.dropwizard.DropWizardSslBundleProvider;
import io.dropwizard.configuration.ResourceConfigurationSourceProvider;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Bootstrap;

public final class CafAuditApplication extends Application<CafAuditConfiguration>
{
    @Override
    public void initialize(final Bootstrap<CafAuditConfiguration> bootstrap)
    {
        ...
        bootstrap.addBundle(DropWizardSslBundleProvider.getInstance());
        ...
    }
    
    ...
}
```

Finally, add the following environment variables:

- `SSL_KEYSTORE_PATH `: Required. This property configures the path to the keystore file.
- `SSL_KEYSTORE `: Required. This property configures the name of the keystore file.
- `SSL_KEYSTORE_PASSWORD `: Required. This property configures the password for the keystore file.
- `SSL_CERT_ALIAS `: Required. This property configures the alias for the certificate in the keystore file.
- `SSL_KEYSTORE_TYPE `: Optional. This property configures the type of the keystore file. Defaults to **JKS**.
- `SSL_VALIDATE_CERTS `: Optional. This property configures whether to validate certs. Defaults to **false**.
- `SSL_DISABLE_SNI_HOST_CHECK`: Optional. This property configures whether to disable the SNI host check. Defaults to **false**.
- `HTTPS_PORT`: Optional. This property configures the port for the HTTPS server. Defaults to **8443**.
