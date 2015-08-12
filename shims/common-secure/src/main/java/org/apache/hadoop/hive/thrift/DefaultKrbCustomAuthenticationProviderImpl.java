package org.apache.hadoop.hive.thrift;

import javax.security.sasl.AuthenticationException;

public class DefaultKrbCustomAuthenticationProviderImpl implements KrbCustomAuthenticationProvider {

  /**
   * This class will be called when you set 
   * hive.server2.authentication=KERBEROS and hive.server2.kerberos.use.SSL = true 
   * with hive.server2.kerberos.ssl.custom.authentication.class=<class name> on hive-site.xml
   **/
  @Override
  public void Authenticate(String user, String password) throws AuthenticationException {
    throw new AuthenticationException("Unsupported authentication method on Kerberos environment");
  }
}