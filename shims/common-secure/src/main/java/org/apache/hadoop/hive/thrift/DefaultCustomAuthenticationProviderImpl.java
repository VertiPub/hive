package org.apache.hadoop.hive.thrift;

import javax.security.sasl.AuthenticationException;

public class DefaultCustomAuthenticationProviderImpl implements CustomAuthenticationProvider {

 /**
  * This class will be called when hive.server2.authentication=KERBEROS without setup custom class.
  * As a result, we will not support PLAIN mechanism on kerberized cluster
  * except when hive.server2.thrift.custom.authentication.class=<class name> on hite-site.xml
  **/
  @Override
  public void Authenticate(String user, String password) throws AuthenticationException {
    throw new AuthenticationException("Unsupported authentication method on Kerberos environment");
  }
}