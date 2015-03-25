/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hive.service.cli.thrift;

import java.net.InetSocketAddress;

import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.conf.HiveConf.ConfVars;
import org.apache.hive.service.auth.HiveAuthFactory;
import org.apache.hive.service.cli.CLIService;
import org.apache.thrift.TProcessorFactory;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.server.TThreadPoolServer;
import org.apache.thrift.server.TServer;
import org.apache.thrift.transport.TServerSocket;
import org.apache.thrift.transport.TTransportFactory;


public class ThriftBinaryCLIService extends ThriftCLIService {

  TServer plainSSLserver;

  public ThriftBinaryCLIService(CLIService cliService) {
    super(cliService, "ThriftBinaryCLIService");
  }

  @Override
  public synchronized void stop() {
    if (plainSSLserver != null) {
      plainSSLserver.stop();
      LOG.info("Thrift SASL(PLAIN) over SSL server has stopped");
    }
    super.stop();
  }

  @Override
  public void run() {
    try {
      hiveAuthFactory = new HiveAuthFactory();
      TTransportFactory  transportFactory = hiveAuthFactory.getAuthTransFactory();
      TProcessorFactory processorFactory = hiveAuthFactory.getAuthProcFactory(this);

      String portString = System.getenv("HIVE_SERVER2_THRIFT_PORT");
      if (portString != null) {
        portNum = Integer.valueOf(portString);
      } else {
        portNum = hiveConf.getIntVar(ConfVars.HIVE_SERVER2_THRIFT_PORT);
      }

      String hiveHost = System.getenv("HIVE_SERVER2_THRIFT_BIND_HOST");
      if (hiveHost == null) {
        hiveHost = hiveConf.getVar(ConfVars.HIVE_SERVER2_THRIFT_BIND_HOST);
      }

      if (hiveHost != null && !hiveHost.isEmpty()) {
        serverAddress = new InetSocketAddress(hiveHost, portNum);
      } else {
        serverAddress = new  InetSocketAddress(portNum);
      }

      minWorkerThreads = hiveConf.getIntVar(ConfVars.HIVE_SERVER2_THRIFT_MIN_WORKER_THREADS);
      maxWorkerThreads = hiveConf.getIntVar(ConfVars.HIVE_SERVER2_THRIFT_MAX_WORKER_THREADS);

      TServerSocket serverSocket = null;
      if (!hiveConf.getBoolVar(ConfVars.HIVE_SERVER2_USE_SSL)) {
        serverSocket = HiveAuthFactory.getServerSocket(hiveHost, portNum);
      } else {
        String keyStorePath = hiveConf.getVar(ConfVars.HIVE_SERVER2_SSL_KEYSTORE_PATH).trim();
        if (keyStorePath.isEmpty()) {
          throw new IllegalArgumentException(ConfVars.HIVE_SERVER2_SSL_KEYSTORE_PATH.varname +
              " Not configured for SSL connection");
        }
        serverSocket = HiveAuthFactory.getServerSSLSocket(hiveHost, portNum,
            keyStorePath, hiveConf.getVar(ConfVars.HIVE_SERVER2_SSL_KEYSTORE_PASSWORD));
      }
      TThreadPoolServer.Args sargs = new TThreadPoolServer.Args(serverSocket)
      .processorFactory(processorFactory)
      .transportFactory(transportFactory)
      .protocolFactory(new TBinaryProtocol.Factory())
      .minWorkerThreads(minWorkerThreads)
      .maxWorkerThreads(maxWorkerThreads);

      server = new TThreadPoolServer(sargs);

      LOG.info("ThriftBinaryCLIService listening on " + serverAddress);

      // ALTISCALE - new thread : SASL(PALIN) over SSL thread for custom class
      String transportMode = hiveConf.getVar(ConfVars.HIVE_SERVER2_TRANSPORT_MODE);
      String authTypeStr = hiveConf.getVar(ConfVars.HIVE_SERVER2_AUTHENTICATION);
      final ThriftCLIService svc = this;
      final String hiveServerHost = hiveHost;

      if (!transportMode.equalsIgnoreCase("http")
          && authTypeStr.equalsIgnoreCase(HiveAuthFactory.AuthTypes.KERBEROS.toString())
          && hiveConf.getBoolVar(ConfVars.HIVE_SERVER2_THRIFT_KERBEROS_USE_SSL)) {
        Thread t = new Thread() {
          @Override
          public void run() {
            try {
              startPlainSSLOnKerberos(hiveConf,
                svc, hiveServerHost, plainSSLserver);
            } catch (Throwable t) {
              LOG.error("Failure ThriftBinaryCLIService SASL(PLAIN) over SSL listening on kerberos " + serverAddress + ": " + t.getMessage());
            }
          }
        };
        t.start();
      }

      server.serve();

    } catch (Throwable t) {
      LOG.error("Error: ", t);
    }

  }

  // ALTISCALE - SASL(PALIN) over SSL thread for custom class
  private static void startPlainSSLOnKerberos(
    HiveConf hiveConf,
    final ThriftCLIService service,
    final String hiveHost,
    TServer plainSSLserver) throws Exception {

    try {
      int sslPortNum;
      String portString = System.getenv("HIVE_SERVER2_THRIFT_KERBEROS_SSL_PORT");
      if (portString != null) {
        sslPortNum = Integer.valueOf(portString);
      } else {
        sslPortNum = hiveConf.getIntVar(ConfVars.HIVE_SERVER2_THRIFT_KERBEROS_SSL_PORT);
      }

      InetSocketAddress serverAddress;
      if (hiveHost != null && !hiveHost.isEmpty()) {
        serverAddress = new InetSocketAddress(hiveHost, sslPortNum);
      } else {
        serverAddress = new InetSocketAddress(sslPortNum);
      }

      int minWorkerThreads = hiveConf.getIntVar(ConfVars.HIVE_SERVER2_THRIFT_KERBEROS_SSL_MIN_WORKER_THREADS);
      int maxWorkerThreads = hiveConf.getIntVar(ConfVars.HIVE_SERVER2_THRIFT_KERBEROS_SSL_MAX_WORKER_THREADS);

      HiveAuthFactory hiveAuthFactory = new HiveAuthFactory();
      TTransportFactory transportFactory = hiveAuthFactory.getAuthPlainTransFactory();
      TProcessorFactory processorFactory = hiveAuthFactory.getAuthProcFactory(service);

      TServerSocket plainSSLSocket = null;
      String keyStorePath = hiveConf.getVar(ConfVars.HIVE_SERVER2_THRIFT_KERBEROS_SSL_KEYSTORE_PATH).trim();
      if (keyStorePath.isEmpty()) {
        throw new IllegalArgumentException(ConfVars.HIVE_SERVER2_THRIFT_KERBEROS_SSL_KEYSTORE_PATH.varname +
        " Not configured for SSL connection");
      }
      plainSSLSocket = HiveAuthFactory.getServerSSLSocket(hiveHost, sslPortNum,
        keyStorePath, hiveConf.getVar(ConfVars.HIVE_SERVER2_THRIFT_KERBEROS_SSL_KEYSTORE_PASSWORD));

      TThreadPoolServer.Args sargs = new TThreadPoolServer.Args(plainSSLSocket)
      .processorFactory(processorFactory)
      .transportFactory(transportFactory)
      .protocolFactory(new TBinaryProtocol.Factory())
      .minWorkerThreads(minWorkerThreads)
      .maxWorkerThreads(maxWorkerThreads);

      plainSSLserver = new TThreadPoolServer(sargs);

      LOG.info("ThriftBinaryCLIService SASL(PLAIN) over SSL on Kerberos listening on " + serverAddress);

      plainSSLserver.serve();
    } catch (Throwable t) {
      LOG.error("Error: ", t);
    }
  }
}
