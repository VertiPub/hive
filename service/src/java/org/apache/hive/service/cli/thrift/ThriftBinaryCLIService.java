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
  TServer customKrbServer;

  public ThriftBinaryCLIService(CLIService cliService) {
    super(cliService, "ThriftBinaryCLIService");
  }

  @Override
  public synchronized void stop() {
    if (customKrbServer != null) {
        customKrbServer.stop();
      LOG.info("Thrift SASL(PLAIN) over SSL with Kerberos server has stopped");
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

      // New thread : Custom authentication class with Kerberos thread
      final ThriftCLIService svc = this;
      final String hiveServerHost = hiveHost;
      String transportMode = hiveConf.getVar(ConfVars.HIVE_SERVER2_TRANSPORT_MODE);
      String authTypeStr = hiveConf.getVar(ConfVars.HIVE_SERVER2_AUTHENTICATION);

      if (!transportMode.equalsIgnoreCase("http")
          && authTypeStr.equalsIgnoreCase(HiveAuthFactory.AuthTypes.KERBEROS.toString())
          && hiveConf.getBoolVar(ConfVars.HIVE_SERVER2_KERBEROS_CUSTOM_AUTH_USED)) {
        Thread t = new Thread() {
          @Override
          public void run() {
            try {
              startCustomKerberos(hiveConf,
                svc, hiveServerHost, customKrbServer);
            } catch (Throwable t) {
              LOG.error(
                "Failure ThriftBinaryCLIService custom authentication with Kerberos listening on "
                + hiveServerHost + ": " + t.getMessage());
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

  // Custom authentication class with Kerberos thread
  private static void startCustomKerberos(
    final HiveConf hiveConf,
    final ThriftCLIService service,
    final String hiveHost,
    TServer customKrbServer) throws Exception {

    try {
      int minWorkerThreads = hiveConf.getIntVar(ConfVars.HIVE_SERVER2_KERBEROS_CUSTOM_AUTH_MIN_WORKER_THREADS);
      int maxWorkerThreads = hiveConf.getIntVar(ConfVars.HIVE_SERVER2_KERBEROS_CUSTOM_AUTH_MAX_WORKER_THREADS);

      int customPortNum;
      String portString = System.getenv("HIVE_SERVER2_KERBEROS_CUSTOM_AUTH_PORT");
      if (portString != null) {
        customPortNum = Integer.valueOf(portString);
      } else {
        customPortNum = hiveConf.getIntVar(ConfVars.HIVE_SERVER2_KERBEROS_CUSTOM_AUTH_PORT);
      }

      HiveAuthFactory hiveAuthFactory = new HiveAuthFactory();
      TTransportFactory transportFactory = hiveAuthFactory.getAuthPlainTransFactory();
      TProcessorFactory processorFactory = hiveAuthFactory.getAuthProcFactory(service);
      TServerSocket customKrbSocket = null;

      if (!hiveConf.getBoolVar(ConfVars.HIVE_SERVER2_KERBEROS_CUSTOM_AUTH_SSL_USED)) {
        customKrbSocket = HiveAuthFactory.getServerSocket(hiveHost, customPortNum);
      } else {
        // SASL over SSL with Kerberos configs
        String keyStorePath = hiveConf.getVar(ConfVars.HIVE_SERVER2_KERBEROS_CUSTOM_AUTH_SSL_KEYSTORE_PATH).trim();
        if (keyStorePath.isEmpty()) {
          throw new IllegalArgumentException(ConfVars.HIVE_SERVER2_KERBEROS_CUSTOM_AUTH_SSL_KEYSTORE_PATH.varname +
          " Not configured for SSL connection");
        }
        String keyStorePassword = hiveConf.getVar(ConfVars.HIVE_SERVER2_KERBEROS_CUSTOM_AUTH_SSL_KEYSTORE_PASSWORD);
        customKrbSocket = HiveAuthFactory.getServerSSLSocket(hiveHost, customPortNum,
          keyStorePath, keyStorePassword);
      }

      // Server args
      TThreadPoolServer.Args sargs = new TThreadPoolServer.Args(customKrbSocket)
         .processorFactory(processorFactory).transportFactory(transportFactory)
         .protocolFactory(new TBinaryProtocol.Factory())
         .minWorkerThreads(minWorkerThreads)
         .maxWorkerThreads(maxWorkerThreads);

      // TCP Server
      customKrbServer = new TThreadPoolServer(sargs);
      String msg = "Starting " + ThriftBinaryCLIService.class.getSimpleName()
         + " custom authentication with Kerberos listening on "
         + customPortNum + " with " + minWorkerThreads + "..." + maxWorkerThreads + " worker threads";
      LOG.info(msg);

      customKrbServer.serve();
    } catch (Throwable t) {
      LOG.error(
        "Error starting HiveServer2: could not start custom authentication with Kerberos", t);
    }
  }
}
