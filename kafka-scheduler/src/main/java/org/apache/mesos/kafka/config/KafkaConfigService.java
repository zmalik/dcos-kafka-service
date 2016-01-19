package org.apache.mesos.kafka.config;

import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.mesos.config.ConfigurationService;
import org.apache.mesos.config.FrameworkConfigurationService;

public class KafkaConfigService extends FrameworkConfigurationService {
  private final Log log = LogFactory.getLog(KafkaConfigService.class);

  private static ConfigurationService configService = new KafkaConfigService();

  public static ConfigurationService getConfigService() {
    return configService;
  }

  private KafkaConfigService() {
    Map<String, String> env = System.getenv();
    for (Entry<String, String> entry : env.entrySet()) {
      String key = entry.getKey();
      String value = entry.getValue();
      setValue(key, value);
    }
  }
}