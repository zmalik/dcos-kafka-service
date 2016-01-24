package org.apache.mesos.kafka.web;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.MediaType;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.mesos.kafka.state.KafkaStateService;

import org.json.JSONArray;
import org.json.JSONObject;

@Path("/brokers")
@Produces("application/json")
public class BrokerController {
  private final Log log = LogFactory.getLog(BrokerController.class);
  private KafkaStateService state = KafkaStateService.getStateService();

  @GET
  public Response brokers() {
    try {
      JSONArray brokerIds = state.getBrokerIds();
      return Response.ok(brokerIds.toString(), MediaType.APPLICATION_JSON).build();
    } catch (Exception ex) {
      log.error("Failed to fetch broker ids with exception: " + ex);
      return Response.serverError().build();
    }
  }

  @GET
  @Path("/{id}")
  public Response broker(@PathParam("id") String id) {
    try {
      JSONObject broker = state.getBroker(id);
      return Response.ok(broker.toString(), MediaType.APPLICATION_JSON).build();
    } catch (Exception ex) {
      log.error("Failed to fetch broker: " + id + " with exception: " + ex);
      return Response.serverError().build();
    }
  }
}