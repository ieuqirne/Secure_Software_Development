package uk.ac.napier.soc.ssd.coursework.appsensor;

import com.google.gson.Gson;
import org.owasp.appsensor.core.*;
import org.owasp.appsensor.core.geolocation.GeoLocation;
import org.springframework.http.ResponseEntity;

import java.security.GeneralSecurityException;

public class EventEmitter {
    private User bob = new User("enri", new IPAddress("10.10.10.1", new GeoLocation(37.596758, -121.647992)));
    private DetectionSystem detectionSystem = new DetectionSystem("myclientapp");
    private Gson gson = new Gson();

    private DetectionPoint detectionPoint;

    public EventEmitter(DetectionPoint detectionPoint) {
        this.detectionPoint = detectionPoint;
    }

    public ResponseEntity<String> send() {
        System.err.format("Sending event type '%s' from user '%s' and system '%s'%s", detectionPoint.getLabel(), bob.getUsername(), detectionSystem.getDetectionSystemId(), System.getProperty("line.separator"));
        Event event = new Event(bob, detectionPoint, detectionSystem);
        System.err.println("sending || " + gson.toJson(event) + " ||");

        ResponseEntity<String> responseEntity = null;

        try {
            responseEntity = HttpClient.send(bob, detectionPoint, detectionSystem);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return responseEntity;
    }
}
