package uk.ac.napier.soc.ssd.coursework.appsensor;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.owasp.appsensor.core.DetectionPoint;
import org.owasp.appsensor.core.DetectionSystem;
import org.owasp.appsensor.core.Event;
import org.owasp.appsensor.core.User;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

public class HttpClient {
    final static String appSensorUrl = "http://localhost:8085/api/v1.0/events";

    public static ResponseEntity<String> send(User user, DetectionPoint detectionPoint, DetectionSystem detectionSystem) throws GeneralSecurityException {
        HttpComponentsClientHttpRequestFactory requestFactory  = new HttpComponentsClientHttpRequestFactory();
        final CloseableHttpClient httpClient = createAcceptSelfSignedCertificateAndAnyHostClient();

        requestFactory.setHttpClient(httpClient);
        Event event = new Event(user, detectionPoint, detectionSystem);
        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Appsensor-Client-Application-Name2", "myclientapp");
        HttpEntity<Event> request = new HttpEntity<>(event, headers);
        ResponseEntity<String> response = new RestTemplate(requestFactory).postForEntity(appSensorUrl, request, String.class);
        return response;
    }

    private static CloseableHttpClient createAcceptSelfSignedCertificateAndAnyHostClient() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
        SSLContext sslContext = SSLContextBuilder
                .create()
                .loadTrustMaterial(new TrustSelfSignedStrategy())
                .build();

        HostnameVerifier allowAllHosts = new NoopHostnameVerifier();

        // create an SSL Socket Factory to use the SSLContext with the trust self signed certificate strategy
        // and allow all hosts verifier.
        SSLConnectionSocketFactory connectionFactory = new SSLConnectionSocketFactory(sslContext, allowAllHosts);

        // finally create the HttpClient using HttpClient factory methods and assign the ssl socket factory
        return HttpClients
                .custom()
                .setSSLSocketFactory(connectionFactory)
                .build();
    }

}
