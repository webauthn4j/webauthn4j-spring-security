/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.metadata;

import com.webauthn4j.extras.fido.metadata.FIDOMDSClient;
import org.springframework.web.client.RestTemplate;

/**
 * Client for FIDO Metadata Service
 */
public class FIDOMDSTemplate implements FIDOMDSClient {

    private static final String DEFAULT_FIDO_METADATA_SERVICE_ENDPOINT = "https://mds.fidoalliance.org/";
    private String fidoMetadataServiceEndpoint = DEFAULT_FIDO_METADATA_SERVICE_ENDPOINT;
    private String token;
    private RestTemplate restTemplate;

    public FIDOMDSTemplate(RestTemplate restTemplate, String token) {
        this.restTemplate = restTemplate;
        this.token = token;
    }

    @Override
    public String fetchMetadataTOC() {
        String url = fidoMetadataServiceEndpoint + "?token=" + token;
        return restTemplate.getForObject(url, String.class);
    }

    @Override
    public String fetchMetadataStatement(String url) {
        return restTemplate.getForObject(url, String.class);
    }

    public String getFidoMetadataServiceEndpoint() {
        return fidoMetadataServiceEndpoint;
    }

    public void setFidoMetadataServiceEndpoint(String fidoMetadataServiceEndpoint) {
        this.fidoMetadataServiceEndpoint = fidoMetadataServiceEndpoint;
    }
}
