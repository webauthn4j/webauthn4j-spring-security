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

package com.webauthn4j.springframework.security.webauthn.metadata;

import com.webauthn4j.metadata.HttpClient;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

/**
 * An {@link HttpClient} implementation with Spring {@link RestTemplate}
 */
public class RestTemplateAdaptorHttpClient implements HttpClient {

    private RestTemplate restTemplate;

    public RestTemplateAdaptorHttpClient(RestTemplate restTemplate) {
        Assert.notNull(restTemplate, "restTemplate must not be null");
        this.restTemplate = restTemplate;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String fetch(String url) {
        return restTemplate.getForObject(url, String.class);
    }
}
