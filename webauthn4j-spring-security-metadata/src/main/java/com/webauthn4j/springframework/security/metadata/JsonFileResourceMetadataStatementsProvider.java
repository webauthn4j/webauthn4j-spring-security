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

package com.webauthn4j.springframework.security.metadata;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.MetadataStatementsProvider;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.util.AssertUtil;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A {@link MetadataStatementsProvider} implementation that loads {@link MetadataStatement}(s) from JSON files in Spring {@link Resource}s
 */
public class JsonFileResourceMetadataStatementsProvider implements MetadataStatementsProvider, InitializingBean {

    // ~ Instance fields
    // ================================================================================================

    private final JsonConverter jsonConverter;
    private List<Resource> resources;
    private Map<AAGUID, Set<MetadataStatement>> cachedMetadataItems;

    // ~ Constructors
    // ===================================================================================================

    public JsonFileResourceMetadataStatementsProvider(ObjectConverter objectConverter) {
        Assert.notNull(objectConverter, "objectConverter must not be null");
        this.jsonConverter = objectConverter.getJsonConverter();
    }

    // ~ Methods
    // ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        checkConfig();
    }

    private void checkConfig() {
        AssertUtil.notNull(resources, "resources must not be null");
    }

    @Override
    public Map<AAGUID, Set<MetadataStatement>> provide() {
        checkConfig();
        if (cachedMetadataItems == null) {
            cachedMetadataItems =
                    resources.stream()
                            .map(this::readJsonFile)
                            .distinct()
                            .collect(Collectors.groupingBy(this::extractAAGUID))
                            .entrySet().stream()
                            .collect(Collectors.toMap(Map.Entry::getKey, entry -> new HashSet<>(entry.getValue())));
        }
        return cachedMetadataItems;
    }

    public List<Resource> getResources() {
        return resources;
    }

    public void setResources(List<Resource> resources) {
        this.resources = resources;
    }

    AAGUID extractAAGUID(MetadataStatement metadataStatement) {
        switch (metadataStatement.getProtocolFamily()) {
            case "fido2":
                return metadataStatement.getAaguid();
            case "u2f":
                return AAGUID.ZERO;
            case "uaf":
            default:
                return AAGUID.NULL;
        }
    }

    MetadataStatement readJsonFile(Resource resource) {
        try (InputStream inputStream = resource.getInputStream()) {
            return jsonConverter.readValue(inputStream, MetadataStatement.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load a metadata statement json file", e);
        }
    }
}
