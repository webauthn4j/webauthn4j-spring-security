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

import com.webauthn4j.extras.fido.metadata.statement.MetadataStatement;
import com.webauthn4j.extras.fido.metadata.statement.MetadataStatementProvider;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.authenticator.AAGUID;
import com.webauthn4j.util.UUIDUtil;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

public class JsonFileResourceMetadataStatementProvider implements MetadataStatementProvider {

    private Registry registry;
    private List<Resource> resources = Collections.emptyList();
    private Map<AAGUID, List<MetadataStatement>> cachedMetadataStatements;

    public JsonFileResourceMetadataStatementProvider(Registry registry) {
        this.registry = registry;
    }

    @Override
    public Map<AAGUID, List<MetadataStatement>> provide() {
        if(cachedMetadataStatements == null){
            cachedMetadataStatements =
                    resources.stream()
                            .map(this::readJsonFile)
                            .collect(Collectors.groupingBy(this::extractAAGUID));
        }
        return cachedMetadataStatements;
    }

    public List<Resource> getResources() {
        return resources;
    }

    public void setResources(List<Resource> resources) {
        this.resources = resources;
    }

    private AAGUID extractAAGUID(MetadataStatement metadataStatement){
        switch (metadataStatement.getProtocolFamily()){
            case "fido2":
                return new AAGUID(metadataStatement.getAaguid());
            case "u2f":
                return AAGUID.ZERO;
            case "uaf":
            default:
                return AAGUID.NULL;
        }
    }

    MetadataStatement readJsonFile(Resource resource) {
        try (InputStream inputStream = resource.getInputStream()) {
            return registry.getJsonMapper().readValue(inputStream, MetadataStatement.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load a metadata statement json file", e);
        }
    }
}
