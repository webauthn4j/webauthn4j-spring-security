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

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.MetadataStatementsProvider;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.util.AssertUtil;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;
import org.jspecify.annotations.NonNull;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class ResourcesMetadataStatementsProvider implements MetadataStatementsProvider, InitializingBean {

    // ~ Instance fields
    // ================================================================================================

    private List<Resource> resources;
    private final ObjectConverter objectConverter;
    private List<MetadataStatement> metadataStatements;

    // ~ Constructors
    // ===================================================================================================

    public ResourcesMetadataStatementsProvider(ObjectConverter objectConverter){
        this.objectConverter = objectConverter;
    }

    // ~ Methods
    // ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        checkConfig();
        load();
    }

    private void checkConfig() {
        AssertUtil.notNull(resources, "resources must not be null");
    }

    public List<Resource> getResources() {
        return resources;
    }

    public void setResources(List<Resource> resources) {
        this.resources = resources;
    }

    private void load(){
        metadataStatements = resources.stream().map(resource -> {
            try {
                return objectConverter.getJsonConverter().readValue(resource.getInputStream(), MetadataStatement.class);
            }
            catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @Override
    public @NonNull List<MetadataStatement> provide() {
        if(metadataStatements == null){
            load();
        }
        return metadataStatements;
    }
}
