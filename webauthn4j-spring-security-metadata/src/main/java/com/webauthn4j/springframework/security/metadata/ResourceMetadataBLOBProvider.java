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
import com.webauthn4j.metadata.CachingMetadataBLOBProvider;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBFactory;
import com.webauthn4j.util.AssertUtil;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;

import java.io.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ResourceMetadataBLOBProvider extends CachingMetadataBLOBProvider implements InitializingBean {

    // ~ Instance fields
    // ================================================================================================

    private Resource resource;
    private final MetadataBLOBFactory metadataBLOBFactory;

    // ~ Constructors
    // ===================================================================================================

    public ResourceMetadataBLOBProvider(ObjectConverter objectConverter){
        metadataBLOBFactory = new MetadataBLOBFactory(objectConverter);
    }

    // ~ Methods
    // ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        checkConfig();
    }

    private void checkConfig() {
        AssertUtil.notNull(resource, "resource must not be null");
    }

    public Resource getResource() {
        return resource;
    }

    public void setResource(Resource resource) {
        this.resource = resource;
    }

    @Override
    protected MetadataBLOB doProvide() {
        try (InputStream inputStream = resource.getInputStream()) {
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
            Stream<String> lines = new BufferedReader(inputStreamReader).lines();
            String string = lines.collect(Collectors.joining());
            return metadataBLOBFactory.parse(string);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load a MetadataBLOB file", e);
        }
    }
}
