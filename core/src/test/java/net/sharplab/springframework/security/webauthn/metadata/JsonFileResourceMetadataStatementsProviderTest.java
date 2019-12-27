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


import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import org.junit.Test;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class JsonFileResourceMetadataStatementsProviderTest {

    private ObjectConverter objectConverter = new ObjectConverter();

    private JsonFileResourceMetadataStatementsProvider target = new JsonFileResourceMetadataStatementsProvider(objectConverter);

    @Test(expected = IllegalArgumentException.class)
    public void resources_not_configured_test() {
        target.provide();
    }

    @Test
    public void extractAAGUID_with_fido2_test() {
        AAGUID aaguid = new AAGUID(UUID.randomUUID());
        MetadataStatement metadataStatement = mock(MetadataStatement.class);
        when(metadataStatement.getProtocolFamily()).thenReturn("fido2");
        when(metadataStatement.getAaguid()).thenReturn(aaguid);
        assertThat(target.extractAAGUID(metadataStatement)).isEqualTo(aaguid);
    }

    @Test
    public void extractAAGUID_with_u2f_test() {
        MetadataStatement metadataStatement = mock(MetadataStatement.class);
        when(metadataStatement.getProtocolFamily()).thenReturn("u2f");
        assertThat(target.extractAAGUID(metadataStatement)).isEqualTo(AAGUID.ZERO);
    }

    @Test
    public void extractAAGUID_with_uaf_test() {
        MetadataStatement metadataStatement = mock(MetadataStatement.class);
        when(metadataStatement.getProtocolFamily()).thenReturn("uaf");
        assertThat(target.extractAAGUID(metadataStatement)).isEqualTo(AAGUID.NULL);
    }


    @Test(expected = UncheckedIOException.class)
    public void readJsonFile_test() throws IOException {
        Resource resource = mock(Resource.class);
        when(resource.getInputStream()).thenThrow(IOException.class);
        target.readJsonFile(resource);
    }

}