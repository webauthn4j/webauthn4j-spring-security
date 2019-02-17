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

import com.webauthn4j.converter.util.JsonConverter;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.ResourcePatternUtils;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
public class JsonFileResourceMetadataItemListProviderSpringTest {


    @Autowired
    private JsonFileResourceMetadataItemListProvider target;

    @Configuration
    public static class Config{

        private JsonConverter jsonConverter = new JsonConverter();

        @Bean
        public JsonFileResourceMetadataItemListProvider jsonFileResourceMetadataItemListProvider(ResourceLoader resourceLoader) throws IOException {
            JsonFileResourceMetadataItemListProvider provider = new JsonFileResourceMetadataItemListProvider(jsonConverter);
            Resource[] resources = ResourcePatternUtils.getResourcePatternResolver(resourceLoader).getResources("classpath:metadataStatements/fido-conformance-tools/*.json");
            provider.setResources(Arrays.asList(resources));
            return provider;
        }
    }

    @Test
    public void provide_test(){
        assertThat(target.provide()).hasSize(19);
    }

    @Test
    public void getter_test(){
        assertThat(target.getResources()).hasSize(19);
    }

}