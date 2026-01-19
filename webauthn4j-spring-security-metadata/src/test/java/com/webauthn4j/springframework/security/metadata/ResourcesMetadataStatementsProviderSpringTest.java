package com.webauthn4j.springframework.security.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.ResourcePatternUtils;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.UncheckedIOException;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


@SuppressWarnings("deprecation")
@RunWith(SpringRunner.class)
public class ResourcesMetadataStatementsProviderSpringTest {

    @Autowired
    private ResourcesMetadataStatementsProvider target;

    @Autowired
    private ResourceLoader resourceLoader;

    @Test
    public void provide_test(){
        List<MetadataStatement> metadataStatements = target.provide();
        assertThat(metadataStatements).hasSize(1);
    }

    @Test
    public void getResources_test(){
        List<Resource> resources = target.getResources();
        assertThat(resources).hasSize(1);
    }

    @Test
    public void invalid_resource_path_test(){
        Resource resource = ResourcePatternUtils.getResourcePatternResolver(resourceLoader).getResource("classpath:invalid.path");
        ResourcesMetadataStatementsProvider provider = new ResourcesMetadataStatementsProvider(new ObjectConverter());
        provider.setResources(Collections.singletonList(resource));
        assertThatThrownBy(provider::provide).isInstanceOf(UncheckedIOException.class);
    }

    @Test
    public void broken_resource_test(){
        Resource resource = ResourcePatternUtils.getResourcePatternResolver(resourceLoader).getResource("classpath:metadata/BrokenMetadataItem.json");
        ResourcesMetadataStatementsProvider provider = new ResourcesMetadataStatementsProvider(new ObjectConverter());
        provider.setResources(Collections.singletonList(resource));
        assertThatThrownBy(provider::provide).isInstanceOf(DataConversionException.class);
    }

    @Configuration
    public static class Config {

        private final ObjectConverter objectConverter;

        public Config() {
            ObjectMapper jsonMapper = new ObjectMapper();
            jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
            ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
            objectConverter = new ObjectConverter(jsonMapper, cborMapper);
        }

        @Bean
        public ResourcesMetadataStatementsProvider resourcesMetadataStatementsProvider(ResourceLoader resourceLoader) {
            ResourcesMetadataStatementsProvider provider = new ResourcesMetadataStatementsProvider(objectConverter);
            Resource resource = ResourcePatternUtils.getResourcePatternResolver(resourceLoader).getResource("classpath:metadata/JsonMetadataItem_fido2.json");
            provider.setResources(Collections.singletonList(resource));
            return provider;
        }
    }


}