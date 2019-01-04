package net.sharplab.springframework.security.webauthn.sample.domain.config;

import net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity;
import net.sharplab.springframework.security.webauthn.sample.util.modelmapper.*;
import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;

/**
 * ModelMapper Configuration
 */
@Configuration
public class ModelMapperConfig {


    @Bean
    public ModelMapper modelMapper() {
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.addConverter(new PageImplConverter<net.sharplab.springframework.security.webauthn.sample.domain.entity.UserEntity, UserEntity>(modelMapper));
        modelMapper.addConverter(new StringToChallengeConverter());

        modelMapper.createTypeMap(Page.class, PageImpl.class).setProvider(new PageImplProvider());
        modelMapper.getTypeMap(PageImpl.class, PageImpl.class).setProvider(new PageImplProvider());

        modelMapper.getConfiguration()
                .setFieldMatchingEnabled(true)
                .setFieldAccessLevel(org.modelmapper.config.Configuration.AccessLevel.PRIVATE);

        return modelMapper;
    }


    /**
     * creates ModelMapper instance
     *
     * @return ModelMapper
     */
    public static ModelMapper createModelMapper() {
        return new ModelMapperConfig().modelMapper();
    }

}
