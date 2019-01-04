/*
 *    Copyright 2002-2019 the original author or authors.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.sample.util.modelmapper;

import org.modelmapper.Converter;
import org.modelmapper.MappingException;
import org.modelmapper.ModelMapper;
import org.modelmapper.internal.util.TypeResolver;
import org.modelmapper.internal.util.Types;
import org.modelmapper.spi.Mapping;
import org.modelmapper.spi.MappingContext;
import org.modelmapper.spi.PropertyInfo;
import org.modelmapper.spi.PropertyMapping;
import org.springframework.data.domain.PageImpl;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

/**
 * Converter which converts from {@code PageImpl<S>} to {@code PageImpl<D>}
 *
 * @param <S> source type
 * @param <D> destination type
 */
public class PageImplConverter<S, D> implements Converter<PageImpl<S>, PageImpl<D>> {

    private ModelMapper modelMapper;

    public PageImplConverter(ModelMapper modelMapper) {
        this.modelMapper = modelMapper;
    }

    /**
     * Converts the {@link MappingContext#getSource()} to an instance of
     * {@link MappingContext#getDestinationType()}.
     *
     * @param context of current mapping process
     * @throws MappingException if an error occurs while converting
     */
    @Override
    public PageImpl<D> convert(MappingContext<PageImpl<S>, PageImpl<D>> context) {
        PageImpl<S> source = context.getSource();
        if (source == null) {
            return null;
        }
        Type elementType = getElementType(context);
        return (PageImpl<D>) source.map(item -> modelMapper.map(item, elementType));
    }

    private Class<?> getElementType(MappingContext<PageImpl<S>, PageImpl<D>> context) {
        Mapping mapping = context.getMapping();
        if (mapping instanceof PropertyMapping) {
            PropertyInfo destInfo = mapping.getLastDestinationProperty();
            Class<?> elementType = TypeResolver.resolveArgument(destInfo.getGenericType(), destInfo.getInitialType());
            return elementType == TypeResolver.Unknown.class ? Object.class : elementType;
        } else {
            return Types.rawTypeFor(((ParameterizedType) context.getGenericDestinationType()).getActualTypeArguments()[0]);
        }
    }


}
