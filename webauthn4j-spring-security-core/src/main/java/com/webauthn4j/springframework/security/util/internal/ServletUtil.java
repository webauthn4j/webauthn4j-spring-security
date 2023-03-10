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

package com.webauthn4j.springframework.security.util.internal;


import com.webauthn4j.data.client.Origin;
import com.webauthn4j.springframework.security.exception.UnretrievableOriginException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * Internal utility to handle servlet
 */
public class ServletUtil {

    private ServletUtil() {
    }

    /**
     * Returns {@link Origin} corresponding {@link ServletRequest} url
     *
     * @param request http servlet request
     * @return the {@link Origin}
     */
    public static Origin getOrigin(final ServletRequest request) {
        final String url = String.format("%s://%s:%s", request.getScheme(), request.getServerName(), request.getServerPort());
        return new Origin(url);
    }

    /**
     * Returns {@link Origin} corresponding to the current {@link HttpServletRequest} url.
     * The current {@link HttpServletRequest} is retrieved via Spring utilities.
     * <p>
     * If the Origin cannot be created from the request, an {@link UnretrievableOriginException} is thrown
     *
     * @return The {@link Origin} of the current request or throw an {@link UnretrievableOriginException}
     *
     * @see ServletUtil#getCurrentHttpServletRequest
     * @see UnretrievableOriginException
     */
    public static Origin getOrigin() {
        return getCurrentHttpServletRequest()
                .map(request -> new Origin(String.format("%s://%s:%s", request.getScheme(), request.getServerName(), request.getServerPort())))
                .orElseThrow( () -> new UnretrievableOriginException("Cannot retrieve Origin from request"));
    }

    /**
     * Returns an {@link Optional} with the current {@link HttpServletRequest} if there is one, the optional empty otherwise
     *
     * @return The current {@link HttpServletRequest} encapsulating in an {@link Optional}
     */
    public static Optional<HttpServletRequest> getCurrentHttpServletRequest() {
        return Optional.ofNullable(RequestContextHolder.getRequestAttributes())
                .filter(ServletRequestAttributes.class::isInstance)
                .map(ServletRequestAttributes.class::cast)
                .map(ServletRequestAttributes::getRequest);
    }

}
