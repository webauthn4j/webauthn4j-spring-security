/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.authenticator;

import com.webauthn4j.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.util.Base64UrlUtil;
import net.sharplab.springframework.security.webauthn.SpringSecurityWebAuthnMessageSource;
import net.sharplab.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.util.Assert;

import java.util.List;

/**
 * A {@link WebAuthnAuthenticatorService} implementation that retrieves the user details
 * from a database using JDBC queries.
 */
public class JdbcWebAuthnAuthenticatorServiceImpl extends JdbcDaoSupport
        implements WebAuthnAuthenticatorService, MessageSourceAware {

    // ~ Static fields/initializers
    // =====================================================================================

    public static final String DEF_AUTHENTICATORS_BY_CREDENTIAL_ID_QUERY =
            "select name, counter, aa_guid, credential_id, credential_public_key, attestation_statement " +
            "from authenticators " + "where credential_id = ?";

    // ~ Instance fields
    // ================================================================================================

    protected MessageSourceAccessor messages = SpringSecurityWebAuthnMessageSource.getAccessor();

    private String authenticatorsByCredentialIdQuery;


    // ~ Constructors
    // ===================================================================================================

    public JdbcWebAuthnAuthenticatorServiceImpl() {
        this.authenticatorsByCredentialIdQuery = DEF_AUTHENTICATORS_BY_CREDENTIAL_ID_QUERY;
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * Locates the authenticator based on the credentialId.
     *
     * @param credentialId the credentialId identifying the authenticator whose data is required.
     * @return a fully populated authenticator record (never <code>null</code>)
     * @throws CredentialIdNotFoundException if the authenticator could not be found
     */
    @Override
    public WebAuthnAuthenticator loadWebAuthnAuthenticatorByCredentialId(byte[] credentialId) {
        List<WebAuthnAuthenticator> authenticators = loadWebAuthnAuthenticatorsByCredentialId(credentialId);

        if (authenticators.isEmpty()) {
            String credentialIdStr = Base64UrlUtil.encodeToString(credentialId);
            this.logger.debug("Query returned no results for authenticator '" + credentialIdStr + "'");

            throw new CredentialIdNotFoundException(
                    this.messages.getMessage("JdbcWebAuthnAuthenticatorServiceImpl.notFound",
                            new Object[]{credentialIdStr}, "Authenticator {0} not found"));
        }

        return authenticators.get(0);
    }

    List<WebAuthnAuthenticator> loadWebAuthnAuthenticatorsByCredentialId(byte[] credentialId) {
        return getJdbcTemplate().query(this.authenticatorsByCredentialIdQuery,
                new byte[][] { credentialId }, (rs, rowNum) -> {
                    String name = rs.getString(1);
                    int counter = rs.getInt(2);
                    byte[] aaGuid = rs.getBytes(3);
                    String credentialPublicKey = rs.getString(5);
                    String attestationStatement = rs.getString(6);
                    AttestedCredentialData attestedCredentialData = new AttestedCredentialData(aaGuid, credentialId, ObjectMapperUtil.readJSONValue(credentialPublicKey, CredentialPublicKey.class));
                    WebAuthnAuthenticator webAuthnAuthenticator = new WebAuthnAuthenticator();
                    webAuthnAuthenticator.setName(name);
                    webAuthnAuthenticator.setCounter(counter);
                    webAuthnAuthenticator.setAttestedCredentialData(attestedCredentialData);
                    webAuthnAuthenticator.setAttestationStatement(ObjectMapperUtil.readJSONValue(attestationStatement, AttestationStatement.class));
                    return webAuthnAuthenticator;
                });
    }

    /**
     * @return the messages
     */
    protected MessageSourceAccessor getMessages() {
        return this.messages;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setMessageSource(MessageSource messageSource) {
        Assert.notNull(messageSource, "messageSource cannot be null");
        this.messages = new MessageSourceAccessor(messageSource);
    }
}
