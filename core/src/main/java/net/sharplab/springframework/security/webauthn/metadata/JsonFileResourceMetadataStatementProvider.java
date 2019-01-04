package net.sharplab.springframework.security.webauthn.metadata;

import com.webauthn4j.extras.fido.metadata.statement.MetadataStatement;
import com.webauthn4j.extras.fido.metadata.statement.MetadataStatementProvider;
import com.webauthn4j.registry.Registry;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class JsonFileResourceMetadataStatementProvider implements MetadataStatementProvider {

    private Registry registry;
    private List<Resource> resources = Collections.emptyList();

    public JsonFileResourceMetadataStatementProvider(Registry registry) {
        this.registry = registry;
    }

    @Override
    public List<MetadataStatement> provide() {
        return resources.stream().map(this::readJsonFile).collect(Collectors.toList());
    }

    public List<Resource> getResources() {
        return resources;
    }

    public void setResources(List<Resource> resources) {
        this.resources = resources;
    }

    MetadataStatement readJsonFile(Resource resource) {
        try (InputStream inputStream = resource.getInputStream()) {
            return registry.getJsonMapper().readValue(inputStream, MetadataStatement.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load a metadata statement json file", e);
        }
    }
}
