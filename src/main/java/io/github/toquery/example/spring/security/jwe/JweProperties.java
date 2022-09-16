package io.github.toquery.example.spring.security.jwe;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;

/**
 * @author deng.shichao
 */
@Data
@ConfigurationProperties(
        prefix = "app.jwe"
)
public class JweProperties {
    private RSAPrivateKey jweKey;
}
