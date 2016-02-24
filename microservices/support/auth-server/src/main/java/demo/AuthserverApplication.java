package demo;


import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.web.SpringBootServletInitializer;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.io.StringReader;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

@SpringBootApplication
public class AuthserverApplication {

	private static final Logger log = LoggerFactory.getLogger(AuthserverApplication.class);

	public static RsaJsonWebKey rjwk;

	public static void main(String[] args) {
		SpringApplication.run(AuthserverApplication.class, args);
	}

	@Bean
	CommandLineRunner init() {
			return new CommandLineRunner() {

				@Value("${config.oauth2.privateKey}")
				private String privateKeyString;

				@Value("${config.oauth2.publicKey}")
				private String publicKeyString;


				@Override
				public void run(String... args) throws Exception {

						if (Security.getProvider("BC") == null) {
								Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
						}
						PEMParser pemReader = new PEMParser(new StringReader(privateKeyString));

						JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

						KeyPair keyPair = converter.getKeyPair((PEMKeyPair) pemReader.readObject());

						RsaJsonWebKey rsaJsonWebKey = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(keyPair.getPublic());
						rsaJsonWebKey.setPrivateKey(keyPair.getPrivate());
						rjwk = rsaJsonWebKey;

						// Give the JWK a Key ID (kid), which is just the polite thing to do
						rsaJsonWebKey.setKeyId("k1");

						// Create the Claims, which will be the content of the JWT
						JwtClaims claims = new JwtClaims();
						claims.setIssuer("ee-security");  // who creates the token and signs it
						claims.setAudience("ee-aaps"); // to whom the token is intended to be sent
						claims.setExpirationTimeMinutesInTheFuture(100); // time when the token will expire (10 minutes from now)
						claims.setGeneratedJwtId(); // a unique identifier for the token
						claims.setIssuedAtToNow();  // when the token was issued/created (now)
						claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
						claims.setSubject("subject"); // the subject/principal is whom the token is about
						claims.setClaim("email","mail@example.com"); // additional claims/attributes about the subject can be added
						List<String> groups = Arrays.asList("group-one", "other-group", "group-three");
						claims.setStringListClaim("scopes", groups); // multi-valued claims work too and will end up as a JSON array

						// A JWT is a JWS and/or a JWE with JSON claims as the payload.
						// In this example it is a JWS so we create a JsonWebSignature object.
						JsonWebSignature jws = new JsonWebSignature();

						// The payload of the JWS is JSON content of the JWT Claims
						jws.setPayload(claims.toJson());

						// The JWT is signed using the private key
						jws.setKey(rsaJsonWebKey.getPrivateKey());

						// Set the Key ID (kid) header because it's just the polite thing to do.
						// We only have one key in this example but a using a Key ID helps
						// facilitate a smooth key rollover process
						jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());

						// Set the signature algorithm on the JWT/JWS that will integrity protect the claims
						jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

						// Sign the JWS and produce the compact serialization or the complete JWT/JWS
						// representation, which is a string consisting of three dot ('.') separated
						// base64url-encoded parts in the form Header.Payload.Signature
						// If you wanted to encrypt it, you can simply set this jwt as the payload
						// of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".
						String jwt = jws.getCompactSerialization();


						// Now you can do something with the JWT. Like send it to some other party
						// over the clouds and through the interwebs.
						System.out.println("JWT: " + jwt);

						System.out.println("publicKey: " + publicKeyString);
				}
		};
	}
}
