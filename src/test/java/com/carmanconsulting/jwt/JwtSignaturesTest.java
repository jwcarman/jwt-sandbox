package com.carmanconsulting.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.Use;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.*;

public class JwtSignaturesTest {
//----------------------------------------------------------------------------------------------------------------------
// Other Methods
//----------------------------------------------------------------------------------------------------------------------

    private JWTClaimsSet createJwt() {
        JWTClaimsSet jwtClaims = new JWTClaimsSet();
        jwtClaims.setIssuer("https://sso.myco.com");
        jwtClaims.setSubject("alice");
        List<String> aud = new ArrayList<String>();
        aud.add("https://app-one.com");
        aud.add("https://app-two.com");
        jwtClaims.setAudience(aud);
        jwtClaims.setExpirationTime(new Date(new Date().getTime() + 1000 * 60 * 10));
        jwtClaims.setNotBeforeTime(new Date());
        jwtClaims.setIssueTime(new Date());
        jwtClaims.setJWTID(UUID.randomUUID().toString());
        return jwtClaims;
    }

    @Test
    public void testRsaSignature() throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair kp = keyGenerator.genKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

        JWSSigner signer = new RSASSASigner(privateKey);

        final JWTClaimsSet jwt = createJwt();
        final JWSHeader header = new JWSHeader(JWSAlgorithm.RS512);
        RSAKey key = new RSAKey(publicKey, Use.SIGNATURE, JWSAlgorithm.RS512, null, null, null, null);

        header.setJWK(key);
        JWSObject jwsObject = new JWSObject(header, new Payload(jwt.toJSONObject()));

        jwsObject.sign(signer);

        assertTrue(jwsObject.getState().equals(JWSObject.State.SIGNED));

        String s = jwsObject.serialize();

        jwsObject = JWSObject.parse(s);
        key = (RSAKey) jwsObject.getHeader().getJWK();

        JWSVerifier verifier = new RSASSAVerifier(key.toRSAPublicKey());

        assertTrue(jwsObject.verify(verifier));

        JWTClaimsSet deserialized = JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject());
        assertEquals(jwt.getJWTID(), deserialized.getJWTID());
    }
}
