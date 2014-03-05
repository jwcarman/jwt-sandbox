package com.carmanconsulting.jwt;

import com.nimbusds.jose.JOSEException;
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
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.*;

public class JwtSignaturesTest {
//----------------------------------------------------------------------------------------------------------------------
// Other Methods
//----------------------------------------------------------------------------------------------------------------------

    @Test
    public void testRsaSignature() throws Exception {
        KeyPair kp = createKeyPair();
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

        assertTrue(verify(jwsObject));

        JWTClaimsSet copy = JWTClaimsSet.parse(jwsObject.getPayload().toJSONObject());
        assertEquals(jwt.getJWTID(), copy.getJWTID());
    }

    private KeyPair createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        return keyGenerator.genKeyPair();
    }

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

    private boolean verify(JWSObject jwsObject) throws NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        RSAKey key = (RSAKey) jwsObject.getHeader().getJWK();
        JWSVerifier verifier = new RSASSAVerifier(key.toRSAPublicKey());
        return jwsObject.verify(verifier);
    }
}
