/*
 * Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.security.trickystore;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import com.android.internal.org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import com.android.internal.org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.android.internal.org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;

public class KeyBoxManagerTest {
    private static KeyPair ecKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static String keybox(KeyPair privateKey, KeyPair signingKey) throws Exception {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        X500Name name = new X500Name("CN=Keybox test");
        long now = System.currentTimeMillis();
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider(provider)
                .getCertificate(new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                        new Date(now - 60000), new Date(now + 86400000), name,
                        signingKey.getPublic()).build(new JcaContentSignerBuilder("SHA256withECDSA")
                                .setProvider(provider).build(signingKey.getPrivate())));
        Base64.Encoder encoder = Base64.getEncoder();
        return "<AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes><Keybox>"
                + "<Key algorithm=\"ecdsa\"><PrivateKey>-----BEGIN PRIVATE KEY-----\n"
                + encoder.encodeToString(privateKey.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----</PrivateKey><CertificateChain>"
                + "<Certificate>-----BEGIN CERTIFICATE-----\n"
                + encoder.encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----</Certificate></CertificateChain>"
                + "</Key></Keybox></AndroidAttestation>";
    }

    @Test
    public void importsEcKeyboxUsingInternalProvider() throws Exception {
        KeyPair pair = ecKeyPair();
        KeyBoxManager manager = new KeyBoxManager();
        assertTrue(manager.parseKeybox(keybox(pair, pair)));
        assertNotNull(manager.getKeybox("EC"));
    }

    @Test
    public void mismatchedPrivateKeyPreservesLoadedKeybox() throws Exception {
        KeyPair pair = ecKeyPair();
        KeyBoxManager manager = new KeyBoxManager();
        assertTrue(manager.parseKeybox(keybox(pair, pair)));
        KeyBoxManager.KeyBox loaded = manager.getKeybox("EC");
        assertFalse(manager.parseKeybox(keybox(ecKeyPair(), pair)));
        assertSame(loaded, manager.getKeybox("EC"));
    }

    @Test
    public void truncatedRefreshPreservesLoadedKeybox() throws Exception {
        KeyPair pair = ecKeyPair();
        String xml = keybox(pair, pair);
        KeyBoxManager manager = new KeyBoxManager();
        assertTrue(manager.parseKeybox(xml));
        KeyBoxManager.KeyBox loaded = manager.getKeybox("EC");
        assertFalse(manager.parseKeybox(xml.substring(0, xml.length() - 10)));
        assertSame(loaded, manager.getKeybox("EC"));
    }
}
