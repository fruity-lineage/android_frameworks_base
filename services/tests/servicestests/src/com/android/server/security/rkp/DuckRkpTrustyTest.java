/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server.security.rkp;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import android.hardware.security.keymint.ErrorCode;
import android.hardware.security.keymint.SecurityLevel;
import android.security.KeyStoreException;
import android.system.keystore2.KeyMetadata;
import android.system.keystore2.ResponseCode;

import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.asn1.x509.BasicConstraints;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.asn1.x509.KeyUsage;
import com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder;
import com.android.internal.org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.android.internal.org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.List;

public class DuckRkpTrustyTest {
    @Test
    public void importConnectivityFailureWaitsForNetwork() {
        KeyStoreException error = new KeyStoreException(
                ResponseCode.OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY, "test");
        assertThat(error.getRetryPolicy())
                .isEqualTo(KeyStoreException.RETRY_WHEN_CONNECTIVITY_AVAILABLE);
        DuckRkpV1.Failure failure = DuckRkpTrusty.importFailure(error);
        assertThat(failure.code).isEqualTo("network_error");
        assertThat(failure.detail).isEqualTo(error.getErrorCode());
        assertThat(DuckRkpManager.isRetryable(failure.code, failure.detail)).isTrue();
    }

    @Test
    public void importPoolAndBackendBusyFailuresBackOff() {
        for (int code : new int[] {ResponseCode.OUT_OF_KEYS_TRANSIENT_ERROR,
                ResponseCode.BACKEND_BUSY}) {
            DuckRkpV1.Failure failure = DuckRkpTrusty.importFailure(
                    new KeyStoreException(code, "test"));
            assertThat(failure.code).isEqualTo("hal_unavailable");
            assertThat(failure.detail).isEqualTo(code);
            assertThat(DuckRkpManager.isRetryable(failure.code, failure.detail)).isTrue();
        }
    }

    @Test
    public void permanentAndUncertainImportFailuresNeedExplicitRetry() {
        for (int code : new int[] {ResponseCode.OUT_OF_KEYS_PERMANENT_ERROR,
                ResponseCode.OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE, ResponseCode.OUT_OF_KEYS,
                ResponseCode.PERMISSION_DENIED, ResponseCode.SYSTEM_ERROR,
                ErrorCode.SECURE_HW_COMMUNICATION_FAILED}) {
            DuckRkpV1.Failure failure = DuckRkpTrusty.importFailure(
                    new KeyStoreException(code, "test"));
            assertThat(failure.code).isEqualTo("hal_rejected");
            assertThat(failure.detail).isEqualTo(code);
            assertThat(DuckRkpManager.isRetryable(failure.code, failure.detail)).isFalse();
        }
    }

    @Test
    public void failedCleanupStopsRetryAndPreservesOriginalFailure() {
        for (int code : new int[] {ResponseCode.OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY,
                ResponseCode.OUT_OF_KEYS_TRANSIENT_ERROR, ResponseCode.BACKEND_BUSY}) {
            DuckRkpV1.Failure primary = DuckRkpTrusty.importFailure(
                    new KeyStoreException(code, "test"));
            DuckRkpV1.Failure cleanup = new DuckRkpV1.Failure(
                    "save_failed", ResponseCode.SYSTEM_ERROR);
            assertThat(DuckRkpTrusty.cleanupFailure(primary, cleanup)).isSameInstanceAs(cleanup);
            assertThat(cleanup.getSuppressed()).asList().containsExactly(primary);
            assertThat(DuckRkpManager.isRetryable(cleanup.code, cleanup.detail)).isFalse();
        }
    }

    @Test
    public void failedCleanupKeepsPermanentPrimaryFailure() {
        for (int code : new int[] {ResponseCode.OUT_OF_KEYS_PERMANENT_ERROR,
                ResponseCode.OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE, ResponseCode.SYSTEM_ERROR,
                ErrorCode.SECURE_HW_COMMUNICATION_FAILED}) {
            DuckRkpV1.Failure primary = DuckRkpTrusty.importFailure(
                    new KeyStoreException(code, "test"));
            DuckRkpV1.Failure cleanup = new DuckRkpV1.Failure(
                    "save_failed", ResponseCode.SYSTEM_ERROR);
            assertThat(DuckRkpTrusty.cleanupFailure(primary, cleanup)).isSameInstanceAs(primary);
            assertThat(primary.getSuppressed()).asList().containsExactly(cleanup);
            assertThat(DuckRkpManager.isRetryable(primary.code, primary.detail)).isFalse();
        }
        DuckRkpV1.Failure cleanup = new DuckRkpV1.Failure(
                "save_failed", ResponseCode.SYSTEM_ERROR);
        assertThat(DuckRkpTrusty.cleanupFailure(null, cleanup)).isSameInstanceAs(cleanup);
        Exception unknown = new IllegalStateException("test");
        assertThat(DuckRkpTrusty.cleanupFailure(unknown, cleanup)).isSameInstanceAs(unknown);
        assertThat(unknown.getSuppressed()).asList().containsExactly(cleanup);
    }

    @Test
    public void chainRequiresHardwareMetadataAndBoundedCertificates() throws Exception {
        KeyMetadata metadata = new KeyMetadata();
        metadata.keySecurityLevel = SecurityLevel.SOFTWARE;
        metadata.certificate = new byte[] {1};
        metadata.certificateChain = new byte[] {2};
        assertThrows(IllegalArgumentException.class,
                () -> DuckRkpTrusty.certificateChain(metadata));
        metadata.keySecurityLevel = SecurityLevel.TRUSTED_ENVIRONMENT;
        metadata.certificateChain = new byte[DuckRkpCbor.LIMIT];
        assertThrows(IllegalArgumentException.class,
                () -> DuckRkpTrusty.certificateChain(metadata));
        metadata.certificateChain = new byte[] {2};
        assertThat(DuckRkpTrusty.certificateChain(metadata)).isEqualTo(new byte[] {1, 2});
    }

    @Test
    public void importedCaCannotExtendParentWithZeroPathLength() throws Exception {
        KeyPair root = key();
        KeyPair parent = key();
        KeyPair imported = key();
        List<X509Certificate> path = List.of(
                certificate("imported", imported, "parent", parent, 0),
                certificate("parent", parent, "root", root, 0),
                certificate("root", root, "root", root, 3));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> DuckRkpCertificates.validate(path));
        assertThat(error).hasMessageThat().contains("CA cannot sign an application certificate");
    }

    @Test
    public void derChainRequiresMatchingKeyAndTrustedRoot() throws Exception {
        KeyPair root = key();
        KeyPair imported = key();
        ByteArrayOutputStream chain = new ByteArrayOutputStream();
        chain.write(certificate("imported", imported, "root", root, 0).getEncoded());
        chain.write(certificate("root", root, "root", root, 3).getEncoded());
        byte[] encoded = chain.toByteArray();
        IllegalArgumentException mismatch = assertThrows(IllegalArgumentException.class,
                () -> DuckRkpCertificates.fromDerChain(key(), encoded));
        assertThat(mismatch).hasMessageThat().contains("No certificate matches the key");
        IllegalArgumentException untrusted = assertThrows(IllegalArgumentException.class,
                () -> DuckRkpCertificates.fromDerChain(imported, encoded));
        assertThat(untrusted).hasMessageThat().contains("Untrusted attestation root");
        chain.write(encoded);
        assertThrows(IllegalArgumentException.class,
                () -> DuckRkpCertificates.fromDerChain(imported, chain.toByteArray()));
    }

    private static KeyPair key() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(String subject, KeyPair key, String issuer,
            KeyPair signer, int pathLength) throws Exception {
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X500Name("CN=" + issuer), BigInteger.ONE,
                new Date(now - 60000), new Date(now + 60000), new X500Name("CN=" + subject),
                SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLength));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));
        byte[] der = builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider(new BouncyCastleProvider()).build(signer.getPrivate())).getEncoded();
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }
}
