/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server.security.rkp;

import android.hardware.security.keymint.Algorithm;
import android.hardware.security.keymint.Digest;
import android.hardware.security.keymint.EcCurve;
import android.hardware.security.keymint.IKeyMintDevice;
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.KeyParameterValue;
import android.hardware.security.keymint.KeyPurpose;
import android.hardware.security.keymint.SecurityLevel;
import android.hardware.security.keymint.Tag;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.security.KeyStore2;
import android.security.KeyStoreException;
import android.security.KeyStoreSecurityLevel;
import android.system.keystore2.Domain;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyMetadata;
import android.system.keystore2.ResponseCode;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

/** Uses KeyMint import attestation; it does not submit an external key in an RKP CSR. */
final class DuckRkpTrusty {
    private static final String CONFIG = "ro.lineage.duckrkp.trusty_import";
    private static final String SERVICE = "android.system.keystore2.IKeystoreService/default";
    private static final String ALIAS = "duck_rkp_trusty_import";

    private DuckRkpTrusty() {}

    static boolean enabled() {
        return SystemProperties.getBoolean(CONFIG, false);
    }

    static boolean available() {
        return !SystemProperties.get("remote_provisioning.hostname").isEmpty()
                && ServiceManager.isDeclared(SERVICE)
                && ServiceManager.isDeclared(IKeyMintDevice.DESCRIPTOR + "/default")
                && ServiceManager.isDeclared(DuckRkpV1.SERVICE);
    }

    static DuckRkpCertificates.Result provision(DuckRkpV1.Progress progress) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair key = generator.generateKeyPair();
        byte[] encoded = key.getPrivate().getEncoded();
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);
        KeyStore2 keystore = KeyStore2.getInstance();
        KeyDescriptor descriptor = new KeyDescriptor();
        descriptor.domain = Domain.APP;
        descriptor.nspace = -1;
        descriptor.alias = ALIAS;

        Exception failure = null;
        try {
            progress.update("hardware");
            deleteTemporaryKey(keystore, descriptor);
            KeyStoreSecurityLevel tee = keystore.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT);
            long now = System.currentTimeMillis();
            List<KeyParameter> params = List.of(
                    parameter(Tag.ALGORITHM, KeyParameterValue.algorithm(Algorithm.EC)),
                    parameter(Tag.EC_CURVE, KeyParameterValue.ecCurve(EcCurve.P_256)),
                    parameter(Tag.PURPOSE, KeyParameterValue.keyPurpose(KeyPurpose.ATTEST_KEY)),
                    parameter(Tag.DIGEST, KeyParameterValue.digest(Digest.SHA_2_256)),
                    parameter(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true)),
                    parameter(Tag.ATTESTATION_CHALLENGE, KeyParameterValue.blob(challenge)),
                    parameter(Tag.CERTIFICATE_SUBJECT, KeyParameterValue.blob(
                            new X500Principal("CN=DuckRkp Imported Key").getEncoded())),
                    parameter(Tag.CERTIFICATE_SERIAL, KeyParameterValue.blob(
                            new BigInteger(1, Arrays.copyOf(challenge, 16)).add(BigInteger.ONE)
                                    .toByteArray())),
                    parameter(Tag.CERTIFICATE_NOT_BEFORE, KeyParameterValue.dateTime(
                            now - TimeUnit.DAYS.toMillis(1))),
                    parameter(Tag.CERTIFICATE_NOT_AFTER, KeyParameterValue.dateTime(
                            now + TimeUnit.DAYS.toMillis(30))));
            KeyMetadata metadata = tee.importKey(descriptor, null, params, 0, encoded);
            progress.update("validating");
            try {
                return DuckRkpCertificates.fromDerChain(key, certificateChain(metadata));
            } catch (Exception e) {
                throw new DuckRkpV1.Failure("certificate_invalid");
            }
        } catch (KeyStoreException e) {
            failure = new DuckRkpV1.Failure("hal_rejected", e.getErrorCode());
            throw failure;
        } catch (Exception e) {
            failure = e;
            throw e;
        } finally {
            Arrays.fill(encoded, (byte) 0);
            try {
                deleteTemporaryKey(keystore, descriptor);
            } catch (DuckRkpV1.Failure cleanup) {
                if (failure == null) throw cleanup;
                failure.addSuppressed(cleanup);
            }
        }
    }

    private static void deleteTemporaryKey(KeyStore2 keystore, KeyDescriptor descriptor)
            throws DuckRkpV1.Failure {
        try {
            keystore.deleteKey(descriptor);
        } catch (KeyStoreException e) {
            if (e.getErrorCode() != ResponseCode.KEY_NOT_FOUND) {
                throw new DuckRkpV1.Failure("save_failed", e.getErrorCode());
            }
        }
    }

    static byte[] certificateChain(KeyMetadata metadata) throws Exception {
        if (metadata == null || metadata.keySecurityLevel != SecurityLevel.TRUSTED_ENVIRONMENT
                || metadata.certificate == null || metadata.certificate.length == 0
                || metadata.certificateChain == null || metadata.certificateChain.length == 0
                || metadata.certificate.length > DuckRkpCbor.LIMIT
                || metadata.certificateChain.length > DuckRkpCbor.LIMIT
                        - metadata.certificate.length) {
            throw new IllegalArgumentException("Missing or oversized hardware certificate chain");
        }
        ByteArrayOutputStream chain = new ByteArrayOutputStream();
        chain.write(metadata.certificate);
        chain.write(metadata.certificateChain);
        return chain.toByteArray();
    }

    private static KeyParameter parameter(int tag, KeyParameterValue value) {
        KeyParameter parameter = new KeyParameter();
        parameter.tag = tag;
        parameter.value = value;
        return parameter;
    }
}
