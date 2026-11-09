/* SPDX-License-Identifier: Apache-2.0 */
package android.security.trickystore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

import android.security.pif.PlayIntegritySpoofService;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.SmallTest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

@SmallTest
@RunWith(AndroidJUnit4.class)
public class CertificateGeneratorIdentityTest {
    private static final String PROFILE = "{\"FINGERPRINT\":"
            + "\"google/bluejay/bluejay:17/CP11.261101.001/12345:user/release-keys\","
            + "\"MANUFACTURER\":\"Google\",\"MODEL\":\"Pixel 6a\"}";
    private PlayIntegritySpoofService mPif;
    private Method mLoadConfig;

    @Before
    public void setUp() throws Exception {
        Constructor<PlayIntegritySpoofService> constructor =
                PlayIntegritySpoofService.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        mPif = constructor.newInstance();
        mLoadConfig = PlayIntegritySpoofService.class.getDeclaredMethod("loadConfig", String.class);
        mLoadConfig.setAccessible(true);
    }

    @After
    public void tearDown() throws Exception {
        load(null);
    }

    private void load(String config) throws Exception {
        mLoadConfig.invoke(mPif, config);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static CertificateGenerator.KeyGenParameters requestedIds() {
        CertificateGenerator.KeyGenParameters params = new CertificateGenerator.KeyGenParameters();
        params.brand = bytes("original brand");
        params.device = bytes("tokay");
        params.product = bytes("tokay");
        params.manufacturer = bytes("original manufacturer");
        params.model = bytes("Pixel 9");
        return params;
    }

    private void apply(CertificateGenerator.KeyGenParameters params, String process) {
        CertificateHacker.applyAttestationIdOverrides(params, mPif, process);
    }

    @Test
    public void activeProfileReplacesRequestedIdsForDroidGuardAndVending() throws Exception {
        load(PROFILE);
        for (String process : new String[] {"com.google.android.gms.unstable",
                "com.android.vending"}) {
            CertificateGenerator.KeyGenParameters params = requestedIds();
            apply(params, process);
            assertArrayEquals(bytes("google"), params.brand);
            assertArrayEquals(bytes("bluejay"), params.device);
            assertArrayEquals(bytes("bluejay"), params.product);
            assertArrayEquals(bytes("Google"), params.manufacturer);
            assertArrayEquals(bytes("Pixel 6a"), params.model);
        }
    }

    @Test
    public void disabledAndAbsentProfilesPreserveRequestedIdentity() throws Exception {
        for (String config : new String[] {null, "", PROFILE.replace("{",
                "{\"spoofBuild\":false,")}) {
            load(config);
            CertificateGenerator.KeyGenParameters params = requestedIds();
            byte[] brand = params.brand;
            byte[] device = params.device;
            byte[] product = params.product;
            byte[] manufacturer = params.manufacturer;
            byte[] model = params.model;
            apply(params, "com.android.vending");
            assertSame(brand, params.brand);
            assertSame(device, params.device);
            assertSame(product, params.product);
            assertSame(manufacturer, params.manufacturer);
            assertSame(model, params.model);
        }
    }

    @Test
    public void ordinaryCallerKeepsOriginalRequestedIds() throws Exception {
        load(PROFILE);
        CertificateGenerator.KeyGenParameters params = requestedIds();
        byte[] model = params.model;
        byte[] device = params.device;
        apply(params, "com.example.app");
        assertSame(model, params.model);
        assertSame(device, params.device);
    }

    @Test
    public void profileDoesNotAddUnrequestedIdentityTags() throws Exception {
        load(PROFILE);
        CertificateGenerator.KeyGenParameters params = new CertificateGenerator.KeyGenParameters();
        params.model = bytes("Pixel 9");
        apply(params, "com.android.vending");
        assertArrayEquals(bytes("Pixel 6a"), params.model);
        assertNull(params.brand);
        assertNull(params.device);
        assertNull(params.product);
        assertNull(params.manufacturer);
    }

    @Test
    public void missingProfileFieldsPreserveOriginalRequestedValues() throws Exception {
        load("{\"MODEL\":\"Pixel 6a\"}");
        CertificateGenerator.KeyGenParameters params = requestedIds();
        byte[] device = params.device;
        byte[] brand = params.brand;
        apply(params, "com.android.vending");
        assertArrayEquals(bytes("Pixel 6a"), params.model);
        assertSame(device, params.device);
        assertSame(brand, params.brand);
    }
}
