/* SPDX-License-Identifier: Apache-2.0 */
package android.security.pif;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.SmallTest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;

@SmallTest
@RunWith(AndroidJUnit4.class)
public class PlayIntegritySpoofServiceTest {
    private PlayIntegritySpoofService mService;

    @Before
    public void setUp() throws Exception {
        Constructor<PlayIntegritySpoofService> constructor =
                PlayIntegritySpoofService.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        mService = constructor.newInstance();
    }

    @After
    public void tearDown() {
        mService.loadConfig(null);
    }

    private void loadNonDefaultFlags() {
        mService.loadConfig("{\"MODEL\":\"old\",\"spoofBuild\":false,"
                + "\"spoofProvider\":true,\"spoofSignature\":true,\"verboseLogs\":100,"
                + "\"spoofVendingFinger\":\"custom\",\"spoofVendingSdk\":32,\"DEBUG\":true}");
        assertFalse(mService.isSpoofBuildEnabled());
        assertTrue(mService.isSpoofProviderEnabled());
        assertTrue(mService.isSpoofSignatureEnabled());
        mService.spoofProvider("com.google.android.gms.unstable");
        assertTrue(DroidGuardProbe.isBlocked());
    }

    private Object field(String name) throws Exception {
        Field field = PlayIntegritySpoofService.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(mService);
    }

    private void assertDefaults() throws Exception {
        assertEquals(true, field("mSpoofBuild"));
        assertEquals(false, field("mSpoofProvider"));
        assertEquals(false, field("mSpoofSignature"));
        assertEquals(0, mService.getVerboseLogs());
        assertEquals("0", mService.getSpoofVendingFinger());
        assertEquals(0, field("mSpoofVendingSdk"));
        assertEquals(false, field("mDebug"));
        assertFalse(DroidGuardProbe.isBlocked());
    }

    @Test
    public void replacementJsonWithoutFlagsRestoresDefaults() throws Exception {
        loadNonDefaultFlags();
        mService.loadConfig("{\"MODEL\":\"replacement\"}");
        assertTrue(mService.isConfigLoaded());
        assertDefaults();
        assertEquals("replacement", mService.getBuildFields().get("MODEL"));
        assertEquals(1, mService.getBuildFields().size());
    }

    @Test
    public void replacementPropWithoutFlagsRestoresDefaults() throws Exception {
        loadNonDefaultFlags();
        mService.loadConfig("MODEL=replacement\n");
        assertTrue(mService.isConfigLoaded());
        assertDefaults();
        assertEquals("replacement", mService.getBuildFields().get("MODEL"));
    }

    @Test
    public void missingAndBlankConfigsClearFieldsFlagsAndChainBlock() throws Exception {
        for (String content : new String[] {null, "", " \n\t"}) {
            loadNonDefaultFlags();
            mService.loadConfig(content);
            assertFalse(mService.isConfigLoaded());
            assertTrue(mService.getBuildFields().isEmpty());
            assertDefaults();
        }
    }

    @Test
    public void malformedReplacementCannotLeavePartiallyParsedFlagsEnabled() throws Exception {
        loadNonDefaultFlags();
        mService.loadConfig("{\"spoofProvider\":true,\"MODEL\":");
        assertFalse(mService.isConfigLoaded());
        assertTrue(mService.getBuildFields().isEmpty());
        assertDefaults();
    }

    private static final class DroidGuardProbe {
        static boolean isBlocked() {
            return PlayIntegritySpoofService.shouldBlockCertificateChain();
        }
    }
}
