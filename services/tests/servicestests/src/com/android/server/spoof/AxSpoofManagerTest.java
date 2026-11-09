/* SPDX-License-Identifier: Apache-2.0 */
package com.android.server.spoof;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import android.app.ActivityManager;
import android.content.ContentResolver;
import android.content.Context;
import android.os.Handler;
import android.os.UserHandle;
import android.provider.Settings;
import android.test.mock.MockContentResolver;
import android.test.mock.MockContext;
import android.testing.TestableLooper;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.SmallTest;

import com.android.internal.util.test.FakeSettingsProvider;
import com.android.internal.util.test.FakeSettingsProviderRule;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Field;
import java.util.Map;

@SmallTest
@RunWith(AndroidJUnit4.class)
@TestableLooper.RunWithLooper
public class AxSpoofManagerTest {
    @Rule public final FakeSettingsProviderRule settingsRule = FakeSettingsProvider.rule();

    private MockContentResolver mResolver;
    private ActivityManager mActivityManager;
    private AxSpoofManager mManager;
    private TestableLooper mLooper;

    @Before
    public void setUp() throws Exception {
        mResolver = settingsRule.mockContentResolver(null);
        mActivityManager = mock(ActivityManager.class);
        mLooper = TestableLooper.get(this);
        Context context = new MockContext() {
            @Override
            public ContentResolver getContentResolver() {
                return mResolver;
            }

            @Override
            public String getSystemServiceName(Class<?> serviceClass) {
                return serviceClass == ActivityManager.class ? ACTIVITY_SERVICE : null;
            }

            @Override
            public Object getSystemService(String name) {
                return ACTIVITY_SERVICE.equals(name) ? mActivityManager : null;
            }
        };
        mManager = new AxSpoofManager(context, new Handler(mLooper.getLooper()));
        setActivated(true);
        Field cache = AxSpoofManager.class.getDeclaredField("mCache");
        cache.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, String> values = (Map<String, String>) cache.get(mManager);
        values.put(Settings.Secure.SPOOF_PIF_CONFIG, "profile");
    }

    private void setActivated(boolean activated) throws Exception {
        Field field = AxSpoofManager.class.getDeclaredField("mActivated");
        field.setAccessible(true);
        field.setBoolean(mManager, activated);
    }

    @Test
    public void ownerSystemToggleGatesCachedConfigAndDefaultsEnabled() {
        assertEquals("profile", mManager.getPifConfig());
        Settings.System.putIntForUser(mResolver, "spoof_pif_enabled", 0, UserHandle.USER_SYSTEM);
        assertNull(mManager.getPifConfig());
        Settings.System.putIntForUser(mResolver, "spoof_pif_enabled", 1, UserHandle.USER_SYSTEM);
        assertEquals("profile", mManager.getPifConfig());
    }

    @Test
    public void secureAndSecondaryUserSwitchesDoNotDisableOwnerConfig() {
        Settings.Secure.putIntForUser(mResolver, "spoof_pif_enabled", 0, UserHandle.USER_SYSTEM);
        Settings.System.putIntForUser(mResolver, "spoof_pif_enabled", 0, 10);
        assertEquals("profile", mManager.getPifConfig());
    }

    @Test
    public void inactiveSpoofingDoesNotDeliverConfigOrRestartPackages() throws Exception {
        setActivated(false);
        assertNull(mManager.getPifConfig());
        mManager.scheduleGmsRestart();
        mLooper.moveTimeForward(1000);
        mLooper.processAllMessages();
        verifyNoInteractions(mActivityManager);
    }

    @Test
    public void nearbyConfigNotificationsRestartGmsFamilyOnce() {
        mManager.scheduleGmsRestart();
        mLooper.moveTimeForward(200);
        mManager.scheduleGmsRestart();
        mLooper.moveTimeForward(500);
        mLooper.processAllMessages();
        verify(mActivityManager, times(1)).forceStopPackage("com.android.vending");
        verify(mActivityManager, times(1)).forceStopPackage("com.google.android.gms");
        verify(mActivityManager, times(9)).forceStopPackage(anyString());
    }
}
