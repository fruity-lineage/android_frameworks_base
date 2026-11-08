/*
 * SPDX-FileCopyrightText: AxionOS
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.wm.sandbox;

import android.content.ContentResolver;
import android.os.UserHandle;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Slog;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.function.Consumer;

public final class SandboxConfigStorage {
    private static final String TAG = "AxSandbox.Storage";
    public static final String SETTING_SANDBOX_CONFIG = "sandbox_config";

    private static final Object sFileLock = new Object();

    private SandboxConfigStorage() {
    }

    public static JSONObject readConfig(ContentResolver resolver) {
        synchronized (sFileLock) {
            String str = Settings.Secure.getStringForUser(resolver, SETTING_SANDBOX_CONFIG,
                    UserHandle.USER_SYSTEM);
            if (TextUtils.isEmpty(str)) {
                return new JSONObject();
            }
            try {
                return new JSONObject(str);
            } catch (JSONException e) {
                Slog.e(TAG, "Failed to parse sandbox_config JSON", e);
                return new JSONObject();
            }
        }
    }

    public static void updateConfig(ContentResolver resolver, Consumer<JSONObject> updater) {
        synchronized (sFileLock) {
            String str = Settings.Secure.getStringForUser(resolver, SETTING_SANDBOX_CONFIG,
                    UserHandle.USER_SYSTEM);
            JSONObject config;
            try {
                config = TextUtils.isEmpty(str) ? new JSONObject() : new JSONObject(str);
            } catch (JSONException e) {
                throw new IllegalStateException("Refusing to replace malformed sandbox_config", e);
            }
            try {
                updater.accept(config);
                if (!Settings.Secure.putStringForUser(resolver, SETTING_SANDBOX_CONFIG,
                        config.toString(), UserHandle.USER_SYSTEM)) {
                    throw new IllegalStateException("SettingsProvider rejected sandbox_config");
                }
            } catch (Exception e) {
                Slog.e(TAG, "Failed to update sandbox_config JSON", e);
                throw new IllegalStateException("Unable to persist sandbox_config", e);
            }
        }
    }
}
