/*
 * Copyright (C) 2026 The PenguinOS Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.security.rkp;

import static com.google.common.truth.Truth.assertThat;

import android.hardware.security.keymint.ErrorCode;
import android.system.keystore2.ResponseCode;

import org.json.JSONObject;
import org.junit.Test;

import java.util.concurrent.TimeUnit;

public class DuckRkpManagerTest {
    @Test
    public void bootResumesLegacyTrustyFailuresWithBackoff() throws Exception {
        long now = TimeUnit.DAYS.toMillis(20000);
        for (int code : new int[] {ResponseCode.OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY,
                ResponseCode.OUT_OF_KEYS_TRANSIENT_ERROR, ResponseCode.BACKEND_BUSY}) {
            JSONObject saved = automaticState("hal_rejected", code, true, 2, 0);
            assertThat(DuckRkpManager.resumeLegacyTrustyState(saved, true, now)).isTrue();
            assertThat(saved.getBoolean("paused")).isFalse();
            assertThat(saved.getString("error")).isEqualTo(code
                    == ResponseCode.OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY
                    ? "network_error" : "hal_unavailable");
            assertThat(saved.getInt("detail")).isEqualTo(code);
            assertThat(saved.getInt("failures")).isEqualTo(2);
            assertThat(saved.getLong("next_attempt")).isEqualTo(
                    now + TimeUnit.HOURS.toMillis(1));
        }
    }

    @Test
    public void bootPreservesLaterRetryDeadline() throws Exception {
        long now = TimeUnit.DAYS.toMillis(20000);
        long later = now + TimeUnit.HOURS.toMillis(4);
        JSONObject saved = automaticState("hal_rejected", ResponseCode.OUT_OF_KEYS_TRANSIENT_ERROR,
                true, 1, later);
        assertThat(DuckRkpManager.resumeLegacyTrustyState(saved, true, now)).isTrue();
        assertThat(saved.getLong("next_attempt")).isEqualTo(later);
    }

    @Test
    public void bootPreservesUnselectedAndUnpausedState() throws Exception {
        for (boolean paused : new boolean[] {false, true}) {
            JSONObject saved = automaticState("hal_rejected",
                    ResponseCode.OUT_OF_KEYS_TRANSIENT_ERROR, paused, 2, 0);
            String original = saved.toString();
            assertThat(DuckRkpManager.resumeLegacyTrustyState(saved, false, 0)).isFalse();
            assertThat(saved.toString()).isEqualTo(original);
            if (!paused) {
                assertThat(DuckRkpManager.resumeLegacyTrustyState(saved, true, 0)).isFalse();
                assertThat(saved.toString()).isEqualTo(original);
            }
        }
    }

    @Test
    public void bootPreservesPermanentCleanupAndUncertainFailures() throws Exception {
        for (int code : new int[] {ResponseCode.OUT_OF_KEYS_PERMANENT_ERROR,
                ResponseCode.OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE, ResponseCode.OUT_OF_KEYS,
                ResponseCode.SYSTEM_ERROR, ErrorCode.SECURE_HW_COMMUNICATION_FAILED}) {
            JSONObject saved = automaticState("hal_rejected", code, true, 2, 0);
            String original = saved.toString();
            assertThat(DuckRkpManager.resumeLegacyTrustyState(saved, true, 0)).isFalse();
            assertThat(saved.toString()).isEqualTo(original);
        }
        for (String error : new String[] {"save_failed", "timeout", "submission_unknown",
                "canceled", "certificate_invalid", "settings_unavailable", "hal_unsupported"}) {
            JSONObject saved = automaticState(error, ResponseCode.OUT_OF_KEYS_TRANSIENT_ERROR,
                    true, 2, 0);
            String original = saved.toString();
            assertThat(DuckRkpManager.resumeLegacyTrustyState(saved, true, 0)).isFalse();
            assertThat(saved.toString()).isEqualTo(original);
        }
    }

    private static JSONObject automaticState(String error, int detail, boolean paused,
            int failures, long nextAttempt) throws Exception {
        return new JSONObject().put("error", error).put("detail", detail).put("paused", paused)
                .put("failures", failures).put("next_attempt", nextAttempt);
    }

    @Test
    public void trustyImportRequiresSelectionAndServices() {
        assertThat(DuckRkpManager.supportsBackend("Google", true, false, true)).isFalse();
        assertThat(DuckRkpManager.supportsBackend("Google", true, true, false)).isFalse();
        assertThat(DuckRkpManager.supportsBackend("Google", false, true, true)).isTrue();
        assertThat(DuckRkpManager.supportsBackend("Qualcomm", true, true, false)).isFalse();
    }

    @Test
    public void unsupportedHardwareCannotUseDeclaredBackend() {
        for (String manufacturer : new String[] {"Google", "Samsung", "", null}) {
            assertThat(DuckRkpManager.supportsBackend(manufacturer, true)).isFalse();
        }
    }

    @Test
    public void supportedHardwareRequiresDeclaredBackend() {
        for (String manufacturer : new String[] {"Qualcomm", "QTI", "qcom", "QUALCOMM"}) {
            assertThat(DuckRkpManager.supportsBackend(manufacturer, false)).isFalse();
            assertThat(DuckRkpManager.supportsBackend(manufacturer, true)).isTrue();
        }
    }

    @Test
    public void renewsOneDayBeforeLongLivedChainExpires() {
        long start = TimeUnit.DAYS.toMillis(20000);
        long expiry = start + TimeUnit.DAYS.toMillis(30);
        assertThat(DuckRkpManager.renewalTime(start, expiry))
                .isEqualTo(expiry - TimeUnit.DAYS.toMillis(1));
    }

    @Test
    public void shortLivedChainKeepsMostOfItsLifetime() {
        long start = TimeUnit.DAYS.toMillis(20000);
        long expiry = start + TimeUnit.HOURS.toMillis(1);
        assertThat(DuckRkpManager.renewalTime(start, expiry))
                .isEqualTo(expiry - TimeUnit.MINUTES.toMillis(12));
    }

    @Test
    public void retryBackoffPersistsAsACappedFailureCount() {
        long[] minutes = {30, 60, 120, 240, 360, 360};
        for (int i = 0; i < minutes.length; i++) {
            assertThat(DuckRkpManager.retryDelay(i + 1))
                    .isEqualTo(TimeUnit.MINUTES.toMillis(minutes[i]));
        }
        assertThat(DuckRkpManager.retryDelay(Integer.MAX_VALUE))
                .isEqualTo(TimeUnit.HOURS.toMillis(6));
    }

    @Test
    public void temporaryFailuresCanRetry() {
        assertThat(DuckRkpManager.isRetryable("network_error", 0)).isTrue();
        assertThat(DuckRkpManager.isRetryable("hal_unavailable", 0)).isTrue();
        for (int status : new int[] {408, 429, 500, 503, 599}) {
            assertThat(DuckRkpManager.isRetryable("http_error", status)).isTrue();
        }
    }

    @Test
    public void rejectedOrUncertainRequestsNeedAnExplicitRetry() {
        for (String error : new String[] {"hal_rejected", "hal_unsupported",
                "submission_unknown", "timeout", "certificate_invalid", "canceled",
                "save_failed", "settings_unavailable", "provision_failed"}) {
            assertThat(DuckRkpManager.isRetryable(error, 0)).isFalse();
        }
        for (int status : new int[] {400, 401, 403, 404, 409, 499, 600}) {
            assertThat(DuckRkpManager.isRetryable("http_error", status)).isFalse();
        }
    }
}
