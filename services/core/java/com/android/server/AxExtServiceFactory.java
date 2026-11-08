/*
 * Copyright (C) 2025 AxionOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.server;

import android.content.Context;

import com.android.server.spoof.AxSpoofManager;
import com.android.server.spoof.IAxSpoofManager;
import com.android.server.wm.sandbox.spoof.SettingsSpoofRepository;
import com.android.server.wm.sandbox.spoof.SettingsSpoofService;

public class AxExtServiceFactory {
    private static volatile AxExtServiceFactory sInstance;

    private static final Object sLock = new Object();

    private static volatile IAxSpoofManager sAxSpoofManager;
    private static volatile SettingsSpoofService sSettingsSpoofService;

    private AxExtServiceFactory(Context context) {
        NtServiceInjector.get().setCtx(context);
    }

    public static synchronized AxExtServiceFactory init(Context context) {
        if (sInstance == null) {
            sInstance = new AxExtServiceFactory(context);
        }
        return sInstance;
    }

    public static AxExtServiceFactory get() {
        if (sInstance == null) {
            throw new IllegalStateException("AxExtServiceFactory not initialized");
        }
        return sInstance;
    }

    @SuppressWarnings("unchecked")
    public static <T> T getOrCreate(IAxExtServiceFactory.ExtType type) {
        Object instance;
        switch (type) {
            case AX_SPOOF_MANAGER:
                if (sAxSpoofManager == null) {
                    synchronized (sLock) {
                        if (sAxSpoofManager == null) {
                            sAxSpoofManager = new AxSpoofManager();
                        }
                    }
                }
                instance = sAxSpoofManager;
                break;

            default:
                throw new IllegalArgumentException("Unknown ExtType: " + type);
        }

        return (T) type.getClazz().cast(instance);
    }

    public static synchronized void systemReady() {
        if (sSettingsSpoofService != null) return;
        getSpoofManager().systemReady();
        SettingsSpoofRepository repository = new SettingsSpoofRepository(NtServiceInjector.getCtx());
        repository.init();
        sSettingsSpoofService = new SettingsSpoofService(repository);
    }

    public static IAxSpoofManager getSpoofManager() {
        return getOrCreate(IAxExtServiceFactory.ExtType.AX_SPOOF_MANAGER);
    }

    public static SettingsSpoofService getSettingsSpoofService() {
        return sSettingsSpoofService;
    }
}
