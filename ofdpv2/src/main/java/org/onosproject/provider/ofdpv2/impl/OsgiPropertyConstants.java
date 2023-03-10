/*
 * Copyright 2018-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.provider.ofdpv2.impl;

/**
 * Constants for default values of configurable properties.
 */
public final class OsgiPropertyConstants {

    private OsgiPropertyConstants() {}

    public static final String PROP_ENABLED = "enabled";
    public static final boolean ENABLED_DEFAULT = true;

    //currently we are not using bddp, therefore, should be false by default
    public static final String PROP_USE_BDDP = "useBddp";
    public static final boolean USE_BDDP_DEFAULT = true;

    public static final String PROP_PROBE_RATE = "probeRate";
    public static final int PROBE_RATE_DEFAULT = 3000; //milliseconds

    public static final String PROP_STALE_LINK_AGE = "staleLinkAge";
    public static final int STALE_LINK_AGE_DEFAULT = 10000;

    public static final String PROP_DISCOVERY_DELAY = "maxDiscoveryDelayMs";
    public static final int DISCOVERY_DELAY_DEFAULT = 1000;

    public static final String PROP_USE_STALE_LINK_AGE = "useStaleLinkAge";
    public static final boolean USE_STALE_LINK_AGE_DEFAULT = true;

}
