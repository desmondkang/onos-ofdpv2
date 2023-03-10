/*
 * Copyright 2016-present Open Networking Foundation
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
package org.onosproject.provider.ofdpv2.lldpcommon_ofdpv2;

import org.onosproject.mastership.MastershipService;
import org.onosproject.net.LinkKey;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.link.LinkProviderService;
import org.onosproject.net.packet.PacketService;

/**
 * Shared context for use by link discovery.
 */
public interface LinkDiscoveryContext {

    /**
     * Returns the shared mastership service reference.
     *
     * @return mastership service
     */
    MastershipService mastershipService();

    /**
     * Returns the shared link provider service reference.
     *
     * @return link provider service
     */
    LinkProviderService providerService();

    /**
     * Returns the shared packet service reference.
     *
     * @return packet service
     */
    PacketService packetService();

    /**
     * Returns the DeviceService reference.
     *
     * @return the device service interface
     */
    DeviceService deviceService();

    /**
     * Returns the FlowRuleService reference.
     *
     * @return flow rule service
     */
    FlowRuleService flowRuleService();

    /**
     * Returns the probe rate in millis.
     *
     * @return probe rate
     */
    long probeRate();

    /**
     * Indicates whether to emit BDDP.
     *
     * @return true to emit BDDP
     */
    boolean useBddp();

    /**
     * Touches the link identified by the given key to indicate that it's active.
     *
     * @param key link key
     */
    void touchLink(LinkKey key);

    /**
     * Set the TTL to the link identified by the given key to indicate that it's active.
     *
     * @param key link key
     * @param ttl ttl value(seconds)
     */
    void setTtl(LinkKey key, short ttl);

    /**
     * Returns the cluster-wide unique identifier.
     *
     * @return the cluster identifier
     */
    String fingerprint();

    /**
     * Returns the cluster-wide MAC secret used to secure LLDP packets.
     *
     * @return the secret
     */
    String lldpSecret();

    /**
     * Returns the maximum delay in milliseconds between sending an LLDP packet and receiving it elsewhere.
     *
     * @return delay in ms
     */
    long maxDiscoveryDelay();
}
