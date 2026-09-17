/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.devicepolicy;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.graalvm.polyglot.HostAccess;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.base.JsBaseAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.conditional.auth.functions.devicepolicy.internal.DevicePolicyFunctionsServiceHolder;
import org.wso2.carbon.identity.device.policy.api.constant.DevicePolicyErrorMessage;
import org.wso2.carbon.identity.device.policy.api.exception.DevicePolicyClientException;
import org.wso2.carbon.identity.device.policy.api.exception.DevicePolicyException;
import org.wso2.carbon.identity.device.policy.api.model.DevicePolicyEvaluationResult;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of {@link DevicePolicyComplianceFunction}. The verified device payload
 * is captured and stored on the authentication context at initiation (see the device.policy
 * component's {@code DeviceDataResolverImpl}); this function reads it from the context under
 * {@link FrameworkConstants#DEVICE_DATA}.
 */
public class DevicePolicyComplianceFunctionImpl implements DevicePolicyComplianceFunction {

    private static final Log LOG = LogFactory.getLog(DevicePolicyComplianceFunctionImpl.class);

    private static final String COMPONENT_ID = "adaptive-auth-service";
    private static final String ACTION_EVALUATE_POLICY = "evaluate-device-policy";
    private static final String PARAM_POLICY_NAME = "policyName";
    private static final String UNKNOWN = "unknown";

    @Override
    @HostAccess.Export
    public String isCompliant(JsBaseAuthenticationContext context, String policyName) {

        try {
            String tenantDomain = context.getWrapped().getTenantDomain();

            Object data = context.getWrapped().getProperty(FrameworkConstants.DEVICE_DATA);
            if (!(data instanceof Map)) {
                logMissingDeviceData(policyName);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("No device data on the authentication context for policy: " + policyName);
                }
                return policyName + ":device token is missing or validation failed";
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> deviceData = new HashMap<>((Map<String, Object>) data);

            String appId = context.getWrapped().getServiceProviderResourceId();

            DevicePolicyEvaluationResult result = DevicePolicyFunctionsServiceHolder.getInstance()
                    .getDevicePolicyEvaluator()
                    .evaluate(policyName, deviceData, appId, tenantDomain);

            switch (result.getStatus()) {
                case COMPLIANT:
                    return null;
                case NON_COMPLIANT:
                    return String.join(", ", result.getFailedFields());
                case INCOMPLETE_DEVICE_DATA:
                    return String.join(", ", result.getMissingFields());
                default:
                    return null;
            }

        } catch (DevicePolicyClientException e) {
            if (DevicePolicyErrorMessage.ERROR_DEVICE_POLICY_NOT_FOUND.getCode().equals(e.getErrorCode())) {
                return policyName + ":policy_not_found";
            }
            LOG.warn("Error while evaluating device policy: " + policyName);
            return policyName + ":policy_error";
        } catch (DevicePolicyException e) {
            LOG.error("Error while evaluating device policy: " + policyName);
            return policyName + ":evaluation_error";
        }
    }

    /**
     * Log that no verified device data was present on the authentication context for a policy check.
     *
     * @param policyName Policy that could not be evaluated.
     */
    private void logMissingDeviceData(String policyName) {

        if (!LoggerUtils.isDiagnosticLogsEnabled()) {
            return;
        }
        DiagnosticLog.DiagnosticLogBuilder builder =
                new DiagnosticLog.DiagnosticLogBuilder(COMPONENT_ID, ACTION_EVALUATE_POLICY);
        builder.resultMessage("No verified device data on the authentication context; device policy cannot be "
                        + "evaluated.")
                .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                .inputParam(PARAM_POLICY_NAME, policyName != null ? policyName : UNKNOWN);
        LoggerUtils.triggerDiagnosticLogEvent(builder);
    }
}
