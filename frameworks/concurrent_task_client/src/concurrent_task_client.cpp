/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <unordered_map>
#include "concurrent_task_client.h"
#include <cinttypes>
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "concurrent_task_log.h"
#include "concurrent_task_errors.h"
#include "system_ability_definition.h"
#include "iconcurrent_task_service.h"
#include "concurrent_task_idl_types.h"

namespace OHOS {
namespace ConcurrentTask {

static IntervalReply IpcToQueryRs(const IpcIntervalReply& IpcQueryRs)
{
    IntervalReply queryRs;
    queryRs.rtgId = IpcQueryRs.rtgId;
    queryRs.tid = IpcQueryRs.tid;
    queryRs.paramA = IpcQueryRs.paramA;
    queryRs.paramB = IpcQueryRs.paramB;
    queryRs.bundleName = IpcQueryRs.bundleName;
    return queryRs;
}

static IpcIntervalReply QueryRsToIpc(const IntervalReply& queryRs)
{
    IpcIntervalReply IpcQueryRs;
    IpcQueryRs.rtgId = queryRs.rtgId;
    IpcQueryRs.tid = queryRs.tid;
    IpcQueryRs.paramA = queryRs.paramA;
    IpcQueryRs.paramB = queryRs.paramB;
    IpcQueryRs.bundleName = queryRs.bundleName;
    return IpcQueryRs;
}

static const IpcDeadlineReply DdlReplyToIpc(const DeadlineReply& ddlreply)
{
    IpcDeadlineReply IpcDdlReply;
    IpcDdlReply.setStatus = ddlreply.setStatus;
    return IpcDdlReply;
}

ConcurrentTaskClient& ConcurrentTaskClient::GetInstance()
{
    static ConcurrentTaskClient instance;
    return instance;
}

void ConcurrentTaskClient::ReportData(uint32_t resType, int64_t value,
                                      const std::unordered_map<std::string, std::string>& mapPayload)
{
    CONCUR_LOGD("ConcurrentTaskClient::ReportData receive resType = %{public}u, value = %{public}" PRId64 ".",
                  resType, value);
    sptr<IConcurrentTaskService> clientService = GetClientService();
    if (clientService == nullptr) {
        return;
    }
    clientService->ReportData(resType, value, mapPayload);
}

void ConcurrentTaskClient::ReportSceneInfo(uint32_t type,
                                           const std::unordered_map<std::string, std::string>& mapPayload)
{
    sptr<IConcurrentTaskService> clientService = GetClientService();
    if (clientService == nullptr) {
        return;
    }
    clientService->ReportSceneInfo(type, mapPayload);
}

void ConcurrentTaskClient::QueryInterval(int queryItem, IntervalReply& queryRs)
{
    sptr<IConcurrentTaskService> clientService = GetClientService();
    if (clientService == nullptr) {
        CONCUR_LOGE("QueryInterval connnect fail");
        return;
    }
    IpcIntervalReply IpcQueryRs = QueryRsToIpc(queryRs);
    clientService->QueryInterval(queryItem, IpcQueryRs);
    queryRs = IpcToQueryRs(IpcQueryRs);
    return;
}

void ConcurrentTaskClient::QueryDeadline(int queryItem, DeadlineReply& ddlReply,
                                         const std::unordered_map<pid_t, uint32_t>& mapPayload)
{
    sptr<IConcurrentTaskService> clientService = GetClientService();
    if (clientService == nullptr) {
        return;
    }
    std::unordered_map<std::string, std::string> payload;
    for (auto it = mapPayload.begin(); it != mapPayload.end(); ++it) {
        payload[std::to_string(it->first)] = std::to_string(it->second);
    }
    const IpcDeadlineReply& IpcDdlReply = DdlReplyToIpc(ddlReply);
    clientService->QueryDeadline(queryItem, IpcDdlReply, payload);
    return;
}

void ConcurrentTaskClient::SetAudioDeadline(int queryItem, int tid, int grpId, IntervalReply& queryRs)
{
    sptr<IConcurrentTaskService> clientService = GetClientService();
    if (clientService == nullptr) {
        CONCUR_LOGE("SetAudioDeadline connnect fail");
        return;
    }
    IpcIntervalReply IpcQueryRs = QueryRsToIpc(queryRs);
    clientService->SetAudioDeadline(queryItem, tid, grpId, IpcQueryRs);
    queryRs = IpcToQueryRs(IpcQueryRs);
    return;
}

void ConcurrentTaskClient::RequestAuth(const std::unordered_map<std::string, std::string>& mapPayload)
{
    sptr<IConcurrentTaskService> clientService = GetClientService();
    if (clientService == nullptr) {
        return;
    }
    clientService->RequestAuth(mapPayload);
    return;
}

void ConcurrentTaskClient::QueryDeadline(int queryItem, DeadlineReply& ddlReply,
                                         const std::unordered_map<std::string, std::string>& mapPayload)
{
    sptr<IConcurrentTaskService> clientService = GetClientService();
    if (clientService == nullptr) {
        return;
    }
    const IpcDeadlineReply& IpcDdlReply = DdlReplyToIpc(ddlReply);
    clientService->QueryDeadline(queryItem, IpcDdlReply, mapPayload);
    return;
}

sptr<IConcurrentTaskService> ConcurrentTaskClient::GetClientService()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (TryConnect() != ERR_OK) {
        return nullptr;
    }
    /*
     * Return a strong reference: callers use the proxy after mutex_ is released, while
     * StopRemoteObject() may reset clientService_ concurrently. Holding the reference also
     * keeps the proxy alive for the duration of the IPC call.
     */
    return clientService_;
}

// The caller must hold mutex_.
ErrCode ConcurrentTaskClient::TryConnect()
{
    if (clientService_) {
        return ERR_OK;
    }

    sptr<ISystemAbilityManager> systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemManager) {
        CONCUR_LOGE("ConcurrentTaskClient::Fail to get registry.");
        return GET_CONCURRENT_TASK_SERVICE_FAILED;
    }

    sptr<IRemoteObject> remoteObject = systemManager->GetSystemAbility(CONCURRENT_TASK_SERVICE_ID);
    if (!remoteObject) {
        CONCUR_LOGE("ConcurrentTaskClient::Fail to connect concurrent task schedule service.");
        return GET_CONCURRENT_TASK_SERVICE_FAILED;
    }

    sptr<IConcurrentTaskService> clientService = iface_cast<IConcurrentTaskService>(remoteObject);
    if (!clientService || !clientService->AsObject()) {
        return GET_CONCURRENT_TASK_SERVICE_FAILED;
    }
    if (!recipient_) {
        try {
            recipient_ = new ConcurrentTaskDeathRecipient(*this);
        } catch (const std::bad_alloc& e) {
            CONCUR_LOGE("ConcurrentTaskClient::New ConcurrentTaskDeathRecipient fail.");
        }
        if (!recipient_) {
            return GET_CONCURRENT_TASK_SERVICE_FAILED;
        }
    }
    if (!clientService->AsObject()->AddDeathRecipient(recipient_)) {
        CONCUR_LOGE("ConcurrentTaskClient::Fail to add death recipient.");
        return GET_CONCURRENT_TASK_SERVICE_FAILED;
    }
    remoteObject_ = remoteObject;
    clientService_ = clientService;
    CONCUR_LOGD("ConcurrentTaskClient::Connect concurrent task service success.");
    return ERR_OK;
}

void ConcurrentTaskClient::StopRemoteObject()
{
    /*
     * Serialize with GetClientService(): clientService_ and recipient_ are accessed from
     * caller threads as well as from the IPC death notification thread. The recipient is
     * created only once and kept alive by this member, so it can not be freed under the
     * feet of a concurrent RemoveDeathRecipient().
     */
    std::lock_guard<std::mutex> lock(mutex_);
    if (clientService_ && clientService_->AsObject() && recipient_) {
        clientService_->AsObject()->RemoveDeathRecipient(recipient_);
    }
    clientService_ = nullptr;
    remoteObject_ = nullptr;
}

int ConcurrentTaskClient::SetSystemQoS([[maybe_unused]] int tid, [[maybe_unused]] int level)
{
    return 0;
}

ConcurrentTaskClient::ConcurrentTaskDeathRecipient::ConcurrentTaskDeathRecipient(
    ConcurrentTaskClient& concurrentTaskClient) : concurrentTaskClient_(concurrentTaskClient) {}

ConcurrentTaskClient::ConcurrentTaskDeathRecipient::~ConcurrentTaskDeathRecipient() {}

void ConcurrentTaskClient::ConcurrentTaskDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& object)
{
    concurrentTaskClient_.StopRemoteObject();
}

#ifdef __cplusplus
extern "C" {
#endif
void CTC_QueryInterval(int queryItem, OHOS::ConcurrentTask::IntervalReply& queryRs)
{
    OHOS::ConcurrentTask::ConcurrentTaskClient::GetInstance().QueryInterval(queryItem, queryRs);
}
#ifdef __cplusplus
}
#endif
} // namespace ConcurrentTask
} // namespace OHOS
