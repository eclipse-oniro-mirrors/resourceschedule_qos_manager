/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <sys/resource.h>
#include <sched.h>
#include <linux/sched.h>
#include "rtg_interface.h"
#include "ipc_skeleton.h"
#include "concurrent_task_log.h"
#include "concurrent_task_controller.h"
constexpr int TARGET_UID = 3039;
using namespace OHOS::RME;

namespace OHOS {
namespace ConcurrentTask {
TaskController& TaskController::GetInstance()
{
    static TaskController instance;
    return instance;
}

void TaskController::ReportData(uint32_t resType, int64_t value, const Json::Value& payload)
{
    pid_t uid = IPCSkeleton::GetInstance().GetCallingUid();
    if (!CheckUid(uid)) {
        CONCUR_LOGE("only system call can be allowed");
        return;
    }
    Json::ValueType type = payload.type();
    if (type != Json::objectValue) {
        CONCUR_LOGE("error payload");
        return;
    }
    if (payload.empty()) {
        CONCUR_LOGE("payload is empty");
        return;
    }
    std::string strRequstType = "";
    try {
        strRequstType = payload["type"].asString();
    } catch (...) {
        CONCUR_LOGE("Unexpected type format");
        return;
    }
    if (strRequstType.length() == 0) {
        CONCUR_LOGE("Get payload type err");
        return;
    }
    int requstType = GetRequestType(strRequstType);
    DealSystemRequest(requstType, payload);
    PrintInfo();
}

void TaskController::QueryInterval(int queryItem, IntervalReply& queryRs)
{
    pid_t uid = IPCSkeleton::GetInstance().GetCallingUid();
    if (uid == 0) {
        CONCUR_LOGE("Uid is 0, error query");
        return;
    }
    switch (queryItem) {
        case QUERY_UI:
            QueryUi(uid, queryRs);
            break;
        case QUERY_RENDER:
            QueryRender(uid, queryRs);
            break;
        case QUERY_RENDER_SERVICE:
            QueryRenderService(uid, queryRs);
            break;
        case QUERY_COMPOSER:
            QueryHwc(uid, queryRs);
            break;
        default:
            break;
    }
}

void TaskController::QueryUi(int uid, IntervalReply& queryRs)
{
    if (uid == SYSTEM_UID) {
        return;
    }
    pid_t pid = IPCSkeleton::GetInstance().GetCallingPid();
    auto iter = GetRecordOfUid(uid);
    if (iter == foregroundApp_.end()) {
        CONCUR_LOGD("Query ui with uid %{public}d failed: pid %{public}d", uid, pid);
        return;
    }
    int grpId = iter->GetGrpId();
    if (grpId <= 0) {
        CONCUR_LOGI("%{public}d Query ui with none grpid", uid);
        queryRs.rtgId = -1;
    } else {
        queryRs.rtgId = grpId;
    }
}

void TaskController::QueryRender(int uid, IntervalReply& queryRs)
{
    if (uid == SYSTEM_UID) {
        return;
    }
    pid_t pid = IPCSkeleton::GetInstance().GetCallingPid();
    auto iter = GetRecordOfUid(uid);
    if (iter == foregroundApp_.end()) {
        CONCUR_LOGD("Query render with uid %{public}d failed, pid %{public}d", uid, pid);
        return;
    }
    int grpId = iter->GetGrpId();
    if (grpId <= 0) {
        CONCUR_LOGI("%{public}d Query render with none grpid", uid);
        queryRs.rtgId = -1;
    } else {
        queryRs.rtgId = grpId;
    }
}

void TaskController::QueryRenderService(int uid, IntervalReply& queryRs)
{
    if (renderServiceGrpId_ > 0) {
        CONCUR_LOGD("uid %{public}d query rs group %{public}d.", uid, renderServiceGrpId_);
        queryRs.rtgId = renderServiceGrpId_;
        return;
    }
    TryCreateRsGroup();
    queryRs.rtgId = renderServiceGrpId_;
    CONCUR_LOGE("uid %{public}d query rs group failed and create %{public}d.", uid, renderServiceGrpId_);
}

void TaskController::QueryHwc(int uid, IntervalReply& queryRs)
{
    if (uid == SYSTEM_UID) {
        return;
    }
    pid_t pid = IPCSkeleton::GetInstance().GetCallingPid();
    auto iter = GetRecordOfUid(uid);
    if (iter == foregroundApp_.end()) {
        CONCUR_LOGD("Query ipc thread with uid %{public}d failed, pid %{public}d", uid, pid);
        return;
    }
    int grpId = iter->GetGrpId();
    if (grpId <= 0) {
        CONCUR_LOGI("%{public}d Query ipc thread with none grpid", uid);
        queryRs.rtgId = -1;
    } else {
        queryRs.rtgId = grpId;
    }
}

void TaskController::SetHwcAuth(bool status)
{
    int ret;
    if (status) {
        ret = AuthEnable(TARGET_UID, AF_RTG_ALL, static_cast<unsigned int>(AuthStatus::AUTH_STATUS_FOREGROUND));
    } else {
        ret = AuthDelete(TARGET_UID);
    }

    if (ret == 0) {
        CONCUR_LOGI("set auth status(%{public}d) for %{public}d success", status, TARGET_UID);
    } else {
        CONCUR_LOGE("set auth status(%{public}d) for %{public}d fail with ret %{public}d ", status, TARGET_UID, ret);
    }
}

void TaskController::Init()
{
    SetHwcAuth(true);
    TypeMapInit();
    qosManager_.Init();
    TryCreateRsGroup();
}

void TaskController::Release()
{
    SetHwcAuth(false);
    msgType_.clear();
    if (renderServiceGrpId_ <= 0) {
        return;
    }
    DestroyRtgGrp(renderServiceGrpId_);
    renderServiceGrpId_ = -1;
}

void TaskController::TypeMapInit()
{
    msgType_.clear();
    msgType_.insert(pair<std::string, int>("foreground", MSG_FOREGROUND));
    msgType_.insert(pair<std::string, int>("background", MSG_BACKGROUND));
    msgType_.insert(pair<std::string, int>("appStart", MSG_APP_START));
    msgType_.insert(pair<std::string, int>("appKilled", MSG_APP_KILLED));
}

void TaskController::TryCreateRsGroup()
{
    if (!rtgEnabled_) {
        rtgEnabled_ = EnableRtg(true) < 0 ? false : true;
        if (!rtgEnabled_) {
            CONCUR_LOGE("Rtg enable failed");
            return;
        }
        CONCUR_LOGI("Enable Rtg");
    }
    renderServiceGrpId_ = CreateNewRtgGrp(PRIO_RT, MAX_KEY_THREADS);
    if (renderServiceGrpId_ <= 0) {
        CONCUR_LOGI("CreateRsRtgGroup with RT failed, try change to normal type.");
        renderServiceGrpId_ = CreateNewRtgGrp(PRIO_NORMAL, MAX_KEY_THREADS);
    }
    if (renderServiceGrpId_ <= 0) {
        CONCUR_LOGI("CreateRsRtgGroup failed! rtGrp:%{public}d", renderServiceGrpId_);
    }
}

int TaskController::GetRequestType(std::string strRequstType)
{
    auto iter = msgType_.find(strRequstType);
    if (iter == msgType_.end()) {
        return MSG_TYPE_MAX;
    }
    return msgType_[strRequstType];
}

bool TaskController::CheckUid(pid_t uid)
{
    if ((uid != SYSTEM_UID) && (uid != 0)) {
        return false;
    }
    return true;
}

void TaskController::DealSystemRequest(int requestType, const Json::Value& payload)
{
    int appUid = 0;
    try {
        appUid = stoi(payload["uid"].asString());
    } catch (...) {
        CONCUR_LOGE("Unexpected uid format");
    }
    if (appUid < 0) {
        CONCUR_LOGE("appUid error:%d", appUid);
        return;
    }
    switch (requestType) {
        case MSG_FOREGROUND:
            NewForeground(appUid);
            break;
        case MSG_BACKGROUND:
            NewBackground(appUid);
            break;
        case MSG_APP_START:
            NewAppStart(appUid);
            break;
        case MSG_APP_KILLED:
            AppKilled(appUid);
            break;
        default:
            CONCUR_LOGE("Unknown system request");
            break;
    }
}

void TaskController::DealAppRequest(int requestType, const Json::Value& payload, pid_t uid)
{
    if (uid <= SYSTEM_UID) {
        CONCUR_LOGE("Unexpected uid in app req");
        return;
    }
    int tid = 0;
    try {
        tid = stoi(payload["tid"].asString());
    } catch (...) {
        CONCUR_LOGE("Unexpected tid format");
        return;
    }
    if ((requestType >= MSG_REG_RENDER) && (requestType <= MSG_REG_KEY_THERAD)) {
        int prioType = PRIO_NORMAL;
        auto record = GetRecordOfUid(uid);
        if (record == foregroundApp_.end()) {
            return;
        }
        if (requestType != MSG_REG_KEY_THERAD) {
            prioType = PRIO_RT;
        }
        record->AddKeyThread(tid, prioType);
    }
}

std::list<ForegroundAppRecord>::iterator TaskController::GetRecordOfUid(int uid)
{
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        if (iter->GetUid() == uid) {
            return iter;
        }
    }
    return foregroundApp_.end();
}

void TaskController::NewForeground(int uid)
{
    auto it = find(authApps_.begin(), authApps_.end(), uid);
    if (it == authApps_.end()) {
        CONCUR_LOGI("un-authed uid %{public}d", uid);
        return;
    }
    unsigned int uidParam = static_cast<unsigned int>(uid);
    unsigned int uaFlag = AF_RTG_ALL;
    unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_FOREGROUND);

    int ret = AuthEnable(uidParam, uaFlag, status);
    if (ret == 0) {
        CONCUR_LOGI("auth_enable %{public}d success", uid);
    } else {
        CONCUR_LOGE("auth_enable %{public}d fail with ret %{public}d", uid, ret);
    }
    bool found = false;
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        if (iter->GetUid() == uid) {
            found = true;
            CONCUR_LOGI("uid %{public}d is already in foreground.", uid);
            iter->BeginScene();
        }
    }
    CONCUR_LOGI("uid %{public}d change to foreground.", uid);
    if (!found) {
        ForegroundAppRecord *tempRecord = new ForegroundAppRecord(uid);
        if (tempRecord->IsValid()) {
            foregroundApp_.push_back(*tempRecord);
            tempRecord->BeginScene();
        } else {
            delete tempRecord;
        }
    }
}

void TaskController::NewBackground(int uid)
{
    auto it = find(authApps_.begin(), authApps_.end(), uid);
    if (it == authApps_.end()) {
        CONCUR_LOGI("un-authed uid %{public}d", uid);
        return;
    }
    CONCUR_LOGI("uid %{public}d change to background.", uid);
    unsigned int uidParam = static_cast<unsigned int>(uid);

    int ret = AuthPause(uidParam);
    if (ret == 0) {
        CONCUR_LOGI("auth_pause %{public}d success", uid);
    } else {
        CONCUR_LOGI("auth_pause %{public}d fail with %{public}d", uid, ret);
    }
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        if (iter->GetUid() == uid) {
            iter->EndScene();
            return;
        }
    }
}

void TaskController::NewAppStart(int uid)
{
    CONCUR_LOGI("uid %{public}d start.", uid);
    unsigned int uidParam = static_cast<unsigned int>(uid);
    unsigned int uaFlag = AF_RTG_ALL;
    unsigned int status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_BACKGROUND);

    int ret = AuthEnable(uidParam, uaFlag, status);
    if (ret == 0) {
        CONCUR_LOGI("auth_enable %{public}d success", uid);
    } else {
        CONCUR_LOGE("auth_enable %{public}d fail with ret %{public}d", uid, ret);
    }
    authApps_.push_back(uid);
}

void TaskController::AppKilled(int uid)
{
    CONCUR_LOGI("uid %{public}d killed.", uid);
    unsigned int uidParam = static_cast<unsigned int>(uid);
    int ret = AuthDelete(uidParam);
    if (ret == 0) {
        CONCUR_LOGI("auth_delete %{public}d success", uid);
    } else {
        CONCUR_LOGE("auth_delete %{public}d fail with %{public}d", uid, ret);
    }
    std::lock_guard<std::mutex> lock(appInfoLock_);
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        if (iter->GetUid() == uid) {
            foregroundApp_.erase(iter++);
            break;
        }
    }
    for (auto iter = authApps_.begin(); iter != authApps_.end(); iter++) {
        if (*iter == uid) {
            authApps_.erase(iter++);
            break;
        }
    }
}

void TaskController::PrintInfo()
{
    for (auto iter = foregroundApp_.begin(); iter != foregroundApp_.end(); iter++) {
        iter->PrintKeyThreads();
    }
}

ForegroundAppRecord::ForegroundAppRecord(int uid)
{
    uid_ = uid;
    grpId_ = CreateNewRtgGrp(PRIO_RT, MAX_KEY_THREADS);
    if (grpId_ <= 0) {
        CONCUR_LOGI("CreateNewRtgGroup with RT failed, try change to normal type.");
        grpId_ = CreateNewRtgGrp(PRIO_NORMAL, MAX_KEY_THREADS);
    }
    if (grpId_ <= 0) {
        CONCUR_LOGI("CreateNewRtgGroup failed! rtGrp:%{public}d, pid: %{public}d", grpId_, uid);
    }
}

ForegroundAppRecord::~ForegroundAppRecord()
{
    if (grpId_ > 0) {
        DestroyRtgGrp(grpId_);
    }
}

void ForegroundAppRecord::AddKeyThread(int tid, int prio)
{
    int rtgPrio = (prio >= PRIO_NORMAL) ? PRIO_NORMAL : PRIO_RT;
    if (keyThreads_.find(tid) != keyThreads_.end()) {
        return;
    }
    if (grpId_ <= 0) {
        CONCUR_LOGI("Add key thread fail: Grp id not been created success.");
        return;
    }
    if (keyThreads_.size() >= MAX_KEY_THREADS) {
        CONCUR_LOGI("Add key thread fail: Key threads num limit.");
        return;
    }
    if (prio == RPIO_IN) {
        setpriority(PRIO_PROCESS, tid, -13); // -13 represent spcial nice in qos
    } else {
        int ret = AddThreadToRtg(tid, grpId_, rtgPrio);
        if (ret != 0) {
            CONCUR_LOGI("Add key thread fail: Kernel err report.");
        } else {
            CONCUR_LOGI("Add key thread %{public}d", tid);
        }
        keyThreads_.insert(tid);
    }
}

bool ForegroundAppRecord::BeginScene()
{
    if (grpId_ <= 0) {
        CONCUR_LOGI("Error begin scene in uid %{public}d", uid_);
        return false;
    }
    OHOS::RME::BeginFrameFreq(grpId_, 0);
    OHOS::RME::EndFrameFreq(grpId_);
    return true;
}

bool ForegroundAppRecord::EndScene()
{
    if (grpId_ <= 0) {
        CONCUR_LOGI("Error end scene in uid %{public}d", uid_);
        return false;
    }
    OHOS::RME::EndScene(grpId_);
    return true;
}

int ForegroundAppRecord::GetUid()
{
    return uid_;
}

int ForegroundAppRecord::GetGrpId()
{
    return grpId_;
}

bool ForegroundAppRecord::IsValid()
{
    if (uid_ > 0 && grpId_ > 0) {
        return true;
    }
    return false;
}

void ForegroundAppRecord::PrintKeyThreads()
{
    std::string strLog = "pid ";
    strLog.append(std::to_string(uid_));
    strLog.append(" has key threads: ");
    for (auto iter = keyThreads_.begin(); iter != keyThreads_.end(); iter++) {
        std::string temp = std::to_string(*iter);
        strLog.append(temp);
        strLog.append(", ");
    }
    CONCUR_LOGD("%{public}s", strLog.c_str());
}
} // namespace ConcurrentTask
} // namespace OHOS
