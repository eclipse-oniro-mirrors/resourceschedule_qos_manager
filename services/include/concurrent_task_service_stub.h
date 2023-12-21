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

#ifndef CONCURRENT_TASK_SEVICES_INCLUDE_CONCURRENT_TASK_SERVICE_STUB_H
#define CONCURRENT_TASK_SEVICES_INCLUDE_CONCURRENT_TASK_SERVICE_STUB_H

#include <map>
#include "iremote_stub.h"
#include "iconcurrent_task_service.h"
#include "concurrent_task_service_ipc_interface_code.h"

namespace OHOS {
namespace ConcurrentTask {
class ConcurrentTaskServiceStub : public IRemoteStub<IConcurrentTaskService> {
public:
    ConcurrentTaskServiceStub();
    ~ConcurrentTaskServiceStub();
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;

private:
    int32_t ReportDataInner(MessageParcel& data, MessageParcel& reply);
    int32_t QueryIntervalInner(MessageParcel& data, MessageParcel& reply);
    int32_t QueryDeadlineInner(MessageParcel& data, MessageParcel& reply);
    int32_t RequestAuthInner(MessageParcel& data, MessageParcel& reply);
    Json::Value StringToJson(const std::string& str);

    void Init();

    using RequestFuncType = std::function<int32_t (MessageParcel& data, MessageParcel& reply)>;
    std::map<uint32_t, RequestFuncType> funcMap_;
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK_SEVICES_INCLUDE_CONCURRENT_TASK_SERVICE_STUB_H
