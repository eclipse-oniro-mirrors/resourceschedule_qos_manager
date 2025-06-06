/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CONCURRENT_TASK_SEVICES_INCLUDE_FUNC_LOADER_H
#define CONCURRENT_TASK_SEVICES_INCLUDE_FUNC_LOADER_H

#include <string>

namespace OHOS {
namespace ConcurrentTask {
class FuncLoader {
public:
    FuncLoader(const std::string& funcImplPath);
    ~FuncLoader();
    void* LoadSymbol(const char* sysName);
    bool GetLoadSuccess();

private:
    void LoadFile(const char* fileName);
    std::string funcImplPath_;
    void* fileHandle_ = nullptr;
    bool enable_ = false;
};
} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK_SEVICES_INCLUDE_FUNC_LOADER_H
