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

#ifndef CONCURRENT_TASK_COMMON_INCLUDE_IPC_UTIL_H
#define CONCURRENT_TASK_COMMON_INCLUDE_IPC_UTIL_H

#include "concurrent_task_log.h"

namespace OHOS {
namespace ConcurrentTask {

#define READ_PARCEL(parcel, type, out, errReturn, className)                    \
    do {                                                                        \
        if (!(parcel).Read##type(out)) {                                        \
            CONCUR_LOGE(""#className"::%{public}s read"#out" failed", __func__); \
            return errReturn;                                                   \
        }                                                                       \
    } while (0)                                                                 \

#define WRITE_PARCEL(parcel, type, in, errReturn, className)                    \
    do {                                                                        \
        if (!(parcel).Write##type(in)) {                                        \
            CONCUR_LOGE(""#className"::%{public}s write"#in" failed", __func__); \
            return errReturn;                                                   \
        }                                                                       \
    } while (0)

} // namespace ConcurrentTask
} // namespace OHOS

#endif // CONCURRENT_TASK_COMMON_INCLUDE_IPC_UTIL_H
