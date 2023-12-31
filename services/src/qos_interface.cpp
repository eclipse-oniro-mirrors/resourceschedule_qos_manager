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

#ifndef GNU_SOURCE
#define GNU_SOURCE
#endif
#include <cstdio>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include "../include/qos_interface.h"

constexpr unsigned int AF_QOS_ALL = 0x0003;
constexpr unsigned int AF_QOS_DELEGATED = 0x0001;

static int TrivalOpenRtgNode(void)
{
    char fileName[] = "/proc/self/sched_rtg_ctrl";
    int fd = open(fileName, O_RDWR);
#ifdef QOS_DEBUG
    if (fd < 0) {
        printf("task %d belong to user %d open rtg node failed\n", getpid(), getuid());
    }
#endif
    return fd;
}

static int TrivalOpenAuthCtrlNode(void)
{
    char fileName[] = "/dev/auth_ctrl";
    int fd = open(fileName, O_RDWR);
#ifdef QOS_DEBUG
    if (fd < 0) {
        printf("task %d belong to user %d open auth node failed\n", getpid(), getuid());
    }
#endif
    return fd;
}

static int TrivalOpenQosCtrlNode(void)
{
    char fileName[] = "/proc/thread-self/sched_qos_ctrl";
    int fd = open(fileName, O_RDWR);
#ifdef QOS_DEBUG
    if (fd < 0) {
        printf("task %d belong to user %d open qos node failed\n", getpid(), getuid());
    }
#endif
    return fd;
}

int EnableRtg(bool flag)
{
    struct RtgEnableData enableData;
    char configStr[] = "load_freq_switch:1;sched_cycle:1;frame_max_util:750";
    int ret;

    enableData.enable = flag;
    enableData.len = sizeof(configStr);
    enableData.data = configStr;
    int fd = TrivalOpenRtgNode();
    if (fd < 0) {
        return fd;
    }

    ret = ioctl(fd, CMD_ID_SET_ENABLE, &enableData);
    if (ret < 0) {
        printf("set rtg config enable failed.\n");
    }

    close(fd);

    return 0;
};

int AuthEnable(unsigned int uid, unsigned int uaFlag, unsigned int status)
{
    struct AuthCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenAuthCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.uid = uid;
    data.rtgUaFlag = uaFlag;
    data.qosUaFlag = AF_QOS_ALL;
    data.status = status;
    data.type = static_cast<unsigned int>(AuthManipulateType::AUTH_ENABLE);

    ret = ioctl(fd, BASIC_AUTH_CTRL_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("auth enable failed for uid %u with status %u\n", uid, status);
    }
#endif
    close(fd);
    return ret;
}

int AuthSwitch(unsigned int uid, unsigned int rtgFlag, unsigned int qosFlag, unsigned int status)
{
    struct AuthCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenAuthCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.uid = uid;
    data.rtgUaFlag = rtgFlag;
    data.qosUaFlag = qosFlag;
    data.status = status;
    data.type = static_cast<unsigned int>(AuthManipulateType::AUTH_SWITCH);

    ret = ioctl(fd, BASIC_AUTH_CTRL_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("auth switch failed for uid %u with status %u\n", uid, status);
    }
#endif
    close(fd);
    return ret;
}

int AuthDelete(unsigned int uid)
{
    struct AuthCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenAuthCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.uid = uid;
    data.type = static_cast<unsigned int>(AuthManipulateType::AUTH_DELETE);

    ret = ioctl(fd, BASIC_AUTH_CTRL_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("auth delete failed for uid %u\n", uid);
    }
#endif
    close(fd);
    return ret;
}

int AuthPause(unsigned int uid)
{
    struct AuthCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenAuthCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.uid = uid;
    data.type = static_cast<unsigned int>(AuthManipulateType::AUTH_SWITCH);
    data.rtgUaFlag = 0;
    data.qosUaFlag = AF_QOS_DELEGATED;
    data.status = static_cast<unsigned int>(AuthStatus::AUTH_STATUS_BACKGROUND);

    ret = ioctl(fd, BASIC_AUTH_CTRL_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("auth pause failed for uid %u\n", uid);
    }
#endif
    close(fd);
    return ret;
}

int AuthGet(unsigned int uid, unsigned int *uaFlag, unsigned int *status)
{
    struct AuthCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenAuthCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.uid = uid;
    data.type = static_cast<unsigned int>(AuthManipulateType::AUTH_GET);

    ret = ioctl(fd, BASIC_AUTH_CTRL_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("auth get failed for uid %u\n", uid);
    }
#endif
    close(fd);

    *uaFlag = data.rtgUaFlag;
    *status = data.status;

    return ret;
}

int QosApply(unsigned int level)
{
    int tid = gettid();
    int ret;

    ret = QosApplyForOther(level, tid);
    return ret;
}

int QosApplyForOther(unsigned int level, int tid)
{
    struct QosCtrlData data;
    int fd;

    int ret;

    fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.level = level;
    data.type = static_cast<unsigned int>(QosManipulateType::QOS_APPLY);
    data.pid = tid;

    ret = ioctl(fd, QOS_CTRL_BASIC_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("qos apply failed for task %d\n", tid);
    }
#endif
    close(fd);
    return ret;
}

int QosLeave(void)
{
    struct QosCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.type = static_cast<unsigned int>(QosManipulateType::QOS_LEAVE);
    data.pid = gettid();

    ret = ioctl(fd, QOS_CTRL_BASIC_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("qos leave failed for task %d\n", getpid());
    }
#endif
    close(fd);
    return ret;
}

int QosLeaveForOther(int tid)
{
    struct QosCtrlData data;
    int fd;
    int ret;

    fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }

    data.type = static_cast<unsigned int>(QosManipulateType::QOS_LEAVE);
    data.pid = tid;

    ret = ioctl(fd, QOS_CTRL_BASIC_OPERATION, &data);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("qos leave failed for task %d\n", tid);
    }
#endif
    close(fd);
    return ret;
}

int QosPolicy(struct QosPolicyDatas *policyDatas)
{
    int fd;
    int ret;

    fd = TrivalOpenQosCtrlNode();
    if (fd < 0) {
        return fd;
    }

    ret = ioctl(fd, QOS_CTRL_POLICY_OPERATION, policyDatas);
#ifdef QOS_DEBUG
    if (ret < 0) {
        printf("set qos policy failed for task %d\n", getpid());
    }
#endif
    close(fd);
    return ret;
}
