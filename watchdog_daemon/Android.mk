# Copyright 2009 - 2010 (c) Intel Corporation. All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq ($(BUILD_WITH_WATCHDOG_DAEMON_SUPPORT),true)

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_FORCE_STATIC_EXECUTABLE := true

LOCAL_C_INCLUDES += hardware/intel/include
LOCAL_C_INCLUDES += bionic/libc/kernel/common/
LOCAL_C_INCLUDES += hardware/intel/linux-2.6/include
LOCAL_CFLAGS += -g -Wall
LOCAL_SRC_FILES:= watchdogd.c
LOCAL_MODULE := watchdogd
LOCAL_STATIC_LIBRARIES := libcutils libc
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)

endif
