LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := monitorSVC
LOCAL_SRC_FILES := ../attach.c
LOCAL_ARM_MODE := arm
LOCAL_CFLAGS := -g -pie -fPIE
LOCAL_LDFLAGS += -pie -fPIE
include $(BUILD_EXECUTABLE)
