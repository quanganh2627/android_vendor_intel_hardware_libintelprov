LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := format_misc.c
LOCAL_MODULE := format_misc
LOCAL_C_INCLUDES := system/core/libvolumeutils
LOCAL_SHARED_LIBRARIES := libvolumeutils

include $(BUILD_EXECUTABLE)
