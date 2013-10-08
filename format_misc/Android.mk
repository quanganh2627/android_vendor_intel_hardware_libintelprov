LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := format_misc.c
LOCAL_MODULE := format_misc
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_C_INCLUDES := system/core/libvolumeutils system/core/mtdutils bionic/libc/private
LOCAL_STATIC_LIBRARIES := libc libcutils liblog libvolumeutils_static libmtdutils

include $(BUILD_EXECUTABLE)

