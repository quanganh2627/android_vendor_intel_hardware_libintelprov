LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_C_INCLUDES:=  $(LOCAL_PATH)/../lib/include

LOCAL_SRC_FILES:= \
	partlink.c

LOCAL_STATIC_LIBRARIES := libcgpt

LOCAL_MODULE:=partlink

LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)

