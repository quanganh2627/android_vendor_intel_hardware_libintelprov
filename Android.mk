# if DROIDBOOT is not used, we dont want this...
# allow to transition smoothly
ifeq ($(TARGET_USE_DROIDBOOT),true)

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

common_libintelprov_files := \
	update_osip.c \
	modem_fw.c \
	fw_version_check.c \
	util.c \
	flash_ifwi.c \

common_libintelprov_includes := \
	hardware/intel/PRIVATE/libcmfwdl/cmfwdl \
	bionic/libc/private


# Plug-in library for AOSP updater
include $(CLEAR_VARS)
LOCAL_MODULE := libintel_updater
LOCAL_SRC_FILES := updater.c $(common_libintelprov_files)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_C_INCLUDES := bootable/recovery $(common_libintelprov_includes)
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter
ifeq ($(TARGET_PRODUCT),ctp_pr0)
LOCAL_CFLAGS += -DCLVT
else ifeq ($(TARGET_PRODUCT),ctp_pr1)
LOCAL_CFLAGS += -DCLVT
endif
include $(BUILD_STATIC_LIBRARY)

# Plug-in libary for Droidboot
include $(CLEAR_VARS)
LOCAL_MODULE := libintel_droidboot
LOCAL_SRC_FILES := droidboot.c $(common_libintelprov_files)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_C_INCLUDES := bootable/droidboot bootable/recovery $(common_libintelprov_includes)
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter -Wno-unused-but-set-variable
ifneq ($(DROIDBOOT_NO_GUI),true)
LOCAL_CFLAGS += -DUSE_GUI
endif
ifeq ($(TARGET_PRODUCT),ctp_pr0)
LOCAL_CFLAGS += -DCLVT
else ifeq ($(TARGET_PRODUCT),ctp_pr1)
LOCAL_CFLAGS += -DCLVT
endif
include $(BUILD_STATIC_LIBRARY)

# a test flashtool for testing the intelprov library
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := eng
LOCAL_MODULE := flashtool
LOCAL_SHARED_LIBRARIES := liblog libcutils
LOCAL_STATIC_LIBRARIES := libcmfwdl
LOCAL_C_INCLUDES := $(common_libintelprov_includes)
LOCAL_SRC_FILES:= flashtool.c $(common_libintelprov_files)
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter
ifeq ($(TARGET_PRODUCT),ctp_pr0)
LOCAL_CFLAGS += -DCLVT
else ifeq ($(TARGET_PRODUCT),ctp_pr1)
LOCAL_CFLAGS += -DCLVT
endif
include $(BUILD_EXECUTABLE)

# plugin for recovery_ui
include $(CLEAR_VARS)
LOCAL_SRC_FILES := recovery_ui.c bootloader.c
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := bootable/recovery bionic/libc/private
LOCAL_MODULE := libintel_recovery_ui
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter
ifneq (, $(filter $(TARGET_PRODUCT), mfld_cdk mfld_pr1 mfld_pr2))
LOCAL_CFLAGS += -DMFLD_PRX_KEY_LAYOUT
endif
include $(BUILD_STATIC_LIBRARY)

# update_recovery: this binary is updating the recovery from MOS
# because we dont want to update it from itself.
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE := update_recovery
LOCAL_SRC_FILES:= update_recovery.c util.c update_osip.c
LOCAL_C_INCLUDES := $(common_libintelprov_includes) bootable/recovery/applypatch bootable/recovery
LOCAL_CFLAGS := -Wall -Wno-unused-parameter
LOCAL_SHARED_LIBRARIES := liblog libcutils libz
LOCAL_STATIC_LIBRARIES := libmincrypt libapplypatch libbz
include $(BUILD_EXECUTABLE)
endif

