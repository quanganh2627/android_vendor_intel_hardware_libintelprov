LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

common_libintelprov_files := \
	update_osip.c \
	modem_fw.c \
	fw_version_check.c \
	util.c \
	flash_ifwi.c \
	modem_nvm.c

common_libintelprov_includes := \
	hardware/intel/PRIVATE/cmfwdl/lib/cmfwdl \
	bionic/libc/private

# Plug-in library for AOSP updater
include $(CLEAR_VARS)
LOCAL_MODULE := libintel_updater
LOCAL_SRC_FILES := updater.c $(common_libintelprov_files)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_C_INCLUDES := bootable/recovery $(common_libintelprov_includes)
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter
include $(BUILD_STATIC_LIBRARY)

# plugin for recovery_ui
include $(CLEAR_VARS)
LOCAL_SRC_FILES := recovery_ui.cpp
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := bootable/recovery bionic/libc/private
LOCAL_MODULE := libintel_recovery_ui
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter
ifeq ($(REF_DEVICE_NAME), mfld_pr2)
LOCAL_CFLAGS += -DMFLD_PRX_KEY_LAYOUT
endif
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := releasetools
LOCAL_MODULE_TAGS := optional
LOCAL_PREBUILT_EXECUTABLES := \
    releasetools.py \
    releasetools/ota_from_target_files \
    releasetools/check_target_files_signatures \
    releasetools/common.py \
    releasetools/edify_generator.py \
    releasetools/lfstk_wrapper.py \
    releasetools/mfld_osimage.py \
    releasetools/sign_target_files_apks \
    releasetools/product_name_mapping.def
include $(BUILD_HOST_PREBUILT)

# if DROIDBOOT is not used, we dont want this...
# allow to transition smoothly
ifeq ($(TARGET_USE_DROIDBOOT),true)

# Plug-in libary for Droidboot
include $(CLEAR_VARS)
LOCAL_MODULE := libintel_droidboot
LIBCGPT_FILES := \
	gpt/lib/cgpt_add.c \
	gpt/lib/cgpt_boot.c \
	gpt/lib/cgpt_common.c \
	gpt/lib/cgpt_create.c \
	gpt/lib/cgpt_find.c \
	gpt/lib/cgpt_legacy.c \
	gpt/lib/cgptlib_internal.c \
	gpt/lib/cgpt_prioritize.c \
	gpt/lib/cgpt_repair.c \
	gpt/lib/cgpt_show.c \
	gpt/lib/crc32.c \
	gpt/lib/utility_stub.c \
	gpt/lib/cmd_add.c \
	gpt/lib/cmd_boot.c \
	gpt/lib/cmd_create.c \
	gpt/lib/cmd_find.c \
	gpt/lib/cmd_legacy.c \
	gpt/lib/cmd_prioritize.c \
	gpt/lib/cmd_repair.c \
	gpt/lib/cmd_reload.c \
	gpt/lib/cmd_show.c

LOCAL_SRC_FILES := droidboot.c update_partition.c $(common_libintelprov_files) $(LIBCGPT_FILES)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_C_INCLUDES := bootable/droidboot bootable/droidboot/volumeutils bootable/recovery $(common_libintelprov_includes) $(LOCAL_PATH)/gpt/lib/include
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter -Wno-unused-but-set-variable
ifneq ($(DROIDBOOT_NO_GUI),true)
LOCAL_CFLAGS += -DUSE_GUI
endif
ifeq ($(TARGET_BOARD_PLATFORM),clovertrail)
  LOCAL_CFLAGS += -DCLVT
endif
ifeq ($(TARGET_BOARD_PLATFORM),merrifield)
  LOCAL_CFLAGS += -DMRFLD
endif

include $(BUILD_STATIC_LIBRARY)

# a test flashtool for testing the intelprov library
include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := eng
LOCAL_MODULE := flashtool
LOCAL_SHARED_LIBRARIES := liblog libcutils
LOCAL_STATIC_LIBRARIES := libcmfwdl
LOCAL_C_INCLUDES := $(common_libintelprov_includes) bootable/recovery
LOCAL_SRC_FILES:= flashtool.c $(common_libintelprov_files)
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter
include $(BUILD_EXECUTABLE)

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

include $(call all-makefiles-under,$(LOCAL_PATH))
