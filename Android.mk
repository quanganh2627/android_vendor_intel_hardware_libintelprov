LOCAL_PATH := $(call my-dir)

LIBCHAABI := $(TOP)/vendor/intel/hardware/PRIVATE/chaabi
ifeq ($(wildcard $(LIBCHAABI)),)
	external_release := yes
else
	external_release := no
endif

include $(CLEAR_VARS)

common_pmdb_files := \
	pmdb-access-sep.c \
	pmdb.c

token_implementation := \
	token.c

ifeq ($(MIU_RMC_FLASHLESS),true)
USE_FLASHLESS_FILES := true
else ifeq ($(MIU_IMC_FLASHLESS),true)
USE_FLASHLESS_FILES := true
endif

common_libintelprov_files := \
	update_osip.c \
	fw_version_check.c \
	util.c \
	flash_ifwi.c \

ifneq ($(USE_FLASHLESS_FILES),true)
common_libintelprov_files += \
	modem_fw.c \
	modem_nvm.c
endif

common_libintelprov_includes := \
	bionic/libc/private \

ifneq ($(USE_FLASHLESS_FILES),true)
common_libintelprov_includes += \
	vendor/intel/hardware/PRIVATE/cmfwdl/lib/cmfwdl
else
common_libintelprov_includes += \
	$(TARGET_OUT_HEADERS)/IFX-modem
endif

chaabi_dir := $(TOP)/vendor/intel/hardware/PRIVATE/chaabi
sep_lib_includes := $(chaabi_dir)/SepMW/VOS6/External/Linux/inc/

# Plug-in library for AOSP updater
include $(CLEAR_VARS)
LOCAL_MODULE := libintel_updater
ifneq ($(USE_FLASHLESS_FILES),true)
LOCAL_SRC_FILES := updater.c $(common_libintelprov_files)
else
LOCAL_SRC_FILES := updater_flashless.c $(common_libintelprov_files)
endif
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_C_INCLUDES := bootable/recovery $(common_libintelprov_includes)
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter
ifeq ($(TARGET_BOARD_PLATFORM),clovertrail)
  LOCAL_CFLAGS += -DCLVT
endif
ifneq ($(USE_FLASHLESS_FILES),true)
LOCAL_WHOLE_STATIC_LIBRARIES := libcmfwdl
else
LOCAL_WHOLE_STATIC_LIBRARIES := libmiu
endif
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

LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter -Wno-unused-but-set-variable
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := STATIC_LIBRARIES

LOCAL_C_INCLUDES := bootable/droidboot bootable/droidboot/volumeutils bootable/recovery $(common_libintelprov_includes) $(LOCAL_PATH)/gpt/lib/include

LOCAL_SRC_FILES := update_partition.c $(common_libintelprov_files) $(LIBCGPT_FILES)

ifneq ($(USE_FLASHLESS_FILES),true)
LOCAL_SRC_FILES += droidboot.c
else
LOCAL_SRC_FILES += droidboot_flashless.c
endif

ifeq ($(external_release),no)
LOCAL_SRC_FILES += $(common_pmdb_files) $(token_implementation)
LOCAL_C_INCLUDES += $(sep_lib_includes)
LOCAL_WHOLE_STATIC_LIBRARIES := libsecurity_sectoken libcrypto_static CC6_UMIP_ACCESS CC6_ALL_BASIC_LIB
else
LOCAL_CFLAGS += -DEXTERNAL
endif

ifneq ($(USE_FLASHLESS_FILES),true)
LOCAL_WHOLE_STATIC_LIBRARIES += libcmfwdl
else
LOCAL_WHOLE_STATIC_LIBRARIES += libmiu
endif

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
ifneq ($(USE_FLASHLESS_FILES),true)
LOCAL_STATIC_LIBRARIES := libcmfwdl
else
LOCAL_STATIC_LIBRARIES := libmiu
endif
LOCAL_C_INCLUDES := $(common_libintelprov_includes) bootable/recovery
ifneq ($(USE_FLASHLESS_FILES),true)
LOCAL_SRC_FILES := flashtool.c $(common_libintelprov_files)
else
LOCAL_SRC_FILES := flashtool_flashless.c $(common_libintelprov_files)
endif
LOCAL_CFLAGS := -Wall -Werror -Wno-unused-parameter
ifeq ($(TARGET_BOARD_PLATFORM),clovertrail)
  LOCAL_CFLAGS += -DCLVT
endif

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
