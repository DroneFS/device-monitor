LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := chall/configuration.c chall/chall.c chall/config-lua.c chall/config-xml.c \
	chall/crypto.c chall/crypto-algo.c chall/crypto-openssl.c \
	chall/formatter-xml.c \
	chall/base64.c \
	log.c list.c mm.c
LOCAL_MODULE := libchall
LOCAL_CFLAGS := -Wall -Wno-unused-parameter -Werror -DHAVE_LIBXML # -DANDROID
LOCAL_SHARED_LIBRARIES := libcrypto libxml2 libicuuc libdl libdch libdch2
LOCAL_REQUIRED_MODULES := config.xml
LOCAL_C_INCLUDES := external/libxml2/include
INCLUDES := external/libxml2/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
# Uncomment these for debugging:
# LOCAL_CFLAGS += -ggdb
# LOCAL_STRIP_MODULE = false
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := linux/dummy-challenge.c
LOCAL_MODULE := libdch
LOCAL_CFLAGS := -Wall -Wno-unused-parameter -Werror
# LOCAL_CFLAGS += -ggdb
# LOCAL_STRIP_MODULE := false
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := linux/dummy-challenge-2.c
LOCAL_MODULE := libdch2
LOCAL_CFLAGS := -Wall -Wno-unused-parameter -Werror
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := config.xml
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/libchall
LOCAL_SRC_FILES := config.xml
include $(BUILD_PREBUILT)

