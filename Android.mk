LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := chall/crypto.c chall/crypto-openssl.c chall/config-xml.c chall/config-lua.c chall/configuration.c \
	chall/crypto-algo.c \
	log.c mm.c list.c
LOCAL_MODULE := libchall
LOCAL_CFLAGS := -Wall -Wno-unused-parameter -Werror -DHAVE_LIBXML -DANDROID
LOCAL_SHARED_LIBRARIES := libcrypto libxml2 libicuuc libdch
LOCAL_PREBUILT_OBJ_FILES := config.xml
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

LOCAL_MODULE := config.xml
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/etc/libchall
LOCAL_SRC_FILES := config.xml

include $(BUILD_PREBUILT)

