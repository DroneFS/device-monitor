LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := crypto.c crypto-openssl.c mm.c list.c config-xml.c configuration.c
LOCAL_MODULE := libchall
LOCAL_CFLAGS := -Wall -Wno-unused-parameter -Werror -DHAVE_LIBXML
# LOCAL_CFLAGS += -ggdb
LOCAL_SHARED_LIBRARIES := libchall
# LOCAL_STRIP_MODULE = false

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := dummy-challenge.c
LOCAL_MODULE := libdch
LOCAL_CFLAGS := -Wall -Wno-unused-parameter -Werror
# LOCAL_CFLAGS += -ggdb
# LOCAL_STRIP_MODULE := false
include $(BUILD_SHARED_LIBRARY)

