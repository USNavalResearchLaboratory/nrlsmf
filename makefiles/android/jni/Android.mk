LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := nrlsmf
LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/../../../protolib/include \
	$(LOCAL_PATH)/../../../include
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_C_INCLUDES)
LOCAL_STATIC_LIBRARIES := protolib

ifeq ($(APP_OPTIM),debug)
	LOCAL_CFLAGS += -DANDROID
endif
LOCAL_EXPORT_CFLAGS := $(LOCAL_CFLAGS)

LOCAL_SRC_FILES := \
	../../../src/common/nrlsmf.cpp \
	../../../src/common/smf.cpp \
	../../../src/common/smfDpd.cpp \
	../../../src/common/smfHash.cpp \
	../../../src/common/smfHashMD5.cpp \
	../../../src/common/smfHashSHA1.cpp \
	../../../src/common/smfQueue.cpp \
	../../../protolib/src/linux/linuxCap.cpp \
	../../../protolib/src/common/protoVif.cpp \
	../../../protolib/src/unix/unixVif.cpp
include $(BUILD_EXECUTABLE)

$(call import-module,protolib/makefiles/android/jni)
