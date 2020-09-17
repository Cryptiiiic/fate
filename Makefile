export ARCHS = arm64 arm64e
export TARGET = iphone:clang:14.0:11.0
DEBUG = 1
FINALPACKAGE = 0
GO_EASY_ON_ME = 1
PACKAGE_VERSION = $(THEOS_PACKAGE_BASE_VERSION)

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ____Fate
____Fate_FILES = Tweak.xm
____Fate_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk

purge::
	@rm -Rf .theos packages
	@find . -name .DS_Store -delete
	$(ECHO_BEGIN)$(PRINT_FORMAT_RED) "Purging"$(ECHO_END); $(ECHO_PIPEFAIL)
