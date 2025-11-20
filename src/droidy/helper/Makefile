ANDROID_API_LEVEL ?= 21
ANDROID_SDK_ROOT ?= $(shell echo ~/Library/Android/sdk)

android_platform := android-$(ANDROID_API_LEVEL)
android_jar := $(ANDROID_SDK_ROOT)/platforms/$(android_platform)/android.jar

build/plawnekjx-helper.dex: build/plawnekjx-helper.jar
	dx --dex --output=$@ $<

build/plawnekjx-helper.jar: re/plawnekjx/Helper.java
	javac \
		-cp .:$(android_jar) \
		-bootclasspath $(android_jar) \
		-source 1.8 \
		-target 1.8 \
		-Xlint:deprecation \
		-Xlint:unchecked \
		$^ \
		-d build/java/
	jar cfe $@ re.plawnekjx.Helper -C build/java/ .
