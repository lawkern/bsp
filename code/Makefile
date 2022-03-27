DEVELOPMENT_BUILD = 1
REQUEST_THREAD_COUNT = 4
APPLICATION_PORT = 6969

CODE_PATH  = ../code
DATA_PATH  = ../data
MISC_PATH  = ../misc
BUILD_PATH = ../build

CC      = clang
CFLAGS  = $(WARNING_FLAGS)                             \
	-DDEVELOPMENT_BUILD=$(DEVELOPMENT_BUILD)       \
	-DREQUEST_THREAD_COUNT=$(REQUEST_THREAD_COUNT) \
	-DWORKING_DIRECTORY=$(DATA_PATH)
LDFLAGS = -lfcgi -lpthread

WARNING_FLAGS = -Wall -Werror

ifeq ($(DEVELOPMENT_BUILD), 1)
	CFLAGS += -g -O0
	WARNING_FLAGS += -Wno-unused-function -Wno-unused-variable -Wno-missing-braces
else
	CFLAGS += -O2
endif

ifeq ($(CC), clang)
	CFLAGS += -fdiagnostics-absolute-paths
endif

bsp::
	@bash -c "$(MISC_PATH)/bsp_kill.sh $(APPLICATION_PORT)"
	@mkdir -p $(BUILD_PATH)
	@$(CC) platform_linux.c -o $(BUILD_PATH)/$@ $(CFLAGS) $(LDFLAGS)
	@bash -c "$(MISC_PATH)/bsp_start.sh $(APPLICATION_PORT)"
