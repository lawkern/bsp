DEVELOPMENT_BUILD = 1
APPLICATION_PORT = 6969

CC      = clang
CFLAGS  = -DDEVELOPMENT_BUILD=$(DEVELOPMENT_BUILD) $(WARNING_FLAGS)
LDFLAGS = -lfcgi

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

CODE_PATH  = ../code
DATA_PATH  = ../data
MISC_PATH  = ../misc
BUILD_PATH = ../build

bsp::
	@bash -c "$(MISC_PATH)/bsp_kill.sh $(APPLICATION_PORT)"
	@mkdir -p $(BUILD_PATH)
	@$(CC) platform_linux.c -o $(BUILD_PATH)/$@ $(CFLAGS) $(LDFLAGS)
	@bash -c "$(MISC_PATH)/bsp_start.sh $(APPLICATION_PORT)"
