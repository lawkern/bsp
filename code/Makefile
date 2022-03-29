APPLICATION_PORT = 6969
REQUEST_THREAD_COUNT = 4

CODE_PATH  = ../code
DATA_PATH  = ../data
MISC_PATH  = ../misc
BUILD_PATH = ../build

CC      = clang
CFLAGS  = -Wall -Werror -DREQUEST_THREAD_COUNT=$(REQUEST_THREAD_COUNT) -DWORKING_DIRECTORY=$(DATA_PATH)
LDFLAGS = -lfcgi -lpthread

ifeq ($(CC), clang)
	CFLAGS += -fdiagnostics-absolute-paths
endif

CFLAGS_DEVELOPMENT = $(CFLAGS) -DDEVELOPMENT_BUILD=1 -O0 -g -Wno-unused-function -Wno-unused-variable
CFLAGS_PRODUCTION  = $(CFLAGS) -DDEVELOPMENT_BUILD=0 -O2 -Wno-unused-function

development::
	@echo "BSP Development Build"
	@echo "====================="
	@bash -c "$(MISC_PATH)/bsp_kill.sh $(APPLICATION_PORT)"
	@mkdir -p $(BUILD_PATH)
	@$(CC) platform_linux.c -o $(BUILD_PATH)/bsp $(CFLAGS_DEVELOPMENT) $(LDFLAGS)
	@bash -c "$(MISC_PATH)/bsp_start.sh $(APPLICATION_PORT)"

production::
	@echo "BSP Production Build"
	@echo "===================="
	@bash -c "$(MISC_PATH)/bsp_kill.sh $(APPLICATION_PORT)"
	@mkdir -p $(BUILD_PATH)
	@$(CC) platform_linux.c -o $(BUILD_PATH)/bsp $(CFLAGS_PRODUCTION) $(LDFLAGS)
	@bash -c "$(MISC_PATH)/bsp_start.sh $(APPLICATION_PORT)"
