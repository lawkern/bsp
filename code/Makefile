APPLICATION_PORT = 6969
REQUEST_THREAD_COUNT = 4

CODE_PATH  = ../code
DATA_PATH  = ../data
MISC_PATH  = ../misc
BUILD_PATH = ../build

PACKAGE_PATH = $(BUILD_PATH)/bsp-package
PRODUCTION_PATH = /srv/bsp

CC      = clang
CFLAGS  = -Wall -Werror -Wno-unused-function -DREQUEST_THREAD_COUNT=$(REQUEST_THREAD_COUNT)
LDFLAGS = -lfcgi -lpthread

ifeq ($(CC), clang)
	CFLAGS += -fdiagnostics-absolute-paths
endif

CFLAGS_DEVELOPMENT = $(CFLAGS) -O0 -g -DDEVELOPMENT_BUILD=1 -DWORKING_DIRECTORY=$(DATA_PATH) -Wno-unused-variable
CFLAGS_PRODUCTION  = $(CFLAGS) -O2    -DDEVELOPMENT_BUILD=0 -DWORKING_DIRECTORY=$(PRODUCTION_PATH)

development::
	@echo "====================="
	@echo "BSP Development Build"
	@echo "====================="
	@mkdir -p $(BUILD_PATH)
	@$(CC) platform_linux.c -o $(BUILD_PATH)/bsp $(CFLAGS_DEVELOPMENT) $(LDFLAGS)
	@bash -c "$(MISC_PATH)/restart_bsp.sh $(APPLICATION_PORT) $(BUILD_PATH)/bsp"

production::
	@echo "===================="
	@echo "BSP Production Build"
	@echo "===================="
	@rm -rf $(PACKAGE_PATH)
	@rm -rf $(PRODUCTION_PATH)/bsp
	@mkdir -p $(PACKAGE_PATH)
	@$(CC) platform_linux.c -o $(PACKAGE_PATH)/bsp $(CFLAGS_PRODUCTION) $(LDFLAGS)
	@mkdir -p $(PACKAGE_PATH)/css
	@mkdir -p $(PACKAGE_PATH)/html
	@mkdir -p $(PACKAGE_PATH)/logs
	@mkdir -p $(PACKAGE_PATH)/misc
	@cp -r $(DATA_PATH)/css/*  $(PACKAGE_PATH)/css/
	@cp -r $(DATA_PATH)/html/* $(PACKAGE_PATH)/html/
	@cp -r $(MISC_PATH)/*      $(PACKAGE_PATH)/misc/
	@cp -r $(PACKAGE_PATH)/* $(PRODUCTION_PATH)/
	@bash -c "$(PRODUCTION_PATH)/misc/restart_bsp.sh $(APPLICATION_PORT) $(PRODUCTION_PATH)/bsp"
