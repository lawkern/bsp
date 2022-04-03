APPLICATION_PORT = 6969
REQUEST_THREAD_COUNT = 4

CODE_PATH  = ../code
DATA_PATH  = ../data
MISC_PATH  = ../misc
BUILD_PATH = ../build

PACKAGE_PATH = $(BUILD_PATH)/bsp-package
DEPLOYMENT_PATH = /srv/bsp

CC      = clang
LDFLAGS = -lfcgi -lpthread

CFLAGS  = -Wall -Werror -Wno-unused-function
CFLAGS += -DWORKING_DIRECTORY=$(DEPLOYMENT_PATH)
CFLAGS += -DREQUEST_THREAD_COUNT=$(REQUEST_THREAD_COUNT)

ifeq ($(CC), clang)
	CFLAGS += -fdiagnostics-absolute-paths
endif

CFLAGS_DEVELOPMENT = $(CFLAGS) -O0 -g -DDEVELOPMENT_BUILD=1  -Wno-unused-variable
CFLAGS_PRODUCTION  = $(CFLAGS) -O2    -DDEVELOPMENT_BUILD=0

MAKEFLAGS += --no-print-directory

development::
	@echo "====================="
	@echo "BSP Development Build"
	@echo "====================="
	@mkdir -p $(BUILD_PATH)
	@$(CC) platform_linux.c -o $(BUILD_PATH)/bsp $(CFLAGS_DEVELOPMENT) $(LDFLAGS)
	@make package
	@make deploy

production::
	@echo "===================="
	@echo "BSP Production Build"
	@echo "===================="
	@mkdir -p $(BUILD_PATH)
	@$(CC) platform_linux.c -o $(BUILD_PATH)/bsp $(CFLAGS_PRODUCTION) $(LDFLAGS)
	@make package
	@make deploy

package::
	@rm -rf   $(PACKAGE_PATH)
	@mkdir -p $(PACKAGE_PATH)/css
	@mkdir -p $(PACKAGE_PATH)/html
	@mkdir -p $(PACKAGE_PATH)/logs
	@mkdir -p $(PACKAGE_PATH)/misc
	@cp    $(BUILD_PATH)/bsp   $(PACKAGE_PATH)/
	@cp -r $(DATA_PATH)/css/*  $(PACKAGE_PATH)/css/
	@cp -r $(DATA_PATH)/html/* $(PACKAGE_PATH)/html/
	@cp -r $(MISC_PATH)/*      $(PACKAGE_PATH)/misc/

deploy::
	@rm -rf $(DEPLOYMENT_PATH)/bsp
	@cp -r $(PACKAGE_PATH)/* $(DEPLOYMENT_PATH)/
	@bash -c "$(DEPLOYMENT_PATH)/misc/restart_bsp.sh $(APPLICATION_PORT) $(DEPLOYMENT_PATH)/bsp"
