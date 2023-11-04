APPLICATION_PORT = 6969
REQUEST_THREAD_COUNT = 8

CODE_PATH  = ../code
DATA_PATH  = ../data
MISC_PATH  = ../misc
BUILD_PATH = ../build

PACKAGE_PATH = $(BUILD_PATH)/bsp-package
DEPLOYMENT_PATH = /srv/bsp

CC      = clang
LDFLAGS = -lfcgi -lpthread

CFLAGS  = -Wall -Werror -Wno-unused-function -Wno-deprecated-declarations
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

	@$(CC) bsp.c -o $(BUILD_PATH)/bsp.o -c -std=c99 $(CFLAGS_DEVELOPMENT)
	@$(CC) platform_linux.c -o $(BUILD_PATH)/platform_linux.o -c -std=gnu99 $(CFLAGS_DEVELOPMENT)

	@make link
	@make package
	@make deploy

production::
	@echo "===================="
	@echo "BSP Production Build"
	@echo "===================="
	@mkdir -p $(BUILD_PATH)

	@$(CC) bsp.c -o $(BUILD_PATH)/bsp.o -c -std=c99 $(CFLAGS_PRODUCTION)
	@$(CC) platform_linux.c -o $(BUILD_PATH)/platform_linux.o -c -std=gnu99 $(CFLAGS_PRODUCTION)

	@make link
	@make package
	@make deploy

link::
	@$(CC) $(BUILD_PATH)/platform_linux.o $(BUILD_PATH)/bsp.o -o $(BUILD_PATH)/bsp $(LDFLAGS)

package::
	@mkdir -p $(DEPLOYMENT_PATH)
	@mkdir -p $(DEPLOYMENT_PATH)/css
	@mkdir -p $(DEPLOYMENT_PATH)/html
	@mkdir -p $(DEPLOYMENT_PATH)/logs

	@rm $(DEPLOYMENT_PATH)/bsp

	@cp    $(BUILD_PATH)/bsp        $(DEPLOYMENT_PATH)/
	@cp    $(DATA_PATH)/favicon.ico $(DEPLOYMENT_PATH)/
	@cp -r $(DATA_PATH)/css/*       $(DEPLOYMENT_PATH)/css/
	@cp -r $(DATA_PATH)/html/*      $(DEPLOYMENT_PATH)/html/

deploy::
	@bash -c "$(MISC_PATH)/restart_bsp.sh $(APPLICATION_PORT) $(DEPLOYMENT_PATH)/bsp"
