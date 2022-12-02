# GNU Make workspace makefile autogenerated by Premake
MQTT_C_SOURCES = src/mqtt.c src/mqtt_pal.c
MQTT_C_EXAMPLES = bin/simple_publisher bin/simple_subscriber bin/reconnect_subscriber bin/bio_publisher bin/openssl_publisher
MQTT_C_UNITTESTS = bin/tests
BINDIR = bin

ifndef config
  config=linux
endif

ifndef verbose
  SILENT = @
endif

ifeq ($(config),linux)
  DNPSlave_config = linux
  dnp_config = linux
  utils_config = linux
  IoTarg_config = linux
endif
ifeq ($(config),sample)
  DNPSlave_config = sample
  dnp_config = sample
  utils_config = sample
  IoTarg_config = sample
endif

PROJECTS := DNPSlave dnp utils IoTarg BINDIR MQTT_C_UNITTESTS MQTT_C_EXAMPLES

.PHONY: all clean help $(PROJECTS) 

all: $(PROJECTS)

DNPSlave: dnp utils IoTarg
ifneq (,$(DNPSlave_config))
	@echo "==== Building DNPSlave ($(DNPSlave_config)) ===="
	@${MAKE} --no-print-directory -C DNPSlave -f Makefile config=$(DNPSlave_config)
endif

dnp:
ifneq (,$(dnp_config))
	@echo "==== Building dnp ($(dnp_config)) ===="
	@${MAKE} --no-print-directory -C tmwscl/dnp -f Makefile config=$(dnp_config)
endif

utils:
ifneq (,$(utils_config))
	@echo "==== Building utils ($(utils_config)) ===="
	@${MAKE} --no-print-directory -C tmwscl/utils -f Makefile config=$(utils_config)
endif

IoTarg:
ifneq (,$(IoTarg_config))
	@echo "==== Building IoTarg ($(IoTarg_config)) ===="
	@${MAKE} --no-print-directory -C tmwscl/tmwtarg -f Makefile config=$(IoTarg_config)
endif


bin/simple_%: examples/simple_%.c $(MQTT_C_SOURCES)
	$(CC) $(CFLAGS) $^ -lpthread $(MSFLAGS) -o $@

bin/reconnect_%: examples/reconnect_%.c $(MQTT_C_SOURCES)
	$(CC) $(CFLAGS) $^ -lpthread $(MSFLAGS) -o $@

bin/bio_%: examples/bio_%.c $(MQTT_C_SOURCES)
	$(CC) $(CFLAGS) `pkg-config --cflags openssl` -D MQTT_USE_BIO $^ -lpthread $(MSFLAGS) `pkg-config --libs openssl` -o $@

bin/openssl_%: examples/openssl_%.c $(MQTT_C_SOURCES)
	$(CC) $(CFLAGS) `pkg-config --cflags openssl` -D MQTT_USE_BIO $^ -lpthread $(MSFLAGS) `pkg-config --libs openssl` -o $@

$(BINDIR):
	mkdir -p $(BINDIR)

$(MQTT_C_UNITTESTS): tests.c $(MQTT_C_SOURCES)
	$(CC) $(CFLAGS) $^ -lcmocka $(MSFLAGS) -o $@
	
	

clean:
	@${MAKE} --no-print-directory -C DNPSlave -f Makefile clean
	@${MAKE} --no-print-directory -C tmwscl/dnp -f Makefile clean
	@${MAKE} --no-print-directory -C tmwscl/utils -f Makefile clean
	@${MAKE} --no-print-directory -C tmwscl/tmwtarg -f Makefile clean
	rm -rf $(BINDIR)

help:
	@echo "Usage: make [config=name] [target]"
	@echo ""
	@echo "CONFIGURATIONS:"
	@echo "  linux"
	@echo "  sample"
	@echo ""
	@echo "TARGETS:"
	@echo "   all (default)"
	@echo "   clean"
	@echo "   DNPSlave"
	@echo "   dnp"
	@echo "   utils"
	@echo "   IoTarg"
	@echo ""
	@echo "For more information, see http://industriousone.com/premake/quick-start"
	
	
UNAME = $(shell uname -o)

CC = gcc
CFLAGS = -Wextra -Wall -std=gnu99 -Iinclude -Wno-unused-parameter -Wno-unused-variable -Wno-duplicate-decl-specifier

ifeq ($(UNAME), Msys)
MSFLAGS = -lws2_32
endif
