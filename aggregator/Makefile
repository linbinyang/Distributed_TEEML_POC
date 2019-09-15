# SGX environment
SGX_SDK ?= /home/SGXSDK/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
	SGX_UAE_SERVICE_LIB:=sgx_uae_service_sim
else
	Urts_Library_Name := sgx_urts
	SGX_UAE_SERVICE_LIB:=sgx_uae_service
endif

# End of SGX environment

EXECUTABLE=kmservice

OPENSSL=/opt/openssl/1.0.1i

CFLAGS=-Wall -I. -I../common -I$(SGX_SDK)/include -fno-builtin-memset -I$(OPENSSL)/include -g -O0
C_SOURCES=base64.c hexutil.c enclave_u.c zeromqio.c readdata.c readconfig.c fileload.c app.c
C_OBJECTS=$(C_SOURCES:.c=.o)

CPPFLAGS=$(CFLAGS) -std=c++11
CPP_SOURCES=common.cpp msgio.cpp main.cpp
CPP_OBJECTS=$(CPP_SOURCES:.cpp=.o)

LDFLAGS := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lsgx_ukey_exchange -l$(SGX_UAE_SERVICE_LIB) -lpthread -L$(OPENSSL)/lib -lcrypto -lzmq -ldl

.phony: all build_enclave

all: build_enclave $(EXECUTABLE)
	@echo "Done"

$(EXECUTABLE): $(C_OBJECTS) $(CPP_OBJECTS) 
	g++ $(C_OBJECTS) $(CPP_OBJECTS) -o $(EXECUTABLE) $(LDFLAGS)

build_enclave:
	cd enclave && make all
	$(SGX_EDGER8R) --search-path ./enclave --search-path $(SGX_SDK)/include --untrusted enclave/enclave.edl
	cp enclave/enclave.signed.so .

clean:
	cd enclave && make clean
	rm -f enclave_u.* enclave.signed.so $(C_OBJECTS) $(CPP_OBJECTS) $(EXECUTABLE) ./pool/*.bin ./pool/*.pem ./pool/*.signature

enclave_u.c enclave_u.h:
	$(SGX_EDGER8R) --search-path ./enclave --search-path $(SGX_SDK)/include --untrusted enclave/enclave.edl

.SECONDARY: Enclave_u.c Enclave_u.h

%.o: %.cpp
	g++ $(CPPFLAGS) -c -o $@ $<

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

%.o: ../common/%.cpp
	g++ $(CPPFLAGS) -c -o $@ $<

%.o: ../common/%.c
	gcc $(CFLAGS) -c -o $@ $<