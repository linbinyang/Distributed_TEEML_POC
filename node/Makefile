OUTDIR:= bin
CURDIR=$(shell pwd)
TOPDIR=$(CURDIR)
SGX_SDK ?= /home/SGXSDK/sgxsdk
OPENSSL=/opt/openssl/1.0.1i
SGX_ARCH ?= x64

EXECUTABLE=kmclient

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else
	SGX_ARCH := x64
endif

ifeq ($(SGX_ARCH), x86)
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

export OUTDIR
export TOPDIR
export SGX_EDGER8R

# If output Dir does not exist, then create
ifneq ($(OUTDIR),)
$(shell mkdir -p $(OUTDIR))
endif

ifeq ($(DEBUG), y)
	CXXFLAGS += -g -DDEBUG
endif

export CXXFLAGS

CFLAGS=-I. -I../common -I$(SGX_SDK)/include -fno-builtin-memset -I$(OPENSSL)/include -g -O0 -DAGENT_LIBCURL=1
C_SOURCES=base64.c hexutil.c zeromqio.c readdata.c readconfig.c LogisticRegression.c python_c_api.c app.c
C_OBJECTS=$(C_SOURCES:.c=.o)

CPPFLAGS=$(CFLAGS) -std=c++11
# CPP_SOURCES=ra_req.cpp agent_curl.cpp iasrequest.cpp msgio.cpp common.cpp main.cpp
CPP_SOURCES=common.cpp main.cpp
CPP_OBJECTS=$(CPP_SOURCES:.cpp=.o)

LDFLAGS := -lpthread -L$(OPENSSL)/lib -lcrypto -lcurl -lzmq -lsgx_urts -lsgx_uae_service -lsgx_ukey_exchange -lpython3.5m -L$(SGX_SDK)/lib64 -ldl

.phony: all

all: $(EXECUTABLE)
	@make -C enclave
	@echo "Done"

$(EXECUTABLE): Enclave_u.o $(C_OBJECTS) $(CPP_OBJECTS)
	g++ Enclave_u.o $(C_OBJECTS) $(CPP_OBJECTS) -o $(EXECUTABLE) $(LDFLAGS) -I$(SGX_SDK)/include

Enclave_u.o: Enclave_u.c
	$(CC) -I$(SGX_SDK)/include -I../common -c $< -o $@

Enclave_u.c: 
	$(SGX_EDGER8R) --search-path ./enclave --search-path $(SGX_SDK)/include --untrusted enclave/Enclave.edl

clean:
	rm -rf $(C_OBJECTS) $(CPP_OBJECTS) $(EXECUTABLE) Enclave_u.o Enclave_u.c Enclave_u.h $(OUTDIR) ./pool/*.bin ./pool/*.pem ./pool/*.signature
	@make -C enclave clean

%.o: %.cpp
	g++ $(CPPFLAGS) -c -o $@ $<

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

%.o: ../common/%.cpp
	g++ $(CPPFLAGS) -c -o $@ $<

%.o: ../common/%.c
	gcc $(CFLAGS) -c -o $@ $<