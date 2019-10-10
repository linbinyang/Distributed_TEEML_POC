A simple POC Distributed Machine Learning Framework using SGX & ZeroMQ
================================================

Introduction
------------
Intel® Software Guard Extensions (Intel® SGX) is a set of instructions that increases the security of application code and data, giving them more protection from disclosure or modification. Developers can partition sensitive information into enclaves, which are areas of execution in memory with more security protection.

For this project, we build a simple distributed Machine Learning Framwork using ZMQ and SGX technology.

Documentation
-------------
- [Intel(R) SGX for Linux\* OS](https://01.org/intel-softwareguard-extensions) project home page on [01.org](https://01.org)
- [Intel(R) SGX Programming Reference](https://software.intel.com/sites/default/files/managed/7c/f1/332831-sdm-vol-3d.pdf)
- To learn more about runing mechanism of this project, please refer to [Framework API & ENCRYPT](./document/API.md)

Compile and Run the Project
-------------------------------------------------------
### Prerequisites:
- Ensure that you have one of the following required operating systems:  
  * Ubuntu\* 16.04 LTS Desktop 64bits
  * Ubuntu\* 16.04 LTS Server 64bits
  * Ubuntu\* 18.04 LTS Desktop 64bits
  * Ubuntu\* 18.04 LTS Server 64bits
  * Red Hat Enterprise Linux Server release 7.4 64bits
  * CentOS 7.5 64bits
  * Fedora 27 Server 64bits
  * SUSE Linux Enterprise Server 12 64bits
- Before building the project:
  * **Enable SGX in Bios**
  * **Disable Secure Boot in Bios**

### Build the Project

- Install the required libraries
```
  $ sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev libcurl4-openssl-dev libzmq3-dev
  $ sudo apt-get install build-essential python
```  

- To use the SGX trusted platform service, install the following
  * Download iclsClient through this [link](https://software.intel.com/en-us/sgx/sdk) or you can go to this [site](https://registrationcenter.intel.com/en/forms/?productid=2859) and the icsClient is automatically downloaded after registration.
  * When the iclsClient is downloaded
  ```
  $ sudo apt-get install alien 
  $ sudo alien --scripts iclsClient-1.45.449.12-1.x86_64.rpm
  $ sudo dpkg -i iclsclient_1.45.449.12-2_amd64.deb
  ```
- Install **JHI**
```
  $ git clone https://github.com/intel/dynamic-application-loader-host-interface
  $ sudo apt-get install uuid-dev libxml2-dev cmake pkg-config libsystemd-dev
  $ cmake .
  $ sudo make
  $ sudo make install
  $ sudo systemctl enable jhi
```
- Install Driver for SGX
  * download the required package from the official website of Intel.
  ```
  $ sudo ./sgx_linux_x64_driver.bin
  ```
- Install SGX PSW
  
```
  $ sudo dpkg -i ./libsgx-enclave-common_${version}-{revision}_amd64.deb
  $ echo 'deb [arch=amd64] https://download.01.org/intelsgx/sgx_repo/ubuntu xenial main' | sudo tee /etc/apt/sources.list.d/intelsgx.list
  $ wget -qO - https://download.01.org/intelsgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
  $ sudo apt-get update
  $ sudo apt-get install libsgx-enclave-common
  $ sudo apt-get install libsgx-enclave-common-dbgsym
``` 
- Check if asemd service is opened:
  The Intel(R) SGX PSW installer installs an aesmd service in your machine, which is running in a special linux account `aesmd`.  
```
  $ service asemd status
```
Stop the service: `$ sudo service aesmd stop`  
Start the service: `$ sudo service aesmd start`  
Restart the service: `$ sudo service aesmd restart`
If not opened (**secure boot in Bios must be closed**) then Check if isgx is loaded ``$ lsmod``, if isgx is loaded, you are fine.

- Install the SGX SDK

```
$ sudo ./sgx_linux_<os>_x64_sdk_<version>.bin
$ mkdir /home/SGXSDK
```
**Note:** When installing, entering the path ``/home/SGXSDK`` and to run the sample code, you need to modify the SGXSDK path in Makefile to ``/home/SGXSDK``.

### Run the Project
- Install openssl 1.0.1i
  ```
  $ wget https://www.openssl.org/source/openssl-1.0.1i.tar.gz 
  $ tar xf openssl-1.0.1i.tar.gz
  $ cd openssl-1.0.1i
  $ ./config --prefix=/opt/openssl/1.0.1i --openssldir=/opt/openssl/1.0.1i
  $ make
  $ sudo make install
  ```
- Make the project
  ```
  $ cd Cer-ML\SGX_POC_Framework
  $ make
  ```
- Configure the configure file in ``<YOUR PATH>\KeyData\client.cfg``

- Running
  * For the service
  ```
  $ LD_LIBRARY_PATH=/opt/openssl/1.0.1i/lib/ ./kmservice <YOUR PATH>/Cer-ML/KeyData/server.cfg
  ```
  * For the Client
  ```
  $ LD_LIBRARY_PATH=/opt/openssl/1.0.1i/lib/ ./kmclient <YOUR PATH>/Cer-ML/KeyData/client.cfg
  ```
