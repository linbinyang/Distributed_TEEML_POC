Remote Attestation and Data Encryption
================================================

Introduction
------------
For this document, we would focus on the specific running mechanism of of project including Data Encryption and How Synchronous training is achieved. Some key functions and the process of remote attestation would be presented in detail.

For this project, we have Aggregator and Node. For Aggregator, its role is to allocate the model parameters, manage AES128 keys and compute the average gradients for multiple Node. The Node uses its own data to compute gradients and update the parameters of LR model.

- **Aggregator**: Task Allocator, Init Enclave, Manage the Keys, Compute average of gradients.
- **Node**: Init Enclave and Compute Gradient.
  
Documentation
-------------
- To learn about how to set environment of this project, please refer to [README.md](../README.md)

ECDH and Training Process
-------------------------------------------------------
### Background
Elliptic-curve Diffie–Hellman (**ECDH**) is an anonymous key agreement protocol that allows two parties, each having an elliptic-curve public–private key pair, to establish a shared secret over an insecure channel. This shared secret may be directly used as a key, or to derive another key. The key, or the derived key, can then be used to encrypt subsequent communications using a symmetric-key cipher. It is a variant of the Diffie–Hellman protocol using elliptic-curve cryptography.

### Node & Aggregator generates PubKey and PriKey
- Aggregator: APubKey & APriKey
- Node: NPubKey & NPriKey
- Key Generated in SGX Enclave
- Sealed The Keys and Store the sealed keys on disk

### Node sends hello_msg to Aggregator
- Aggregator receives the hello_msg and sends its APubKey to the NODE.

### Node wait for parameters
- After receiving APubKey from Aggregator, the Node would generate one AES key and the Node would derive 128 bits as SK. Sealed SK and store the SK on disk.
- Node sends NPubKey to Aggregator and tells the Aggregator to pass parameters.

### Aggregator sends parameters
- The Aggregators would generate the same SK after receiving the NPubKey from Node. The SK would also be stored on disk.
- Aggregator sends model parameters to Node.

### Node waits for Average Gradients (First Around)
- Initialized W and b.
- Compute the gradients.
- Encrypt the gradients in SGX Enclave and Sends the Encrypted Data to Aggregator.
  
### Collected gradients
- Decrypted the Encrpyted Gradients in Enclave.
- After receiving the same around gradients from all Node, the Aggregator would compute the average gradients and sends it back to the node waited in queue.
- The Node could continue its training for next around.

Reference
-------------
- [Code Sample: Intel@Software Guard Extension Remote Attestation End-to-End Example](https://software.intel.com/en-us/articles/code-sample-intel-software-guard-extensions-remote-attestation-end-to-end-example)
