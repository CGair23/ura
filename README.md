# Universe01 Remote Attestation (ura)
## Attest

Here is an example to display the attestation report from a Teaclave service.

```bash
$ ./ura attest --address localhost:8888 
Report Freshness: 428s
SGX Quote status: ConfigurationAndSwHardeningNeeded
Version and signature/key type: Version 3, ECDSA P256_256 attestation key
Security version of the QE: 6
Security version of the PCE: 11
ID of the QE vendor: 939a7233-f79c-4ca9-940a-0db3957f0607
Custom user-defined data (hex): 5e2127332d17a43cbdc6f0e43b0ea24a00000000
CPU version (hex): 1212050501ff00000000000000000000
SSA Frame extended feature set: 0
Attributes of the enclave (hex): 07000000000000000700000000000000
Enclave measurement (hex): 6467928c50f610220305215f210a0f56f72d16af0f40fdcfe2cf6a6aed7e74a8
Hash of the enclave singing key (hex): 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
Enclave product ID: 0
Security version of the enclave: 0
The value of REPORT (hex): eedb104e14c2b243acde4460b1f9a3341985975fc32e2ee48ebb02c393e9514f3bf16a2190cc6e766e86a50cc6f94b28d462d668c4e5c905b3d31e3ec38be3a3
```