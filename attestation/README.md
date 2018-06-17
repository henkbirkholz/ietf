# Attestation

This draft defines data model for fetching attestation data.

Typical user of the model will do the following:
* Create a netconf session with the device
* Check for support for ietf-network-device-remote-attestation.yang
* Verify trust in attestation certificate chain
    * Use get-certificate RPC to fetch the certificates and verify it
* Verify boot integrity
    * Fetch PCR quote and values for the Boot integrity PCR indices using attest-platform-config-registers RPC
    * Fetch Boot event logs using get-platform-boot-integrity-event-logs RPC
    * Verify the PCR quote based on attestation key
    * Verify PCR values from the quote
    * Verify boot event logs against the PCR value
    * Now that boot event logs are verified, compare the boot integrity of individual entity measured against Known Good Values

* Verify runtime integrity
    * Fetch PCR quote and values for the runtime integrity PCR index using attest-platform-config-registers RPC
    * Fetch runtime event logs using get-platform-ima-event-logs RPC
    * Verify the PCR quote based on attestation key
    * Verify PCR values from the quote
    * Verify runtime event logs against the PCR value
    * Now that runtime event logs are verified, compare the runtime integrity of individual entity measured against Known Good Values
    * Continuously fetch new runtime integrity event logs and PCR quote and optimize the data fetched using get-platform-ima-event-logs start-event-number filter. This can be used to build trust the network device in steady state.

## Using the model

### Building Python API for the model using YDK

* Install ydk : Follow instructions here [https://github.com/CiscoDevNet/ydk-py]
* Install ydk-gen: [https://github.com/CiscoDevNet/ydk-gen]
* Generate python api bindings for the model:

```
    $ cd <ydk-gen dir>
    $ <install ydk-gen .. follow the Readme>
    $ ./generate.py --adhoc-bundle-name attestation --adhoc-bundle <path to ietf-network-device-remote-attestation.yang>
    $ cd ./gen-api/python/attestation-bundle/
    $ <follow Readme>
    $ python setup.py sdist
    $ pip install dist/ydk-*.tar.gz
    $ sudo pip install dist/ydk-*.tar.gz


```

### Invoke yang defined RPC

```
     $ python trigger-remote-attestation.py ssh://<username>:<password>@<IP>:<netconf port>
```
