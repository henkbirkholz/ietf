from argparse import ArgumentParser
from urlparse import urlparse
import numpy

from ydk.services import ExecutorService
from ydk.providers import NetconfServiceProvider

from ydk.models.attestation import ietf-network-device-remote-attestation \
    as attestation_act
import logging
import base64
import OpenSSL.crypto

def process_ima_logs(ima_rpc):
    for node_data in ima_rpc.output.system_ima.node_data:
        print(node_data.node_location)
        for event in node_data.ima_event_log:
            print(str(event.event_number.get())+" "+event.filename_hint.get())

if __name__ == "__main__":
    """Execute main program."""
    parser = ArgumentParser()
    parser.add_argument("-v", "--verbose", help="print debugging messages",
                        action="store_true")
    parser.add_argument("device",
                        help="NETCONF device (ssh://user:password@host:port)")
    args = parser.parse_args()
    device = urlparse(args.device)
    # log debug messages if verbose argument specified
    if args.verbose:
        logger = logging.getLogger("ydk")
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        formatter = logging.Formatter(("%(asctime)s - %(name)s - "
                                       "%(levelname)s - %(message)s"))
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # create NETCONF provider
    provider = NetconfServiceProvider(address=device.hostname,
                                      port=device.port,
                                      username=device.username,
                                      password=device.password,
                                      protocol=device.scheme)
    # create executor service
    executor = ExecutorService()

    getcert_rpc = attestation_act.GetCertificate()
    getcert_rpc.input.certificate_identifier = "test"
    getcert_rpc.input.location = "RP/0/RP0/CPU0"
    random_array = numpy.random.randint(9, size=48, dtype=numpy.uint8)
    print(random_array)
    nonce = base64.b64encode(random_array)
    getcert_rpc.input.nonce = nonce
    print(getcert_rpc.input.nonce)
    print("That was the nonce")
    # execute RPC on NETCONF device
    getcert_rpc.output = executor.execute_rpc(provider, getcert_rpc, getcert_rpc.output) 
    for cert_list in getcert_rpc.output.get_certificate_response.system_certificates:
        print(cert_list)
        print(getcert_rpc.input.nonce)
        print(" Received nonce is:")
        print(cert_list.nonce)
        decoded_recvd_nonce_str = base64.decodestring(cert_list.nonce.get())
        recv_nonce = numpy.frombuffer(decoded_recvd_nonce_str, dtype=numpy.uint8)
        print(recv_nonce)
        if (numpy.allclose(recv_nonce, random_array)):
            print("Sent and received nonce match")
        else:
            print("Nonce missmatch")
        c=OpenSSL.crypto
        for cert_i in cert_list.certificates.certificate:
            cert_string = base64.decodestring(cert_i.value.get())
            cert_recvd = c.load_certificate(c.FILETYPE_ASN1,
                                            cert_string)
    # Verify certificate chain

    #Fetch PCR Quote for boot integrity

    #Validate PCR values against quote
    
    # Boot integrity validation with logs
    getbivlogs = attestation_act.GetPlatformBootIntegrityEventLogs()
    getbivlogs.input.location = "RP/0/RP0/CPU0"
    getbivlogs.output = executor.execute_rpc(provider, getbivlogs)

    # Process logs to match against PCR values received

    # Process hashes in boot event logs against KGVs
    
    #Runtime integrity validation
    attest_ima_rpc = attestation_act.GetPlatformImaEventLogs()
    attest_ima_rpc.input.location = "RP/0/RP0/CPU0"
    attest_ima_rpc.input.attestation_trustpoint = "AIK"
    attest_ima_rpc.input.last_event_number = 0
    attest_ima_rpc.input.attestation_key_algorithm = attest_ima_rpc.input.AttestationKeyAlgorithmEnum.ECDSA
    attest_ima_rpc.output = executor.execute_rpc(provider, attest_ima_rpc, attest_ima_rpc.output)
    process_ima_logs(attest_ima_rpc)


    exit()
