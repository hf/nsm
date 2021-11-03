# NSM Attestation Example

This is a simple example that shows how you can get the attestation from a
Nitro Enclave.

Make sure you've read the AWS Nitro Enclaves guide.

All commands should be run in the root of the project, not the directory where
this README resides.

First build a Docker image:

```bash
docker build -t nsm-example -f example/attestation/Dockerfile .
```

Then build a Nitro EIF file:

```bash
nitro-cli build-enclave --docker-uri nsm-example --output-file nsm-example.eif
```

Then run an enclave:

```bash
sudo nitro-cli run-enclave --eif-path nsm-example.eif --cpu-count 2 --memory 1024 --debug-mode
```

Record the enclave ID as returned by the above command, and execute:

```bash
sudo nitro-cli console --enclave-id <ENCLAVE-ID>
```

You should be able to see a Base64 encoded version of the returned attestation
in the console output.
