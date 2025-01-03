# Lendiq Signer CLI

**Lendiq Signer** is a command-line application for signing documents using the CAdES-BASELINE-LT and ASiC-E signature formats. It leverages the [DSS library](https://ec.europa.eu/digital-building-blocks/DSS) for creating secure, legally valid digital signatures.

## Features

- Supports CAdES-BL-LT and ASiC-E signature formats.
- Enveloping signatures using SHA-256.
- Automatic loading of private keys and certificates from a PKCS#12 (.pfx) file.
- Optional support for providing an external certificate file.
- Secure integration with OCSP and CRL for signature validation.
- Timestamping support via an external TSP server.

---

## Prerequisites

### Dependencies

- Java 11 or higher
- DSS library ([Documentation and downloads](https://ec.europa.eu/digital-building-blocks/DSS))

### Input Requirements

1. **PFX File**: Contains the private key and certificate chain.
2. **Password**: Password for accessing the PFX file.
3. **Input File**: The file you want to sign.
4. **Optional Certificate File**: An X.509 certificate for signing (if not using the PFX file).

---

## Installation

1. Clone or download the project repository.
2. Build the project using your preferred build tool (e.g., Maven or Gradle).
3. Package the project into a runnable JAR file.

```sh
mvn clean package
```

---

## Usage

Run the CLI program with the required arguments:

```sh
java -jar lendiq-signer.jar --key <PFX_FILE> --password <PASSWORD> --cert <CERT_FILE> --file <FILE_PATH>
```

### Arguments

- `--key <PFX_FILE>`: Path to the PKCS#12 file containing the private key.
- `--password <PASSWORD>`: Password for the PKCS#12 file.
- `--file <FILE_PATH>`: Path to the input file to sign.
- `--cert <CERT_FILE>` (optional): Path to an external X.509 certificate file.

### Example

```sh
java -jar lendiq-signer.jar --key mykey.pfx --password mypassword --file document.pdf
```

---

## Output

- The signed file will be saved with the `.asice` extension in the same directory as the input file.
- Example: If the input file is `document.pdf`, the output file will be `document.pdf.asice`.

---

## Implementation Details

- **Signature Parameters**: The program uses SHA-256 as the digest algorithm, enveloping signature packaging, and the CAdES-BL-LT signature level.
- **OCSP/CRL Integration**: Ensures that the signing process includes online certificate validation.
- **Timestamping**: Configured with a TSP server to ensure time-stamped signatures.

### Supported Signature Formats

- **CAdES-BL-LT**: Long-term signature with online validation and timestamping.
- **ASiC-E**: Advanced Signature Container (ENVELOPING type).

---

## Error Handling

The application validates all input files and parameters before proceeding:

- Checks for the existence of the PFX file, input file, and optional certificate file.
- Verifies private keys and certificates in the PFX file.
- Handles invalid or missing parameters gracefully, displaying appropriate error messages.

---

## Development Notes

### Configuration

The application uses the following libraries and features:

- **DSS Library**: Implements the signing logic.
- **Commons Data Loader**: Fetches revocation data via CRL and OCSP.
- **Online TSP Server**: Provides timestamping services (default URL: `http://ca.diia.gov.ua/services/tsp/ecdsa/`).

### Extensibility

The code is modular, allowing developers to easily extend the application to support additional signature formats, validation rules, or integration with other services.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## Acknowledgments

This project uses the DSS library from the European Commission for secure digital signatures. Special thanks to the community contributors maintaining the library.
