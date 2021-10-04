# :cat: Catlin Vulnerability Scanner :cat:

This can be used to scan vulnerability in Tekton Tasks.

## What is Trivy?

Trivy (tri pronounced like trigger, vy pronounced like envy) is a simple and comprehensive vulnerability scanner for containers and other artifacts. A software vulnerability is a glitch, flaw, or weakness present in the software or in an Operating System. Trivy detects vulnerabilities of OS packages (Alpine, RHEL, CentOS, etc.) and application dependencies (Bundler, Composer, npm, yarn, etc.). Trivy is easy to use. Just install the binary and you're ready to scan. All you need to do for scanning is to specify a target such as an image name of the container.

> Credit: https://github.com/aquasecurity/trivy

## Prequisite

1. Trivy CLI as it will be used as server. To install Trivy you can refer the installation guide [here](https://aquasecurity.github.io/trivy/v0.19.2/getting-started/installation/).
2. Go 1.14+

## Getting Started

1. First of all start the Trivy server. Trivy has client/server mode. Trivy server has vulnerability database and Trivy client doesn't have to download vulnerability database. It is useful if you want to scan images at multiple locations and do not want to download the database at every location. In order to do that, we need to start Trivy server first using the following command:

   ```bash
   $ trivy --cache-dir ./trivycache server
   2021-02-07T14:13:52.210+0300    INFO    Need to update DB
   2021-02-07T14:13:52.211+0300    INFO    Downloading DB...
   2021-02-07T14:13:59.275+0300    INFO    Listening localhost:4954...
   ```

After the server starts running it automatically updates it's DB every 12 hours. [Issue](https://github.com/aquasecurity/trivy/issues/692) mentioning this.

2. Now build the binary using the following command:

   ```
   $ go build -o catlin ./cmd/catlin
   ```

3. `Catlin` binary has many subcommands as it's taken from `github.com/tektoncd/plumbing` in order to use the existing code and avoid re-writing but here I am going to focus on vulnerability scanning.
   So to try that out use the following sub-command:

```bash
$ ./catlin scan pkg/cmd/validate/testdata/task/black/0.1/black.yaml
FILE: pkg/cmd/validate/testdata/task/black/0.1/black.yaml
docker.io/cytopia/black:latest-0.2@sha256:2ec766f1c7e42e6b59c0873ce066fa0a2aa2bf8a80dbc1c40f1566bb539303e0
Vulnerability type:  [os library]2021-09-26T17:58:03.078+0530	WARN	This OS version is no longer supported by the distribution: alpine 3.9.4
2021-09-26T17:58:03.078+0530	WARN	The vulnerability detection may be insufficient because security updates are not provided
30 vulnerability/ies found
docker.io/cytopia/black:latest-0.2@sha256:2ec766f1c7e42e6b59c0873ce066fa0a2aa2bf8a80dbc1c40f1566bb539303e0 (alpine 3.9.4)
=========================================================================================================================
Total: 30 (UNKNOWN: 0, LOW: 4, MEDIUM: 16, HIGH: 8, CRITICAL: 2)

+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
|   LIBRARY    | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                 TITLE                 |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
| libcrypto1.1 | CVE-2020-1967    | HIGH     | 1.1.1b-r1         | 1.1.1g-r0     | openssl: Segmentation                 |
|              |                  |          |                   |               | fault in SSL_check_chain              |
|              |                  |          |                   |               | causes denial of service              |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-1967  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2021-23840   |          |                   | 1.1.1j-r0     | openssl: integer                      |
|              |                  |          |                   |               | overflow in CipherUpdate              |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-23840 |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2021-3450    |          |                   | 1.1.1k-r0     | openssl: CA certificate check         |
|              |                  |          |                   |               | bypass with X509_V_FLAG_X509_STRICT   |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-3450  |
+              +------------------+----------+                   +---------------+---------------------------------------+
|              | CVE-2019-1547    | MEDIUM   |                   | 1.1.1d-r0     | openssl: side-channel weak            |
|              |                  |          |                   |               | encryption vulnerability              |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1547  |
+              +------------------+          +                   +               +---------------------------------------+
|              | CVE-2019-1549    |          |                   |               | openssl: information                  |
|              |                  |          |                   |               | disclosure in fork()                  |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1549  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2019-1551    |          |                   | 1.1.1d-r2     | openssl: Integer overflow in RSAZ     |
|              |                  |          |                   |               | modular exponentiation on x86_64      |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1551  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2020-1971    |          |                   | 1.1.1i-r0     | openssl: EDIPARTYNAME                 |
|              |                  |          |                   |               | NULL pointer de-reference             |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-1971  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2021-23841   |          |                   | 1.1.1j-r0     | openssl: NULL pointer dereference     |
|              |                  |          |                   |               | in X509_issuer_and_serial_hash()      |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-23841 |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2021-3449    |          |                   | 1.1.1k-r0     | openssl: NULL pointer dereference     |
|              |                  |          |                   |               | in signature_algorithms processing    |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-3449  |
+              +------------------+----------+                   +---------------+---------------------------------------+
|              | CVE-2019-1563    | LOW      |                   | 1.1.1d-r0     | openssl: information                  |
|              |                  |          |                   |               | disclosure in PKCS7_dataDecode        |
|              |                  |          |                   |               | and CMS_decrypt_set1_pkey             |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1563  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2021-23839   |          |                   | 1.1.1j-r0     | openssl: incorrect SSLv2              |
|              |                  |          |                   |               | rollback protection                   |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-23839 |
+--------------+------------------+----------+                   +---------------+---------------------------------------+
| libssl1.1    | CVE-2020-1967    | HIGH     |                   | 1.1.1g-r0     | openssl: Segmentation                 |
|              |                  |          |                   |               | fault in SSL_check_chain              |
|              |                  |          |                   |               | causes denial of service              |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-1967  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2021-23840   |          |                   | 1.1.1j-r0     | openssl: integer                      |
|              |                  |          |                   |               | overflow in CipherUpdate              |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-23840 |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2021-3450    |          |                   | 1.1.1k-r0     | openssl: CA certificate check         |
|              |                  |          |                   |               | bypass with X509_V_FLAG_X509_STRICT   |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-3450  |
+              +------------------+----------+                   +---------------+---------------------------------------+
|              | CVE-2019-1547    | MEDIUM   |                   | 1.1.1d-r0     | openssl: side-channel weak            |
|              |                  |          |                   |               | encryption vulnerability              |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1547  |
+              +------------------+          +                   +               +---------------------------------------+
|              | CVE-2019-1549    |          |                   |               | openssl: information                  |
|              |                  |          |                   |               | disclosure in fork()                  |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1549  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2019-1551    |          |                   | 1.1.1d-r2     | openssl: Integer overflow in RSAZ     |
|              |                  |          |                   |               | modular exponentiation on x86_64      |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1551  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2020-1971    |          |                   | 1.1.1i-r0     | openssl: EDIPARTYNAME                 |
|              |                  |          |                   |               | NULL pointer de-reference             |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-1971  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2021-23841   |          |                   | 1.1.1j-r0     | openssl: NULL pointer dereference     |
|              |                  |          |                   |               | in X509_issuer_and_serial_hash()      |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-23841 |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2021-3449    |          |                   | 1.1.1k-r0     | openssl: NULL pointer dereference     |
|              |                  |          |                   |               | in signature_algorithms processing    |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-3449  |
+              +------------------+----------+                   +---------------+---------------------------------------+
|              | CVE-2019-1563    | LOW      |                   | 1.1.1d-r0     | openssl: information                  |
|              |                  |          |                   |               | disclosure in PKCS7_dataDecode        |
|              |                  |          |                   |               | and CMS_decrypt_set1_pkey             |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-1563  |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2021-23839   |          |                   | 1.1.1j-r0     | openssl: incorrect SSLv2              |
|              |                  |          |                   |               | rollback protection                   |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2021-23839 |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
| musl         | CVE-2019-14697   | CRITICAL | 1.1.20-r4         | 1.1.20-r5     | musl libc through 1.1.23 has          |
|              |                  |          |                   |               | an x87 floating-point stack           |
|              |                  |          |                   |               | adjustment imbalance, related...      |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-14697 |
+              +------------------+----------+                   +---------------+---------------------------------------+
|              | CVE-2020-28928   | MEDIUM   |                   | 1.1.20-r6     | In musl libc through 1.2.1,           |
|              |                  |          |                   |               | wcsnrtombs mishandles particular      |
|              |                  |          |                   |               | combinations of destination buffer... |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-28928 |
+--------------+------------------+----------+                   +---------------+---------------------------------------+
| musl-utils   | CVE-2019-14697   | CRITICAL |                   | 1.1.20-r5     | musl libc through 1.1.23 has          |
|              |                  |          |                   |               | an x87 floating-point stack           |
|              |                  |          |                   |               | adjustment imbalance, related...      |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-14697 |
+              +------------------+----------+                   +---------------+---------------------------------------+
|              | CVE-2020-28928   | MEDIUM   |                   | 1.1.20-r6     | In musl libc through 1.2.1,           |
|              |                  |          |                   |               | wcsnrtombs mishandles particular      |
|              |                  |          |                   |               | combinations of destination buffer... |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-28928 |
+--------------+------------------+          +-------------------+---------------+---------------------------------------+
| python3      | CVE-2020-14422   |          | 3.6.9-r2          | 3.6.9-r3      | python: DoS via inefficiency          |
|              |                  |          |                   |               | in IPv{4,6}Interface classes          |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-14422 |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+
| sqlite-libs  | CVE-2019-19244   | HIGH     | 3.28.0-r1         | 3.28.0-r2     | sqlite: allows a crash                |
|              |                  |          |                   |               | if a sub-select uses both             |
|              |                  |          |                   |               | DISTINCT and window...                |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-19244 |
+              +------------------+          +                   +---------------+---------------------------------------+
|              | CVE-2020-11655   |          |                   | 3.28.0-r3     | sqlite: malformed window-function     |
|              |                  |          |                   |               | query leads to DoS                    |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-11655 |
+              +------------------+----------+                   +---------------+---------------------------------------+
|              | CVE-2019-19242   | MEDIUM   |                   | 3.28.0-r2     | sqlite: SQL injection in              |
|              |                  |          |                   |               | sqlite3ExprCodeTarget in expr.c       |
|              |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2019-19242 |
+--------------+------------------+----------+-------------------+---------------+---------------------------------------+

```
