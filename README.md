# snp

The `snp` crate provides an implementation of [AMD Secure Encrypted
Virtualization - Secure Nested Paging (SEV-SNP)](https://www.amd.com/en/processors/amd-secure-encrypted-virtualization) APIs.

The Linux kernel exposes three technically distinct AMD SEV-SNP APIs:

1. An API for managing the SEV-SNP platform itself (for an SNP-capable host)
2. An API for managing SNP-enabled KVM virtual machines
3. An API for navigating the SNP guest environment (for an SNP-encrypted guest)

This crate implements the three of those APIs and offers them to client
code through a flexible and type-safe high level interface.

### Host Platform Management

Refer to the [`firmware::host`] module for more information.

### KVM Guest Management

Refer to the [`launch`] module for more information.

### Guest Platform Navigation

Refer to the [`firmware::guest`] module for more information.

### Remarks

FOR HOSTS: Note that the Linux kernel provides access to the host APIs through a set
of `ioctl`s that are meant to be called on device nodes (`/dev/kvm` and
`/dev/sev`, to be specific). Binaries that result from consumers of this crate are
expected to run as a process with the necessary privileges to interact
with the device nodes.

FOR GUESTS: Note that the Linux kernel provides access to the guest APIs through a set
of `ioctl`s that are meant to be called on the device node `/dev/sev-guest`.
Binaries that result from consumers of this crate are expected to run as a process with
the necessary privileges to interact with the device node.

License: Apache-2.0
