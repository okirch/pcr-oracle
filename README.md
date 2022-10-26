# PCR Oracle

This tool tries to predict TPM PCR values for future boot, based
on the current state of the system it runs in.

The top objective in creating this tool is to support full disk
encryption, and be able to have the TPM unseal the encryption key
that is protecting the system partition. Of course, as changes
are made to the system, the PCR values during boot will change,
making it necessary to adjust the policy that's protecting the
SRK. Examples include updates of the shim and/or boot loader,
or changes made to the GPT of the hard disk that EFI is booting from.

The primary mode of operation uses the TPM event log to replay the
sequence of PCR Extend operations. However, instead of hashing the
event as contained in the event log, it will use the current values
of EFI variables, boot applications and files etc as found in the
running system.

## Better safe than sorry: verify

In order to verify that the tool works on a specific EFI system,
it is best to run it in verification mode, like this:

    pcr-oracle --from eventlog all --verify current

This will re-hash all events found inside the event log, and when
done, compare the predicted values against the current PCR values
read from the TPM. (For those who are curious about what's going
on under the hood, run the command with the "-d" option for
debugging; use -ddd for really verbose output).

## Predict for the right point in time

Of course, in order to be usable for full disk encryption,
the prediction needs to output the PCR values not at the very
end of the boot process, but at the exact point where the
key would be unsealed. In the case of the grub based approach we're
currently evaluating at SUSE, this would happen in the early
grub.cfg file, looking like this:

    tpm2_key_protector_init -b sha256 -p 0,2,4,7,9 -k $prefix/sealed.key
    cryptomount -u e333642244ee4f0c828a466855781386 -k tpm2

In order to predict the PCR values for this scenario, you would
invoke pcr-oracle like this:

    pcr-oracle --from eventlog 0,2,4,7,9 \
        --before --stop--event grub-command=tpm2_key_protector_init \
        --format binary >pcr.state

This will stop processing the TPM event log right before the
first grub command event for the `tpm2_key_protector_init` command.

By writing the output in binary format, the `pcr.state` file generated
by this example can be used directly with the --pcr option of
`tpm2_policypcr`.

