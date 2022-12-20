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
        --before --stop-event grub-command=tpm2_key_protector_init \
        --format binary >pcr.state

This will stop processing the TPM event log right before the
first grub command event for the `tpm2_key_protector_init` command.

By writing the output in binary format, the `pcr.state` file generated
by this example can be used directly with the --pcr option of
`tpm2_policypcr`.


## NEW: Using Authorized Policies

-- NOTE: UNDER HEAVY DEVELOPMENT --

Using a set of PCR values to seal a secret directly is a challenge
when dealing with updates of software components of grub, the shim
loader, etc - because these updates change the outcome of the PCR
computation done by the firmware.

Of course, it's possible to re-seal the secret using the new set
of PCR values, and that is what pcr-oracle was originally designed
to do. However, re-sealing means you need to have the original
secret from somewhere. And that can be difficult, or at least lead
to implementations that are not very user friendly.

To deal with this challenge, authorized policies were invented
(sometimes called "brittle PCR policies"). Now, what's the difference?

With regular PCR policies, you basically tell the TPM "I want you
to divulge the following secret whenever PCR registers A, B, and C
have the following value(s)."

With authorized PCR policies, you tell the TPM "Whenever I present
you with a set of PCR register values, and a digital signature
of these values signed with RSA key X, I want you to divulge the
secret whenever PCR registers A, B, and C have the given values."

In other words, with regular PCR policies, you tie the sealed
secret to specific PCR values directly. Whereas an authorized policy
inserts an RSA key in the middle - and if you update say the grub2
boot loader, you do not re-seal the secret, you just re-compute
the PCR values, and sign them with an RSA secret key.

How is this an improvement? After all, it's only a gradual difference
if I leave a copy of a LUKS key on my disk, or an unencrypted RSA key
that can be used to sign arbitrary PCR policies, right?

However, authorized policies can provide drastic improvements in
managed environments, eg when keeping the RSA key in a central
location. In this case, a managed system, when performing an update
of grub2, would send its TPM event log to the central system,
along with the name/version of grub it wants to update to. The
central authority would verify that it's okay to update to the
indicated grub version, predict the new PCRs based on the event log
plus its copy of the files from the grub package, sign these
values and return the signature to the managed node.

So far, pcr-oracle does not yet implement this mode of operation.
However, it already supports the creationg of, and sealing against,
authorized policies.

Here's how to do it:

pcr-oracle --rsa-key policy-key.pem --auth authorized.policy \
	create-authorized-policy 0,2,4
pcr-oracle --auth authorized.policy --in secret --out sealed \
	seal-secret
pcr-oracle --sign-policy --rsa-key policy-key.pem 0,2,4 \
	--out pcr-policy.signed


## Generate and submit test cases

The UEFI spec is large and complex, so writing a UEFI Firmware is
without doubt a daunting task. And not surprisingly, firmwares sometimes
do not adhere to the spec 100%. Which is why a tool like this needs
to detect such issues, and handle them gracefully.

In order to keep regressions to a minimum, need to build a
collection of test cases that covers a broad range of vendors and
system configurations.

You can contribute to this collection by submitting a test case!
Simply run the following commands:

    pcr-oracle --from eventlog all --verify current -d \
    	--create-testcase /tmp/pcr-oracle.test
    tar cjf /tmp/pcr-oracle.test.tar.bz2 /tmp/pcr-oracle.test

Submit your test case as a github issue to the pcr-oracle project,
or send it to me via email.

If you're curious, you can also re-run your own test case using
this command:

    pcr-oracle --from eventlog all --verify current -d \
    	--replay-testcase /tmp/pcr-oracle.test

Thank you!
