Sonix SNC73xx Boot Code Decrypter
=================================

This program is designed to decrypt boot code on SPI NOR flash for SNC7320, SNC7330, and SNC7340 microcontrollers.
SPI NAND flash images (where the spare data have been removed) and SD card firmware are supported but not tested.

Usage
-----

Supply the device key, encrypted firmware path, and optionally decrypted firmware path to the program.

The device key, depending on the device variant, can be found at `SN_SYS0->FEUSE2_b.AES_Key` (top 16 bits of `0x45000038`)
or `SN_SYS0->FEUSE3` (word at `0x4500003c`). Supply as either a decimal number, or hexadecimal number prefixed with `0x`.

If a decrypted firmware path is not supplied, the decrypted firmware will be saved with `_decrypted` appended before
the file extension of the input path.

For SD card, the initial firmware should be at `sdc_bin/bin` on the card. This program does not support priority boot
from a different boot device, but you can run the program separately on the file pointed to. Priority boot on SD card
when the initial load table is from SD card is not supported by the bootrom.

Note that for SNC7330 and SNC7340, the firmware image is restored to pre-encryption state, and the encryption flags are
not removed. If you want to prevent the image from being encrypted, unset the `ENCRYPTED_BOOT_CODE` bit (lowest bit at
`0x08` in the firmware image), and set the encrypter mark starting at `0x80` in the firmware image to four null bytes.
Update the load table checksum if desired (or required by the `CHECK_LOAD_TABLE` flag).
