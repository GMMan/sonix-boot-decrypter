// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography;

const uint SPI_FLASH_ADDR = 0x60000000;
const uint LOAD_TABLE_V2 = 0x5a5a0002;
const uint LOAD_TABLE_V3 = 0x5a5a0033;
const uint ENCRYPTER_PENDING_MARK = 0x5f5f4e45; // "EN__" for auto encrypt
const int SPI_LOAD_TABLE_SIZE = 0x200;
string[] LOAD_TABLE_MAGIC_VALUES = [
    "SNC7320",
    "SN323200",
    "SNUR00",
    "SN98300",
    "SONIXDEV",
    "SNCSPINF",
];

static byte[] ReverseArray(byte[] input)
{
    input = (byte[])input.Clone();
    Array.Reverse(input);
    return input;
}

bool IsLoadTable(byte[] magic)
{
    foreach (var value in LOAD_TABLE_MAGIC_VALUES)
    {
        bool match = true;
        for (int i = 0; i < value.Length; ++i)
        {
            if (magic[i] != value[i])
            {
                match = false;
                break;
            }
        }

        if (match)
        {
            return true;
        }
    }

    return false;
}

if (args.Length < 2)
{
    Console.Error.WriteLine($"Usage: {Environment.GetCommandLineArgs()[0]} <deviceKey> <inPath> [outPath]");
    return 1;
}

try
{
    uint deviceKey = Convert.ToUInt32(args[0], args[0].ToLower().StartsWith("0x") ? 16 : 10);
    string inPath = args[1];
    string outPath;
    if (args.Length < 3)
    {
        outPath = Path.Combine(Path.GetDirectoryName(inPath), $"{Path.GetFileNameWithoutExtension(inPath)}_decrypted{Path.GetExtension(inPath)}");
    }
    else
    {
        outPath = args[2];
    }

    File.Copy(inPath, outPath, true);

    using FileStream fs = File.Open(outPath, FileMode.Open, FileAccess.ReadWrite);
    if (fs.Length < SPI_LOAD_TABLE_SIZE) throw new InvalidDataException("File too small.");
    BinaryReader br = new(fs);
    BinaryWriter bw = new(fs);

    bool ProcessLoadTable(uint baseOffset, bool isPriorityBoot = false)
    {
        fs.Seek(baseOffset, SeekOrigin.Begin);
        byte[] tableMagic = br.ReadBytes(8);
        if (!IsLoadTable(tableMagic)) return false;

        fs.Seek(baseOffset + 8, SeekOrigin.Begin);
        uint loadCfg = br.ReadUInt32();

        fs.Seek(baseOffset + 0x1f8, SeekOrigin.Begin);
        uint tableVersion = br.ReadUInt32();
        CipherMode aesMode = tableVersion switch
        {
            < LOAD_TABLE_V3 => CipherMode.OFB,
            >= LOAD_TABLE_V3 => CipherMode.CBC,
        };

        // Load tables processed:
        // - Priority boot
        // - Priority boot in manual table
        // - Manual table
        // - Normal
        bool isRedirectEncrypted = false;

        // Priority boot does not allow nested redirects
        if (!isPriorityBoot)
        {
            // Priority boot (redirect to any boot device)
            if (((loadCfg >> 16) & 0xfff) == 0xfff)
            {
                // Check that we're still in flash, because this could boot off any other device
                fs.Seek(baseOffset + 0xc0, SeekOrigin.Begin);
                uint deviceType = br.ReadUInt32();
                if (deviceType == 0x01 || deviceType == 0x08)
                {
                    uint flashAddr = br.ReadUInt32();
                    if ((flashAddr | SPI_FLASH_ADDR) == flashAddr)
                    {
                        flashAddr -= SPI_FLASH_ADDR;
                    }
                    isRedirectEncrypted |= ProcessLoadTable(flashAddr, true);
                }
            }

            // Manual table (redirect within current boot device)
            fs.Seek(baseOffset + 0x68, SeekOrigin.Begin);
            uint manualTableAddress = br.ReadUInt32();
            if ((manualTableAddress | SPI_FLASH_ADDR) == manualTableAddress)
            {
                manualTableAddress -= SPI_FLASH_ADDR;
                isRedirectEncrypted |= ProcessLoadTable(manualTableAddress);
            }
        }

        bool isEncrypted = true;

        // ENCRYPTED_BOOT_CODE flag check
        if ((loadCfg & 1) == 0)
        {
            isEncrypted = false;
        }

        // ENCRYPTER.MARK check (not currently encrypted if present)
        if (isEncrypted && tableVersion >= LOAD_TABLE_V3)
        {
            fs.Seek(baseOffset + 0x80, SeekOrigin.Begin);
            uint mark = br.ReadUInt32();
            if (mark == ENCRYPTER_PENDING_MARK)
            {
                isEncrypted = false;
            }
        }

        if (!isEncrypted)
        {
            return isRedirectEncrypted;
        }

        fs.Seek(baseOffset + 0x28, SeekOrigin.Begin);
        byte[] aesKey = br.ReadBytes(32);

        // Create IV
        using Aes aes = Aes.Create();
        aes.Key = ReverseArray(aesKey.AsSpan(0x10, 0x10).ToArray());
        byte[] ivBytes = aesKey.AsSpan(0x0, 0x10).ToArray();
        byte[] ivVarBytes = BitConverter.GetBytes(deviceKey);
        for (int i = 0; i < ivBytes.Length; i += 4)
        {
            ivBytes[i] ^= ivVarBytes[0];
            ivBytes[i + 1] ^= ivVarBytes[1];
            ivBytes[i + 2] ^= ivVarBytes[2];
            ivBytes[i + 3] ^= ivVarBytes[3];
        }
        Array.Reverse(ivBytes);
        ivBytes = aes.EncryptEcb(ivBytes, PaddingMode.None);

        // Set up decryption
        aes.Key = ReverseArray(aesKey);
        aes.Mode = CipherMode.ECB; // We apply our own mode operations due to different byte order
        aes.Padding = PaddingMode.None;

        byte[] DecryptData(uint address, int length)
        {
            if (length == 0) return [];
            if (address < SPI_FLASH_ADDR || address + length > SPI_FLASH_ADDR + 0x10000000)
                throw new ArgumentOutOfRangeException(nameof(address), "Address not in flash range.");

            fs.Seek(address - SPI_FLASH_ADDR, SeekOrigin.Begin);
            byte[] data = br.ReadBytes(length);
            int dataLength = data.Length / (aes.BlockSize / 8) * (aes.BlockSize / 8);

            if (aesMode == CipherMode.OFB)
            {
                using ICryptoTransform transform = aes.CreateEncryptor();
                byte[] roundIv = (byte[])ivBytes.Clone();
                for (int i = 0; i < dataLength; i += aes.BlockSize / 8)
                {
                    transform.TransformBlock(roundIv, 0, roundIv.Length, roundIv, 0);
                    for (int j = 0; j < roundIv.Length; ++j)
                    {
                        data[i + j] ^= roundIv[roundIv.Length - 1 - j];
                    }
                }
            }
            else if (aesMode == CipherMode.CBC)
            {
                using ICryptoTransform transform = aes.CreateDecryptor();
                const int CHUNK_SIZE = 0x1000; // SNC733x doesn't have enough RAM to decrypt all 0x10000 bytes at once
                for (int i = 0; i < dataLength; i += CHUNK_SIZE)
                {
                    byte[] roundIv = (byte[])ivBytes.Clone();
                    byte[] plaintextBlock = new byte[aes.BlockSize / 8];
                    for (int j = 0; j < CHUNK_SIZE && i + j < dataLength; j += aes.BlockSize / 8)
                    {
                        byte[] cipherBlock = ReverseArray(data.AsSpan().Slice(i + j, aes.BlockSize / 8).ToArray());
                        transform.TransformBlock(cipherBlock, 0, cipherBlock.Length, plaintextBlock, 0);
                        for (int k = 0; k < plaintextBlock.Length; ++k)
                        {
                            plaintextBlock[k] ^= roundIv[k];
                        }
                        roundIv = cipherBlock;
                        Array.Reverse(plaintextBlock);
                        Buffer.BlockCopy(plaintextBlock, 0, data, i + j, plaintextBlock.Length);
                    }
                }
            }
            else
            {
                throw new InvalidOperationException("Unsupported mode of operation.");
            }

            return data;
        }

        // Main data
        fs.Seek(baseOffset + 0x10, SeekOrigin.Begin);
        uint userCodeAddr = br.ReadUInt32();
        int userCodeLength = br.ReadInt32();
        byte[] userCode = DecryptData(userCodeAddr, userCodeLength);
        fs.Seek(userCodeAddr - SPI_FLASH_ADDR, SeekOrigin.Begin);
        fs.Write(userCode);

        if (tableVersion == LOAD_TABLE_V2)
        {
            // Process manual load sections (V2-only)
            List<(uint srcAddr, int size)> manualLoadSections = new();
            fs.Seek(baseOffset + 0x140, SeekOrigin.Begin);
            int numEntries = br.ReadInt32();
            for (int i = 0; i < numEntries; ++i)
            {
                br.ReadUInt32(); // DES_ADDR
                uint srcAddr = br.ReadUInt32();
                int size = br.ReadInt32();
                br.ReadUInt32(); // CRC_CHECKSUM
                manualLoadSections.Add((srcAddr, size));
            }

            foreach (var section in manualLoadSections)
            {
                byte[] sectionData = DecryptData(section.srcAddr, section.size);
                fs.Seek(section.srcAddr - SPI_FLASH_ADDR, SeekOrigin.Begin);
                fs.Write(sectionData);
            }
        }

        if (tableVersion >= LOAD_TABLE_V3)
        {
            // Read extra code locations
            fs.Seek(baseOffset + 0x90, SeekOrigin.Begin);
            uint sramCodeAddr = br.ReadUInt32();
            int sramCodeLength = br.ReadInt32();
            uint dpdCodeAddr = br.ReadUInt32();
            int dpdCodeLength = br.ReadInt32();

            // SRAM
            if (sramCodeLength != 0)
            {
                byte[] sramCode = DecryptData(sramCodeAddr, sramCodeLength);
                fs.Seek(sramCodeAddr - SPI_FLASH_ADDR, SeekOrigin.Begin);
                fs.Write(sramCode);
            }

            // DPD
            // Note: SNC733x ignores this
            if (dpdCodeLength != 0)
            {
                byte[] dpdCode = DecryptData(dpdCodeAddr, dpdCodeLength);
                fs.Seek(dpdCodeAddr - SPI_FLASH_ADDR, SeekOrigin.Begin);
                fs.Write(dpdCode);
            }
        }

        // Patch encryption flags
        if (tableVersion >= LOAD_TABLE_V3)
        {
            // ENCRYPTER.MARK
            fs.Seek(baseOffset + 0x80, SeekOrigin.Begin);
            bw.Write(ENCRYPTER_PENDING_MARK);
        }
        else
        {
            // ENCRYPTED_BOOT_CODE
            // Still set if auto encrypt enabled for LOADER_TABLE_V3
            fs.Seek(baseOffset + 8, SeekOrigin.Begin);
            bw.Write((uint)(loadCfg & ~1));
        }

        return true;
    }

    // Handle multi-image firmware
    // In such an arrangement, first table could be for updated firmware while second table could be for original.
    // In ISP mode, first table could be bootloader and second table could be main firmware.
    bool isEncrypted = false;
    uint offset = 0;
    bool fromEnd = false;
    // Theoretically this should sweep the entire flash, but for now let's keep it reasonable, to the number
    // illustrated in the ISP manual.
    for (int i = 0; i < 6; ++i)
    {
        if (!fromEnd)
        {
            if (offset + SPI_LOAD_TABLE_SIZE <= fs.Length)
            {
                isEncrypted |= ProcessLoadTable(offset);
            }
            else
            {
                break;
            }
        }
        else
        {
            offset *= 2;
            if (fs.Length - offset >= 0)
            {
                isEncrypted |= ProcessLoadTable((uint)(fs.Length - offset));
            }
            else
            {
                break;
            }
        }

        if (offset == 0)
        {
            offset = 0x1000;
        }
        else
        {
            fromEnd = !fromEnd;
        }
    }

    if (!isEncrypted)
    {
        Console.Error.WriteLine("Code not encrypted. Exiting.");
        return 3;
    }

    bw.Flush();
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Something went wrong: {ex}");
    return 2;
}
