// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography;

const uint SPI_FLASH_ADDR = 0x60000000;
const uint LOADER_TABLE_V2 = 0x5a5a0002;
const uint LOADER_TABLE_V3 = 0x5a5a0033;
static byte[] ReverseArray(byte[] input)
{
    input = (byte[])input.Clone();
    Array.Reverse(input);
    return input;
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
    if (fs.Length < 512) throw new InvalidDataException("File too small.");
    BinaryReader br = new(fs);

    fs.Seek(0x1f8, SeekOrigin.Begin);
    uint tableVersion = br.ReadUInt32();

    bool isOfb;
    switch (tableVersion)
    {
        case LOADER_TABLE_V2:
            isOfb = true;
            break;
        case LOADER_TABLE_V3:
            isOfb = false;
            break;
        default:
            throw new InvalidDataException("Unknown load table version.");
    }

    fs.Seek(8, SeekOrigin.Begin);
    uint loadCfg = br.ReadUInt32();
    if ((loadCfg & 1) == 0)
    {
        Console.Error.WriteLine("Code not encrypted. Exiting.");
        return 3;
    }

    fs.Seek(0x28, SeekOrigin.Begin);
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

    // Set up encryption
    aes.Key = ReverseArray(aesKey);

    byte[] DecryptData(uint address, int length)
    {
        if (length == 0) return [];
        if (address < SPI_FLASH_ADDR || address + length > SPI_FLASH_ADDR + 0x10000000)
            throw new ArgumentOutOfRangeException(nameof(address), "Address not in flash range.");

        fs.Seek(address - SPI_FLASH_ADDR, SeekOrigin.Begin);
        byte[] data = br.ReadBytes(length);
        int dataLength = data.Length / (aes.BlockSize / 8) * (aes.BlockSize / 8);

        if (isOfb)
        {
            // OFB
            byte[] roundIv = (byte[])ivBytes.Clone();
            for (int i = 0; i < dataLength; i += aes.BlockSize / 8)
            {
                roundIv = aes.EncryptEcb(roundIv, PaddingMode.None);
                for (int j = 0; j < roundIv.Length; ++j)
                {
                    data[i + j] ^= roundIv[roundIv.Length - 1 - j];
                }
            }
        }
        else
        {
            // CBC
            const int CHUNK_SIZE = 0x1000; // SNC733x doesn't have enough RAM to decrypt all 0x10000 bytes at the same time
            for (int i = 0; i < dataLength; i += CHUNK_SIZE)
            {
                byte[] roundIv = (byte[])ivBytes.Clone();
                for (int j = 0; j < CHUNK_SIZE && i + j < dataLength; j += aes.BlockSize / 8)
                {
                    byte[] cipherBlock = ReverseArray(data.AsSpan().Slice(i + j, 0x10).ToArray());
                    byte[] plaintextBlock = aes.DecryptEcb(cipherBlock, PaddingMode.None);
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

        return data;
    }

    // Main data
    fs.Seek(0x10, SeekOrigin.Begin);
    uint userCodeAddr = br.ReadUInt32();
    int userCodeLength = br.ReadInt32();
    byte[] userCode = DecryptData(userCodeAddr, userCodeLength);
    fs.Seek(userCodeAddr - SPI_FLASH_ADDR, SeekOrigin.Begin);
    fs.Write(userCode);

    if (tableVersion >= LOADER_TABLE_V3)
    {
        // Read extra code locations
        fs.Seek(0x90, SeekOrigin.Begin);
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
        if (dpdCodeLength != 0)
        {
            byte[] dpdCode = DecryptData(dpdCodeAddr, dpdCodeLength);
            fs.Seek(dpdCodeAddr - SPI_FLASH_ADDR, SeekOrigin.Begin);
            fs.Write(dpdCode);
        }
    }

    // Patch encryption flags
    BinaryWriter bw = new(fs);

    if (tableVersion >= LOADER_TABLE_V3)
    {
        // ENCRYPTER.MARK
        fs.Seek(0x80, SeekOrigin.Begin);
        bw.Write(0x5f5f4e45); // "EN__" for auto encrypt
    }
    else
    {
        // ENCRYPTED_BOOT_CODE
        // Still set if auto encrypt enabled for LOADER_TABLE_V3
        fs.Seek(8, SeekOrigin.Begin);
        bw.Write((uint)(loadCfg & ~1));
    }

    bw.Flush();

    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Something went wrong: {ex}");
    return 2;
}
