using System;
using System.IO;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("ImageHlp.dll", SetLastError = true)]
    private static extern bool CheckSumMappedFile(IntPtr BaseAddress, uint FileLength, out uint HeaderSum, out uint CheckSum);

    static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Usage: CheckSumEditor.exe <path_to_exe>");
            return;
        }

        string exePath = args[0];
        byte[] fileBytes = File.ReadAllBytes(exePath);

        GCHandle handle = GCHandle.Alloc(fileBytes, GCHandleType.Pinned);
        IntPtr baseAddress = handle.AddrOfPinnedObject();

        uint headerSum;
        uint newCheckSum;
        if (!CheckSumMappedFile(baseAddress, (uint)fileBytes.Length, out headerSum, out newCheckSum))
        {
            Console.WriteLine("Failed to calculate CheckSum.");
            return;
        }

        handle.Free();

        using (FileStream fs = new FileStream(exePath, FileMode.Open, FileAccess.ReadWrite))
        using (BinaryReader reader = new BinaryReader(fs))
        using (BinaryWriter writer = new BinaryWriter(fs))
        {
            // Move to the PE header offset location (0x3C in DOS header)
            fs.Seek(0x3C, SeekOrigin.Begin);
            int peHeaderOffset = reader.ReadInt32();

            // Move to the PE header
            fs.Seek(peHeaderOffset, SeekOrigin.Begin);

            // Read the PE Signature (should be "PE\0\0")
            uint peSignature = reader.ReadUInt32();
            if (peSignature != 0x00004550)  // "PE\0\0" in hexadecimal
            {
                Console.WriteLine("Invalid PE file.");
                return;
            }

            // Calculate the offset to the CheckSum field
            int peOptionalHeaderOffset = peHeaderOffset + 24; // COFF header size is 24 bytes
            int checkSumOffset = peOptionalHeaderOffset + 64; // CheckSum is at offset 64 in the Optional Header

            // Move to the CheckSum field
            fs.Seek(checkSumOffset, SeekOrigin.Begin);

            // Read the current CheckSum
            uint originalCheckSum = reader.ReadUInt32();
            Console.WriteLine($"Original CheckSum: 0x{originalCheckSum:X}");

            if (originalCheckSum != 0)
            {
                Console.WriteLine("Error: Existing CheckSum is not zero. Operation aborted.");
                return;
            }

            // Move back to the CheckSum field to write the new CheckSum
            fs.Seek(checkSumOffset, SeekOrigin.Begin);
            writer.Write(newCheckSum);
            Console.WriteLine($"New CheckSum: 0x{newCheckSum:X}");
        }
    }
}
