using System;
using System.IO;
using System.Text;

/**
 * Reads numbers in and out byte arrays
 */
public class NumberSerializer
{

    /**
     * When we are serializing bytes this is the length we need
     */
    public static int GetByteCount(string s)
    {
        //We just need one more byte than the UTF8 encoding does
        return Encoding.UTF8.GetByteCount(s) + 1;
    }
    public static bool ReadBool(Stream s)
    {
        int val = s.ReadByte();
        if (val < 0)
        {
            throw new Exception("Reached EOF");
        }
        //If the value is 0, false, otherwise true 
        return (val > 0);
    }
    /**
     * Reads a network endian (MSB) from bin
     * coded by hand for speed (profiled on mono)
     */
    public static int ReadInt(byte[] bin, int offset)
    {
        int val = 0;
        for (int i = 0; i < 4; i++)
        {
            val = (val << 8) | bin[i + offset];
        }
        return val;
    }
    //Too bad we can't use a template here, .Net generics *may* do the job
    public static int ReadInt(MemBlock mb, int offset)
    {
        int val = 0;
        for (int i = 0; i < 4; i++)
        {
            val = (val << 8) | mb[i + offset];
        }
        return val;
    }
    /**
     * Read an Int from the stream and advance the stream
     */
    public static int ReadInt(Stream s)
    {
        int bytes = 4;
        int val = 0;
        int tmp;
        while (bytes-- > 0)
        {
            tmp = s.ReadByte();
            if (tmp == -1)
            {
                throw new Exception("Could not read 4 bytes from the stream to read an int");
            }
            val = (val << 8) | tmp;
        }
        return val;
    }
    /**
     * Read a Long from the stream and advance the stream
     * coded by hand for speed (profiled on mono)
     */
    public static long ReadLong(Stream s)
    {
        int bytes = 8;
        long val = 0;
        int tmp;
        while (bytes-- > 0)
        {
            tmp = s.ReadByte();
            if (tmp < 0)
            {
                throw new Exception("Could not read 8 bytes from the stream to read a long");
            }
            //tmp should be in the interval [0, 255] this is to
            //avoid a mono compiler warning
            byte btmp = (byte)tmp;
            val = (val << 8) | btmp;
        }
        return val;
    }

    // coded by hand for speed (profiled on mono)
    public static long ReadLong(byte[] bin, int offset)
    {
        long val = 0;
        for (int i = 0; i < 8; i++)
        {
            val = (val << 8) | bin[i + offset];
        }
        return val;
    }
    // coded by hand for speed (profiled on mono)
    public static long ReadLong(MemBlock bin, int offset)
    {
        long val = 0;
        for (int i = 0; i < 8; i++)
        {
            val = (val << 8) | bin[i + offset];
        }
        return val;
    }

    // coded by hand for speed (profiled on mono)
    public static short ReadShort(byte[] bin, int offset)
    {
        return (short)((bin[offset] << 8) | bin[offset + 1]);
    }
    public static short ReadShort(MemBlock bin, int offset)
    {
        return (short)((bin[offset] << 8) | bin[offset + 1]);
    }

    /**
     * Read a short from the stream and advance the stream
     */
    public static short ReadShort(Stream s)
    {
        int result = s.ReadByte();
        if (result == -1)
        {
            throw new Exception("Could not read 2 bytes from the stream to read a short");
        }
        short ret_val = (short)(result << 8);
        result = s.ReadByte();
        if (result == -1)
        {
            throw new Exception("Could not read 2 bytes from the stream to read a short");
        }
        ret_val |= (short)result;
        return ret_val;
    }

    /**
     * This method reads UTF-8 strings out of byte arrays by looking
     * for the string up to the first zero byte.
     * 
     * While strings are not numbers, this serialization code
     * is put here anyway.
     *
     * @param bin the byte array
     * @param offset where to start looking.
     * @param bytelength how many bytes did we ready out
     *
     */
    public static string ReadString(byte[] bin, int offset, out int bytelength)
    {
        //Find the end of the string:
        int string_end = offset;
        while (bin[string_end] != 0)
        {
            string_end++;
        }
        //Add 1 for the null terminator
        bytelength = string_end - offset + 1;
        Encoding e = Encoding.UTF8;
        //subtract 1 for the null terminator
        return e.GetString(bin, offset, bytelength - 1);
    }
    public static string ReadString(MemBlock b, int offset, out int bytelength)
    {
        int null_idx = b.IndexOf(0, offset);
        int raw_length = null_idx - offset;
        bytelength = raw_length + 1; //One for the null
        Encoding e;
        /*
         * Benchmarks of mono show this to be about twice as fast as just
         * using UTF8.  That really means UTF8 could be optimized in mono
         */
        if (b.IsAscii(offset, raw_length))
        {
            e = Encoding.ASCII;
        }
        else
        {
            e = Encoding.UTF8;
        }
        return b.GetString(e, offset, raw_length);
    }
    /**
     * Read a UTF8 string from the stream
     * @param s the stream to read from
     * @param count the number of bytes we read from the stream.
     */
    public static string ReadString(Stream s, out int len)
    {
        bool cont = true;
        //Here is the initial buffer we make for reading the string:
        byte[] str_buf = new byte[32];
        int pos = 0;
        do
        {
            int val = s.ReadByte();
            if (val == 0)
            {
                //This is the end of the string.
                cont = false;
            }
            else if (val < 0)
            {
                //Some kind of error occured
                string str = Encoding.UTF8.GetString(str_buf, 0, pos);
                throw new Exception("Could not read the next byte from stream, string so far: " + str);
            }
            else
            {
                str_buf[pos] = (byte)val;
                pos++;
                if (str_buf.Length <= pos)
                {
                    //We can't fit anymore into this buffer.
                    //Make a new buffer twice as long
                    byte[] tmp_buf = new byte[str_buf.Length * 2];
                    Array.Copy(str_buf, 0, tmp_buf, 0, str_buf.Length);
                    str_buf = tmp_buf;
                }
            }
        } while (cont == true);
        len = pos + 1; //1 byte for the null
        return Encoding.UTF8.GetString(str_buf, 0, pos);
    }

    public static float ReadFloat(byte[] bin, int offset)
    {
        if (BitConverter.IsLittleEndian)
        {
            //Console.Error.WriteLine("This machine uses Little Endian processor!");
            SwapEndianism(bin, offset, 4);
            float result = BitConverter.ToSingle(bin, offset);
            //Swap it back:
            SwapEndianism(bin, offset, 4);
            return result;
        }
        else
            return BitConverter.ToSingle(bin, offset);
    }
    public static float ReadFloat(MemBlock mb)
    {
        return ReadFloat(mb, 0);
    }
    public static float ReadFloat(MemBlock mb, int offset)
    {
        byte[] bin = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            bin[i] = mb[offset + i];
        }
        return ReadFloat(bin, 0);
    }
    public static float ReadFloat(Stream s)
    {
        byte[] b = new byte[4];
        for (int i = 0; i < b.Length; i++)
        {
            int res = s.ReadByte();
            if (res < 0)
            {
                throw new Exception("Reached EOF");
            }
            b[i] = (byte)res;
        }
        return ReadFloat(b, 0);
    }

    /***/
    public static double ReadDouble(byte[] bin, int offset)
    {
        if (BitConverter.IsLittleEndian)
        {
            //Console.Error.WriteLine("This machine uses Little Endian processor!");
            SwapEndianism(bin, offset, 8);
            double result = BitConverter.ToDouble(bin, offset);
            //Swap it back:
            SwapEndianism(bin, offset, 8);
            return result;
        }
        else
            return BitConverter.ToDouble(bin, offset);
    }
    public static double ReadDouble(MemBlock mb)
    {
        return ReadDouble(mb, 0);
    }
    public static double ReadDouble(MemBlock mb, int offset)
    {
        byte[] bin = new byte[8];
        for (int i = 0; i < 8; i++)
        {
            bin[i] = mb[offset + i];
        }
        return ReadDouble(bin, 0);
    }
    public static double ReadDouble(Stream s)
    {
        byte[] b = new byte[8];
        for (int i = 0; i < b.Length; i++)
        {
            int res = s.ReadByte();
            if (res < 0)
            {
                throw new Exception("Reached EOF");
            }
            b[i] = (byte)res;
        }
        return ReadDouble(b, 0);
    }

    public static bool ReadFlag(byte[] bin, int offset)
    {
        byte var = (byte)(0x80 & bin[offset]);
        if (var == 0x80)
            return true;
        else
            return false;
    }

    public static void WriteInt(int val, byte[] target, int offset)
    {
        for (int i = 0; i < 4; i++)
        {
            target[offset + i] = (byte)(0xFF & (val >> 8 * (3 - i)));
        }
    }
    public static void WriteInt(int val, Stream s)
    {
        for (int i = 0; i < 4; i++)
        {
            byte tmp = (byte)(0xFF & (val >> 8 * (3 - i)));
            s.WriteByte(tmp);
        }
    }
    public static void WriteUInt(uint val, byte[] target, int offset)
    {
        for (int i = 0; i < 4; i++)
        {
            target[offset + i] = (byte)(0xFF & (val >> 8 * (3 - i)));
        }
    }
    public static void WriteUInt(uint val, Stream s)
    {
        for (int i = 0; i < 4; i++)
        {
            byte tmp = (byte)(0xFF & (val >> 8 * (3 - i)));
            s.WriteByte(tmp);
        }
    }

    public static void WriteShort(short val, byte[] target,
                                  int offset)
    {
        target[offset] = (byte)(0xFF & (val >> 8));
        target[offset + 1] = (byte)(0xFF & (val));
    }
    public static void WriteShort(short val, Stream s)
    {
        byte one = (byte)(0xFF & (val >> 8));
        byte two = (byte)(0xFF & (val));
        s.WriteByte(one);
        s.WriteByte(two);
    }
    public static void WriteUShort(ushort val, byte[] target, int offset)
    {
        target[offset] = (byte)(0xFF & (val >> 8));
        target[offset + 1] = (byte)(0xFF & (val));
    }
    public static void WriteUShort(ushort val, Stream s)
    {
        byte one = (byte)(0xFF & (val >> 8));
        byte two = (byte)(0xFF & (val));
        s.WriteByte(one);
        s.WriteByte(two);
    }
    /**
     * Write a UTF8 encoding of the string into the byte array
     * and terminate it with a "0x00" byte.
     * @param svalue the string to write into the byte array
     * @param target the byte array to write into
     * @param offset the number of bytes into the target to start
     * @return the number of bytes written
     */
    public static int WriteString(string svalue, byte[] target, int offset)
    {
        Encoding e = Encoding.UTF8;
        int bcount = e.GetBytes(svalue, 0, svalue.Length, target, offset);
        //Write the null:
        target[offset + bcount] = 0;
        return bcount + 1;
    }
    /**
     * Write a UTF8 encoding of the string into the byte array
     * and terminate it with a "0x00" byte.
     * @param svalue the string to write into the byte array
     * @param the Stream to write it into
     * @return the number of bytes written
     */
    public static int WriteString(string svalue, Stream s)
    {
        Encoding e = Encoding.UTF8;
        byte[] data = e.GetBytes(svalue);
        //Write the data:
        s.Write(data, 0, data.Length);
        //Write the null:
        s.WriteByte(0);
        return data.Length + 1;
    }

    public static void WriteLong(long lval, byte[] target, int offset)
    {
        for (int i = 0; i < 8; i++)
        {
            byte tmp = (byte)(0xFF & (lval >> 8 * (7 - i)));
            target[i + offset] = tmp;
        }
    }
    public static void WriteLong(long val, Stream s)
    {
        for (int i = 0; i < 8; i++)
        {
            byte tmp = (byte)(0xFF & (val >> 8 * (7 - i)));
            s.WriteByte(tmp);
        }
    }
    public static void WriteULong(ulong val, Stream s)
    {
        for (int i = 0; i < 8; i++)
        {
            byte tmp = (byte)(0xFF & (val >> 8 * (7 - i)));
            s.WriteByte(tmp);
        }
    }

    public static void WriteFloat(float value, byte[] target, int offset)
    {
        byte[] arr = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
        {
            //Make sure we are Network Endianism
            SwapEndianism(arr, 0, 4);
        }
        Array.Copy(arr, 0, target, offset, 4);
    }

    public static void WriteFloat(float value, Stream s)
    {
        byte[] b = new byte[4];
        WriteFloat(value, b, 0);
        for (int i = 0; i < b.Length; i++)
        {
            s.WriteByte(b[i]);
        }
    }


    /***/

    public static void WriteDouble(double value, byte[] target, int offset)
    {
        byte[] arr = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
        {
            //Make sure we are Network Endianism
            SwapEndianism(arr, 0, 8);
        }
        Array.Copy(arr, 0, target, offset, 8);
    }

    public static void WriteDouble(double value, Stream s)
    {
        byte[] b = new byte[8];
        WriteDouble(value, b, 0);
        for (int i = 0; i < b.Length; i++)
        {
            s.WriteByte(b[i]);
        }
    }

    public static void WriteFlag(bool flag, byte[] target, int offset)
    {
        byte var = target[offset];
        if (flag)
            var |= 0x80;    //Make the first bit 1
        else
            var &= 0x7F;    //Make the first bit 0

        target[offset] = var;
    }

    //Swap the bytes at offset
    protected static void SwapEndianism(byte[] data, int offset, int length)
    {
        int steps = length / 2;
        for (int i = 0; i < steps; i++)
        {
            byte tmp = data[offset + i];
            data[offset + i] = data[offset + length - i - 1];
            data[offset + length - i - 1] = tmp;
        }
    }
}
