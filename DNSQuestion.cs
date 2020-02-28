using System;

/**
<summary>Represents a DNS Question</summary>
<remarks><para>Sadly the size of these can only be determined by parsing
the entire packet.</para>
<para>It looks like this:</para>
<code>
                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
</code></remarks>
*/
public class Question : DataPacket
{
    /// <summary>What type of qname do we have ptr or name</summary>
    public enum Types
    {
        /// <summary>a pointer / ip address</summary>
        IP_ADDR,
        /// <summary>name</summary>
        CHAR_ARRAY
    };
    /// <summary>string representation of the qname</summary>
    public readonly String QNAME;
    /// <summary>the blob format for the qname</summary>
    public readonly MemBlock QNAME_BLOB;
    /// <summary>the query type</summary>
    public readonly DNSPacket.TYPES QTYPE;
    /// <summary>the network class</summary>
    public readonly DNSPacket.CLASSES QCLASS;

    /**
    <summary>Constructor when creating a DNS Query</summary>
    <param name="QNAME">the name of resource you are looking up, IP Address 
    when QTYPE = PTR otherwise hostname</param>
    <param name="QTYPE"> the type of look up to perform</param>
    <param name="QCLASS">should always be IN</param>
    */
    public Question(string QNAME, DNSPacket.TYPES QTYPE, DNSPacket.CLASSES QCLASS)
    {
        this.QNAME = QNAME;
        this.QTYPE = QTYPE;
        this.QCLASS = QCLASS;

        if (QTYPE == DNSPacket.TYPES.A)
        {
            QNAME_BLOB = DNSPacket.HostnameStringToMemBlock(QNAME);
        }
        else if (QTYPE == DNSPacket.TYPES.PTR)
        {
            QNAME_BLOB = DNSPacket.PtrStringToMemBlock(QNAME);
        }
        else
        {
            throw new Exception("Invalid QTYPE: " + QTYPE + "!");
        }

        // 2 for QTYPE + 2 for QCLASS
        byte[] data = new byte[4];
        int idx = 0;
        data[idx++] = (byte)((((int)QTYPE) >> 8) & 0xFF);
        data[idx++] = (byte)(((int)QTYPE) & 0xFF);
        data[idx++] = (byte)((((int)QCLASS) >> 8) & 0xFF);
        data[idx++] = (byte)(((int)QCLASS) & 0xFF);
        _icpacket = new CopyList(QNAME_BLOB, MemBlock.Reference(data));
    }

    /**
    <summary>Constructor when parsing a DNS Query</summary>
    <param name="Data"> must pass in the entire packet from where the question
    begins, after parsing, can check Data.Length to find where next
    container begins.</param>
    */
    public Question(MemBlock Data, int Start)
    {
        QNAME_BLOB = DNSPacket.RetrieveBlob(Data, Start, out int idx);
        int qtype = (Data[idx++] << 8) + Data[idx++];
        QTYPE = (DNSPacket.TYPES)qtype;

        int qclass = (Data[idx++] << 8) + Data[idx];
        QCLASS = (DNSPacket.CLASSES)qclass;

        if (QTYPE == DNSPacket.TYPES.A)
        {
            QNAME = DNSPacket.HostnameMemBlockToString(QNAME_BLOB);
        }
        else if (QTYPE == DNSPacket.TYPES.PTR)
        {
            QNAME = DNSPacket.PtrMemBlockToString(QNAME_BLOB);
        }

        _icpacket = _packet = Data.Slice(Start, idx + 1 - Start);
    }
}