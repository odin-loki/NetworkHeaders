using System;

/**
<summary>A response type is all the other blocks of data in a DNS packet
after the question, they can be RR, AR, and NS types based upon the RDATA
payload.</summary>
<remarks>
<para>Represents a Response to a DNS Query.</para>
<code>
1  1  1  1  1  1
0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                                               /
/                      NAME                     /
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
</code>
</remarks>
*/
public class Response : DataPacket
{
    /// <summary>the name rdata resolves as a string.</summary>
    public readonly string NAME;
    /// <summary>the name rdata resolves as a memblock.</summary>
    public readonly MemBlock NAME_BLOB;
    /// <summary>type of response</summary>
    public readonly DNSPacket.TYPES TYPE;
    /// <summary>type of network</summary>
    public readonly DNSPacket.CLASSES CLASS;
    /// <summary>Cache flush, not used for DNS only MDNS</summary>
    public readonly bool CACHE_FLUSH;
    /// <summary>cache time to live for the response</summary>
    public readonly int TTL;
    /// <summary>the length of the rdata</summary>
    public readonly short RDLENGTH;
    /// <summary>string representation of the RDATA</summary>
    public readonly string RDATA;
    /// <summary>MemBlock representation of the RDATA</summary>
    public readonly MemBlock RDATA_BLOB;

    /**
    <summary>Creates a response from the parameter fields with RDATA being
    a memory chunk.  This is for MDNS which supports caching</summary>
    <param name="NAME">The name resolved.</param>
    <param name="TYPE">The query type.</param>
    <param name="CLASS">The network type.</param>
    <param name="CACHE_FLUSH">Flush the dns cache in the client.</param>
    <param name="TTL">How long to hold the result in the local dns cache.</param>
    <param name="RDATA">RDATA in String format.</param>
    */
    public Response(string NAME, DNSPacket.TYPES TYPE, DNSPacket.CLASSES CLASS, bool CACHE_FLUSH, int TTL, string RDATA)
    {
        this.NAME = NAME;
        this.CLASS = CLASS;
        this.TTL = TTL;

        this.TYPE = TYPE;
        this.CLASS = CLASS;
        this.CACHE_FLUSH = CACHE_FLUSH;
        this.RDATA = RDATA;

        if (TYPE == DNSPacket.TYPES.A)
        {
            NAME_BLOB = DNSPacket.HostnameStringToMemBlock(NAME);
            RDATA_BLOB = DNSPacket.IPStringToMemBlock(RDATA);
        }
        else if (TYPE == DNSPacket.TYPES.PTR)
        {
            if (DNSPacket.StringIsIP(NAME))
            {
                NAME_BLOB = DNSPacket.PtrStringToMemBlock(NAME);
            }
            else
            {
                NAME_BLOB = DNSPacket.HostnameStringToMemBlock(NAME);
            }
            RDATA_BLOB = DNSPacket.HostnameStringToMemBlock(RDATA);
        }
        else
        {
            throw new Exception("Invalid Query TYPE: " + TYPE + "!");
        }

        RDLENGTH = (short)RDATA_BLOB.Length;
        // 2 for TYPE + 2 for CLASS + 4 for TTL + 2 for RDLENGTH
        byte[] data = new byte[10];
        int idx = 0;
        data[idx++] = (byte)((((int)TYPE) >> 8) & 0xFF);
        data[idx++] = (byte)(((int)TYPE) & 0xFF);

        byte cache_flush = 0x80;
        if (!CACHE_FLUSH)
        {
            cache_flush = 0x00;
        }

        data[idx++] = (byte)(((((int)CLASS) >> 8) & 0x7F) | cache_flush);
        data[idx++] = (byte)(((int)CLASS) & 0xFF);
        data[idx++] = (byte)((TTL >> 24) & 0xFF);
        data[idx++] = (byte)((TTL >> 16) & 0xFF);
        data[idx++] = (byte)((TTL >> 8) & 0xFF);
        data[idx++] = (byte)(TTL & 0xFF);
        data[idx++] = (byte)((RDLENGTH >> 8) & 0xFF);
        data[idx] = (byte)(RDLENGTH & 0xFF);

        _icpacket = new CopyList(NAME_BLOB, MemBlock.Reference(data), RDATA_BLOB);
    }

    /**
    <summary>Creates a response from the parameter fields with RDATA being
    a memory chunk.  This is for regular dns which has no notion of caching.
    </summary>
    <param name="NAME">The name resolved.</param>
    <param name="TYPE">The query type.</param>
    <param name="CLASS">The network type.</param>
    <param name="CACHE_FLUSH">Flush the dns cache in the client.</param>
    <param name="TTL">How long to hold the result in the local dns cache.</param>
    <param name="RDATA">RDATA in String format.</param>
    */
    public Response(string NAME, DNSPacket.TYPES TYPE, DNSPacket.CLASSES CLASS,     int TTL, string RDATA) : this(NAME, TYPE, CLASS, false, TTL, RDATA) { }

    /**
    <summary>Creates a response given the entire packet.</summary>
    <remarks>The entire packet must be given, because some name servers take
    advantage of pointers to reduce their size.</remarks>
    <param name="Data">The entire DNS packet.</param>
    <param name="Start">The starting position of the Response.</param>
    */
    public Response(MemBlock Data, int Start)
    {
        NAME_BLOB = DNSPacket.RetrieveBlob(Data, Start, out int idx);

        int type = (Data[idx++] << 8) + Data[idx++];
        TYPE = (DNSPacket.TYPES)type;

        CACHE_FLUSH = ((Data[idx] & 0x80) == 0x80) ? true : false;
        int rclass = ((Data[idx++] << 8) & 0x7F) + Data[idx++];
        CLASS = (DNSPacket.CLASSES)rclass;

        TTL = (Data[idx++] << 24);
        TTL |= (Data[idx++] << 16);
        TTL |= (Data[idx++] << 8);
        TTL |= (Data[idx++]);

        RDLENGTH = (short)((Data[idx++] << 8) + Data[idx++]);
        RDATA_BLOB = Data.Slice(idx, RDLENGTH);

        if (TYPE == DNSPacket.TYPES.PTR)
        {
            try
            {
                NAME = DNSPacket.PtrMemBlockToString(NAME_BLOB);
            }
            catch
            {
                NAME = DNSPacket.HostnameMemBlockToString(NAME_BLOB);
            }

            RDATA_BLOB = DNSPacket.RetrieveBlob(Data, idx, out _);
            RDATA = DNSPacket.HostnameMemBlockToString(RDATA_BLOB);
        }
        else if (TYPE == DNSPacket.TYPES.A)
        {
            NAME = DNSPacket.HostnameMemBlockToString(NAME_BLOB);
            RDATA = DNSPacket.IPMemBlockToString(RDATA_BLOB);
        }
        _icpacket = _packet = Data.Slice(Start, idx + RDLENGTH - Start);
    }
}