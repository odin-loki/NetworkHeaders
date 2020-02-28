using System;

/**
<summary>This is for a SOA type Response and would be considered
a AR and not an RR.</summary>
<remarks>
<para>Authority RR RDATA, this gets placed in a response packet
RDATA</para>
<code>
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                     MNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                     RNAME                     /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    SERIAL                     |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    REFRESH                    |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     RETRY                     |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    EXPIRE                     |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    MINIMUM                    |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
</code>
</remarks>
*/
public class ZoneAuthority : DataPacket
{
    /// <summary>Incomplete</summary>
    public readonly string MNAME;
    /// <summary>Incomplete</summary>
    public readonly string RNAME;
    /// <summary>Incomplete</summary>
    public readonly int SERIAL;
    /// <summary>Incomplete</summary>
    public readonly int REFRESH;
    /// <summary>Incomplete</summary>
    public readonly int RETRY;
    /// <summary>Incomplete</summary>
    public readonly int EXPIRE;
    /// <summary>Incomplete</summary>
    public readonly int MINIMUM;

    /**
    <summary>Constructor when creating a ZoneAuthority from a MemBlock, this
    is incomplete.</summary>
    */
    public ZoneAuthority(MemBlock data)
    {
        int idx = 0;
        MNAME = String.Empty;
        while (data[idx] != 0)
        {
            byte length = data[idx++];
            for (int i = 0; i < length; i++)
            {
                MNAME += (char)data[idx++];
            }
            if (data[idx] != 0)
            {
                MNAME += ".";
            }
        }
        idx++;

        RNAME = string.Empty;
        while (data[idx] != 0)
        {
            byte length = data[idx++];
            for (int i = 0; i < length; i++)
            {
                RNAME += (char)data[idx++];
            }
            if (data[idx] != 0)
            {
                RNAME += ".";
            }
        }
        idx++;

        SERIAL = (data[idx++] << 24) + (data[idx++] << 16) + (data[idx++] << 8) + data[idx++] << 24;
        REFRESH = (data[idx++] << 24) + (data[idx++] << 16) + (data[idx++] << 8) + data[idx++] << 24;
        RETRY = (data[idx++] << 24) + (data[idx++] << 16) + (data[idx++] << 8) + data[idx++] << 24;
        EXPIRE = (data[idx++] << 24) + (data[idx++] << 16) + (data[idx++] << 8) + data[idx++] << 24;
        MINIMUM = (data[idx++] << 24) + (data[idx++] << 16) + (data[idx++] << 8) + data[idx++] << 24;
        _icpacket = _packet = data.Slice(0, idx);
    }
}