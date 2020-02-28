using System;
using System.Net;

/**
<summary>Supports the parsing of DNS Packets.</summary>
<remarks><para>This is a very naive implementation and lacks support for
services other than address lookup (TYPE=A) and pointer look up (TYPE=PTR).
Because I haven't found a service that used inverse querying for name look
up, only pointer look up is implemented.</para>

<para>Exceptions will not occur when parsing byte arrays, only when
attempting to create from scratch new packets with unsupported TYPES.</para>

<code>
A DNS packet ...
1  1  1  1  1  1
0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                    QUERYS                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                   RESPONSES                   /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
</code>
<list type="table">
  <listheader>
    <term>Field</term>
    <description>Description</description>
  </listheader>
  <item>
    <term>ID</term>
    <description>identification - client generated, do not change</description>
  </item>
  <item>
    <term>QR</term>
    <description>query / reply, client sends 0, server replies 1</description>
  </item>
  <item>
    <term>Opcode</term>
    <description>0 for query, 1 inverse query</description>
  </item>
  <item>
    <term>AA</term>
    <description>Authoritative answer - True when there is a mapping</description>
  </item>
  <item>
    <term>TC</term>
    <description>Truncation - ignored - 0</description>
  </item>
  <item>
    <term>RD</term>
    <description>Recursion desired</description>
  </item>
  <item>
    <term>RA</term>
    <description>Recursion availabled</description>
  </item>
  <item>
    <term>Z</term><description>Reserved - must be 0</description>
  </item>
  <item>
    <term>RCODE</term>
    <description>ignored, stands for error code - 0</description>
  </item>
  <item>
    <term>QDCOUNT</term>
    <description>questions - should be 1</description>
  </item>
  <item>
    <term>ANCOUNT</term>
    <description>answers - should be 0 until we answer!</description>
  </item>
  <item>
    <term>NSCOUNT</term>
    <description>name server records - somewhat supported, but I can't
      find a reason why it needs to be so I've left in ZoneAuthority code
      in case it is ever needed!</description>
  </item>
  <item>
    <term>ARCOUNT</term>
    <description>additional records - unsupported</description>
  </item>
</list>
</remarks>
*/
public class DNSPacket : DataPacket
{
    /// <summary>the standard ptr suffix</summary>
    public const string INADDR_ARPA = ".in-addr.arpa";
    /// <summary>DNS Query / Response / Record types</summary>
    public enum TYPES
    {
        /// <summary>Host address(name)</summary>
        A = 1,
        /// <summary>zone authority</summary>
        SOA = 6,
        /// <summary>domain name pointer (ip address)</summary>
        PTR = 12
    };
    /// <summary>supported network classes</summary>
    public enum CLASSES
    {
        /// <summary>The Internet</summary>
        IN = 1
    };
    /// <summary>Unique packet ID</summary>
    public readonly short ID;
    /// <summary>Query if true, otherwise a response</summary>
    public readonly bool QUERY;
    /// <summary>0 = Query, 1 = Inverse Query, 2 = Status</summary>
    public readonly byte OPCODE;
    /// <summary>Authoritative answer (if you have a resolution, set)</summary>
    public readonly bool AA;
    public readonly bool RD;
    public readonly bool RA;
    /// <summary>list of Questions</summary>
    public readonly Question[] Questions;
    /// <summary>list of Answers</summary>
    public readonly Response[] Answers;
    public readonly Response[] Authority;
    public readonly Response[] Additional;

    /**
    <summary>Creates a DNS packet from the parameters provided.</summary>
    <param name="ID">A unique ID for the packet, responses should be the same
    as the query</param>
    <param name="QUERY">True if a query, false if a response</param>
    <param name="OPCODE">0 = Query, which is the only supported parsing method
    </param>
    <param name="AA">Authoritative Answer, true if there is a resolution for
    the lookup.</param>
    <param name="Questions">A list of Questions.</param>
    <param name="Answers">A list of Answers.</param>
    */
    public DNSPacket(short ID, bool QUERY, byte OPCODE, bool AA, bool RA, bool RD, Question[] Questions, Response[] Answers, Response[] Authority, Response[] Additional)
    {
        byte[] header = new byte[12];

        this.ID = ID;
        header[0] = (byte)((ID >> 8) & 0xFF);
        header[1] = (byte)(ID & 0xFF);

        this.QUERY = QUERY;
        if (!QUERY)
        {
            header[2] |= 0x80;
        }

        this.OPCODE = OPCODE;
        header[2] |= (byte)(OPCODE << 3);

        this.AA = AA;
        if (AA)
        {
            header[2] |= 0x4;
        }
        this.RD = RD;
        if (RD)
        {
            header[2] |= 0x1;
        }
        this.RA = RA;
        if (RA)
        {
            header[3] |= 0x80;
        }

        if (Questions != null)
        {
            this.Questions = Questions;
            header[4] = (byte)((Questions.Length >> 8) & 0xFF);
            header[5] = (byte)(Questions.Length & 0xFF);
        }
        else
        {
            this.Questions = new Question[0];
            header[4] = 0;
            header[5] = 0;
        }

        if (Answers != null)
        {
            this.Answers = Answers;
            header[6] = (byte)((Answers.Length >> 8) & 0xFF);
            header[7] = (byte)(Answers.Length & 0xFF);
        }
        else
        {
            this.Answers = new Response[0];
            header[6] = 0;
            header[7] = 0;
        }

        if (Authority != null)
        {
            this.Authority = Authority;
            header[8] = (byte)((Authority.Length >> 8) & 0xFF);
            header[9] = (byte)(Authority.Length & 0xFF);
        }
        else
        {
            this.Authority = new Response[0];
            header[8] = 0;
            header[9] = 0;
        }

        if (Additional != null)
        {
            this.Additional = Additional;
            header[10] = (byte)((Additional.Length >> 8) & 0xFF);
            header[11] = (byte)(Additional.Length & 0xFF);
        }
        else
        {
            this.Additional = new Response[0];
            header[10] = 0;
            header[11] = 0;
        }

        _icpacket = MemBlock.Reference(header);

        for (int i = 0; i < this.Questions.Length; i++)
        {
            _icpacket = new CopyList(_icpacket, Questions[i].ICPacket);
        }
        for (int i = 0; i < this.Answers.Length; i++)
        {
            _icpacket = new CopyList(_icpacket, Answers[i].ICPacket);
        }
        for (int i = 0; i < this.Authority.Length; i++)
        {
            _icpacket = new CopyList(_icpacket, Authority[i].ICPacket);
        }
        for (int i = 0; i < this.Additional.Length; i++)
        {
            _icpacket = new CopyList(_icpacket, Additional[i].ICPacket);
        }
    }

    /**
    <summary>Parses a MemBlock as a DNSPacket.</summary>
    <param name="Packet">The payload containing hte DNS Packet in byte format.
    </param>
    */
    public DNSPacket(MemBlock Packet)
    {
        ID = (short)((Packet[0] << 8) + Packet[1]);
        QUERY = ((Packet[2] & 0x80) >> 7) == 0;
        OPCODE = (byte)((Packet[2] & 0x78) >> 3);

        if ((Packet[2] & 0x4) == 0x4)
        {
            AA = true;
        }
        else
        {
            AA = false;
        }

        if ((Packet[2] & 0x1) == 0x1)
        {
            RD = true;
        }
        else
        {
            RD = false;
        }

        if ((Packet[3] & 0x80) == 0x80)
        {
            RA = true;
        }
        else
        {
            RA = false;
        }

        int qdcount = (Packet[4] << 8) + Packet[5];
        int ancount = (Packet[6] << 8) + Packet[7];
        int nscount = (Packet[8] << 8) + Packet[9];
        int arcount = (Packet[10] << 8) + Packet[11];
        int idx = 12;

        Questions = new Question[qdcount];
        for (int i = 0; i < qdcount; i++)
        {
            Questions[i] = new Question(Packet, idx);
            idx += Questions[i].Packet.Length;
        }

        Answers = new Response[ancount];
        for (int i = 0; i < ancount; i++)
        {
            Answers[i] = new Response(Packet, idx);
            idx += Answers[i].Packet.Length;
        }

        Authority = new Response[nscount];
        for (int i = 0; i < nscount; i++)
        {
            Authority[i] = new Response(Packet, idx);
            idx += Authority[i].Packet.Length;
        }

        Additional = new Response[arcount];
        for (int i = 0; i < arcount; i++)
        {
            Additional[i] = new Response(Packet, idx);
            idx += Additional[i].Packet.Length;
        }

        _icpacket = _packet = Packet;
    }

    /**
    <summary>Given a DNSPacket, it will generate a failure message so that
    the local resolver can move on to the next nameserver without timeouting
    on the this one.</summary>
    <param name="Packet">The base packet to translate into a failed response
    </param>
    */
    public static MemBlock BuildFailedReplyPacket(DNSPacket Packet)
    {
        byte[] res = new byte[Packet.Packet.Length];
        Packet.Packet.CopyTo(res, 0);
        res[3] |= 5;
        res[2] |= 0x80;
        return MemBlock.Reference(res);
    }

    public static bool StringIsIP(string IP)
    {
        bool is_ip = false;
        try
        {
            IPAddress.Parse(IP);
            is_ip = true;
        }
        catch { }
        return is_ip;
    }

    /**
    <summary>Takes in a memblock containing dns ptr data ...
    d.c.b.a.in-addr.arpa ... and returns the IP Address as a string.</summary>
    <param name="ptr">The block containing the dns ptr data.</param>
    <returns>The IP Address as a string - a.b.c.d.</returns>
    */
    public static string PtrMemBlockToString(MemBlock ptr)
    {
        string name = HostnameMemBlockToString(ptr);
        string[] res = name.Split('.');
        name = string.Empty;
        /* The last 2 parts are the pointer IN-ADDR.ARPA, the rest is 
        * reverse notation, we don't bother the user with this.
        */
        for (int i = res.Length - 3; i > 0; i--)
        {
            try
            {
                byte.Parse(res[i]);
            }
            catch
            {
                throw new Exception("Invalid IP PTR");
            }
            name += res[i] + ".";
        }
        name += res[0];
        return name;
    }

    /**
    <summary>Takes in an IP Address in dns format and returns a string.  The
    format is abcd (byte[] {a, b, c, d}.</summary>
    <param name="ip">a memblock containing abcd.</param>
    <returns>String IP a.b.c.d</returns>
    */
    public static string IPMemBlockToString(MemBlock ip)
    {
        if (ip.Length != 4 && ip.Length != 6)
        {
            throw new Exception("Invalid IP");
        }
        string res = ip[0].ToString();
        for (int i = 1; i < ip.Length; i++)
        {
            res += "." + ip[i].ToString();
        }
        return res;
    }

    /**
    <summary>Takes in a memblock containing a dns formatted hostname string and
    converts it into a String.</summary>
    <param name="name">The memblock containing the dns formated hostname.
    </param>
    <returns>The hostname in a properly formatted string.</returns>
    */
    public static string HostnameMemBlockToString(MemBlock name)
    {
        string names = string.Empty;
        int idx = 0;
        while (name[idx] != 0)
        {
            byte length = name[idx++];
            for (int i = 0; i < length; i++)
            {
                names += (char)name[idx++];
            }
            if (name[idx] != 0)
            {
                names += ".";
            }
        }
        return names;
    }

    /**
    <summary>Takes in an IP Address string and returns the dns ptr formatted
    memblock containing d.c.b.a.in-addr.arpa.</summary>
    <param name="ptr">An IP Address in the format a.b.c.d.</param>
    <returns>MemBlock containing d.c.b.a.in-addr.arpa.</returns>
    */
    public static MemBlock PtrStringToMemBlock(string ptr)
    {
        string[] res = ptr.Split('.');
        string name = string.Empty;
        for (int i = res.Length - 1; i > 0; i--)
        {
            name += res[i] + ".";
        }
        name += res[0] + INADDR_ARPA;
        return HostnameStringToMemBlock(name);
    }

    /**
    <summary>Takes in an ip string such as a.b.c.d and returns a MemBlock
    containing the IP [a, b, c, d].</summary>
    <param name="ip">The IP in a string to convert.</param>
    <returns>The MemBlock version of the IP Address.</returns>
    */
    public static MemBlock IPStringToMemBlock(string ip)
    {
        string[] bytes = ip.Split('.');
        if (bytes.Length != 4 && bytes.Length != 6)
        {
            throw new Exception("Invalid IP");
        }
        byte[] ipb = new byte[bytes.Length];
        for (int i = 0; i < ipb.Length; i++)
        {
            ipb[i] = byte.Parse(bytes[i]);
        }
        return MemBlock.Reference(ipb);
    }

    /**
    <summary>Given a NAME as a string converts it into bytes given the type
    of query.</summary>
    <param name="name">The name to convert (and resolve).</param>
    <param name="TYPE">The type of response packet.</param>
    */
    public static MemBlock HostnameStringToMemBlock(string name)
    {
        string[] pieces = name.Split('.');
        // First Length + Data + 0 (1 + name.Length + 1)
        byte[] nameb = new byte[name.Length + 2];
        int pos = 0;
        for (int idx = 0; idx < pieces.Length; idx++)
        {
            nameb[pos++] = (byte)pieces[idx].Length;
            for (int jdx = 0; jdx < pieces[idx].Length; jdx++)
            {
                nameb[pos++] = (byte)pieces[idx][jdx];
            }
        }
        nameb[pos] = 0;
        return MemBlock.Reference(nameb);
    }

    /**
    <summary>A blob is a fully resolved name.  DNS uses pointers to reduce
    memory consumption in packets, this can traverse all pointers and return a
    complete name.  The blob starts a Start and Ends at End.  This is used so
    that the parsing program knows where to continue reading data from.
    </summary>
    <param name="Data">The entire packet to grab the blob from.</param>
    <param name="Start">The beginning of the blob.</param>
    <param name="End">Returned to the user and notes where the blob ends.
    </param>
    <returns>The fully resolved blob as a memblock.</returns>
    */
    public static MemBlock RetrieveBlob(MemBlock Data, int Start, out int End)
    {
        int pos = Start, idx = 0;
        End = Start;
        byte[] blob = new byte[256];
        int length = 0;
        bool first = true;
        while (Data[pos] != 0)
        {
            if ((Data[pos] & 0xF0) == 0xC0)
            {
                int offset = (Data[pos++] & 0x3F) << 8;
                offset |= Data[pos];
                if (first)
                {
                    End = pos + 1;
                    first = false;
                }
                pos = offset;
            }
            else
            {
                blob[idx++] = Data[pos++];
                length++;
            }
        }

        // Get the last 0
        blob[idx] = Data[pos++];
        if (first)
        {
            End = pos;
        }
        return MemBlock.Reference(blob, 0, length + 1);
    }
}
