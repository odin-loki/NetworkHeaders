/**
<summary>Provides an encapsulation for UDP Packets and can create new UDP
Packets.</summary>
<remarks>
The contents of a UDP Packet:
<list type="table">
  <listheader>
    <term>Field</term>
    <description>Position</description>
  </listheader>
  <item><term>Source Port</term><description>2 bytes</description></item>
  <item><term>Destination Port</term><description>2 bytes</description></item>
  <item><term>Length</term><description>2 bytes - includes udp header and
    data</description></item>
  <item><term>Checksum</term><description>2 bytes- disabled = 00 00 00 00
    </description></item>
  <item><term>Data</term><description>The rest</description></item>
</list>
</remarks>
*/
public class UDPPacket : NetworkPacket
{
    /// <summary>The packets originating port</summary>
    public readonly int SourcePort;
    /// <summary>The packets destination port</summary>
    public readonly int DestinationPort;

    /**
    <summary>Takes in a MemBlock and parses it as a UDP Packet.</summary>
    <param name="packet">The MemBlock containing the UDP Packet</param>
     */
    public UDPPacket(MemBlock packet)
    {
        _icpacket = _packet = packet;
        SourcePort = (packet[0] << 8) | packet[1];
        DestinationPort = (packet[2] << 8) | packet[3];
        _icpayload = _payload = packet.Slice(8);
    }

    /**
    <summary>Creates a UDP Packet given the source port, destination port
    and the payload.</summary>
    <param name="SourcePort">The packets originating port</param>
    <param name="DestinationPort">The packets destination port</param>
    <param name="Payload">The data for the packet.</param>
    */
    public UDPPacket(int SourcePort, int DestinationPort, ICopyable Payload)
    {
        byte[] header = new byte[8];
        header[0] = (byte)((SourcePort >> 8) & 0xFF);
        header[1] = (byte)(SourcePort & 0xFF);
        header[2] = (byte)((DestinationPort >> 8) & 0xFF);
        header[3] = (byte)(DestinationPort & 0xFF);
        int length = Payload.Length + 8;
        header[4] = (byte)((length >> 8) & 0xFF);
        header[5] = (byte)(length & 0xFF);
        // Checksums are disabled!
        header[6] = 0;
        header[7] = 0;
        _icpacket = new CopyList(MemBlock.Reference(header), Payload);
        _icpayload = Payload;
    }
}