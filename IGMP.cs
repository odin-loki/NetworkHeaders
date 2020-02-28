/**
<summary>Unsupported, this class is too big to support now!</summary>
*/
public class IGMPPacket : NetworkPacket
{
    /**
    <summary>Unsupported, this class is too big to support now!</summary>
    */
    public enum Types { Join = 0x16, Leave = 0x17 };
    public readonly byte Type;
    public readonly MemBlock GroupAddress;

    public IGMPPacket(MemBlock packet)
    {
        _icpacket = _packet = packet;
        Type = packet[0];
        GroupAddress = packet.Slice(4, 4);
        _icpayload = _payload = packet.Slice(8);
    }
}