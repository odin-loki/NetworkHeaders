/**
<summary>Provides an abstraction to sue a generic packet idea, that is you
can use the ICPacket portion to make a large packet and just copy the final 
object to a byte array in the end rather then at each stage.  When Packet
is accessed and is undefined, it will perform the copy automatically for 
you from ICPacket to Packet.</summary>
*/
public abstract class DataPacket
{
    /// <summary>The packet in ICopyable format.</summary>
    protected ICopyable _icpacket;
    /// <summary>The packet in ICopyable format.</summary>
    public ICopyable ICPacket { get { return _icpacket; } }

    /// <summary>The packet in MemBlock format</summary>
    protected MemBlock _packet;
    /// <summary>The packet in ICopyable format.  Creates the _packet if it
    /// does not already exist.</summary>
    public MemBlock Packet
    {
        get
        {
            if (_packet == null)
            {
                if (_icpacket is MemBlock)
                {
                    _packet = (MemBlock)_icpacket;
                }
                else
                {
                    byte[] tmp = new byte[_icpacket.Length];
                    _icpacket.CopyTo(tmp, 0);
                    _packet = MemBlock.Reference(tmp);
                }
            }
            return _packet;
        }
    }
}

/**
<summary>Similar to DataPacket but also provides a(n) (IC)Payload for packet
types that have a header and a body, as Ethernet and IP Packets do.</summary>
*/
public abstract class NetworkPacket : DataPacket
{
    /// <summary>The payload in ICopyable format.</summary>
    protected ICopyable _icpayload;
    /// <summary>The payload in ICopyable format.</summary>
    public ICopyable ICPayload { get { return _icpayload; } }
    /// <summary>The packet in MemBlock format</summary>
    protected MemBlock _payload;
    /// <summary>The packet in ICopyable format.  Creates the _packet if it
    /// does not already exist.</summary>
    public MemBlock Payload
    {
        get
        {
            if (_payload == null)
            {
                if (_icpayload is MemBlock)
                {
                    _payload = (MemBlock)_icpayload;
                }
                else
                {
                    byte[] tmp = new byte[_icpayload.Length];
                    _icpayload.CopyTo(tmp, 0);
                    _payload = MemBlock.Reference(tmp);
                }
            }
            return _payload;
        }
    }
}