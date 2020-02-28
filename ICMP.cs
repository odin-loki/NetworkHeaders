using System;

/// <summary>Internet Control Message Packets (Ping)</summary>
public class ICMPPacket : DataPacket
{
    public enum Types
    {
        EchoReply = 0,
        EchoRequest = 8
    };

    public readonly Types Type;
    public readonly byte Code;
    public readonly short Identifier;
    public readonly short SequenceNumber;
    public readonly MemBlock Data;

    public ICMPPacket(Types type, short id, short seq_num)
    {
        Type = type;
        Identifier = id;
        SequenceNumber = seq_num;
        Code = 0;

        byte[] msg = new byte[64];
        Random rand = new Random();
        rand.NextBytes(msg);
        msg[0] = (byte)type;
        msg[1] = Code;
        msg[2] = (byte)0;
        msg[3] = (byte)0;


        NumberSerializer.WriteShort(Identifier, msg, 4);
        NumberSerializer.WriteShort(SequenceNumber, msg, 6);

        short checksum = (short)IPPacket.GenerateChecksum(MemBlock.Reference(msg));
        NumberSerializer.WriteShort(checksum, msg, 2);

        _icpacket = MemBlock.Reference(msg);
        _packet = MemBlock.Reference(msg);
    }

    public ICMPPacket(Types type) : this(type, 0, 0)
    {
    }

    public ICMPPacket(MemBlock Packet)
    {
        if (Packet.Length < 4)
        {
            throw new Exception("ICMP: Not long enough!");
        }

        _icpacket = Packet;
        _packet = Packet;

        Type = (Types)Packet[0];
        Code = Packet[1];

        if (Packet.Length >= 8)
        {
            Identifier = NumberSerializer.ReadShort(Packet, 4);
            SequenceNumber = NumberSerializer.ReadShort(Packet, 6);
        }
        else
        {
            Identifier = 0;
            SequenceNumber = 0;
        }
    }
}
