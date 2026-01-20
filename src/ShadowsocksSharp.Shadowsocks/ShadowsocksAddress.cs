using System.Net;
using System.Text;

namespace ShadowsocksSharp.Shadowsocks;

public static class ShadowsocksAddress
{
    public static int WriteAddress(string host, int port, Span<byte> buffer)
    {
        if (IPAddress.TryParse(host, out var ip))
        {
            var bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                buffer[0] = 0x01;
                bytes.CopyTo(buffer.Slice(1, 4));
                WritePort(buffer, 5, port);
                return 7;
            }

            buffer[0] = 0x04;
            bytes.CopyTo(buffer.Slice(1, 16));
            WritePort(buffer, 17, port);
            return 19;
        }

        var hostBytes = Encoding.ASCII.GetBytes(host);
        buffer[0] = 0x03;
        buffer[1] = (byte)hostBytes.Length;
        hostBytes.CopyTo(buffer.Slice(2, hostBytes.Length));
        WritePort(buffer, 2 + hostBytes.Length, port);
        return 2 + hostBytes.Length + 2;
    }

    private static void WritePort(Span<byte> buffer, int offset, int port)
    {
        buffer[offset] = (byte)(port >> 8);
        buffer[offset + 1] = (byte)(port & 0xFF);
    }
}
