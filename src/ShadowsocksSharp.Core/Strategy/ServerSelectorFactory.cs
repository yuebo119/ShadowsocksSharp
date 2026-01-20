using ShadowsocksSharp.Core.Configuration;

namespace ShadowsocksSharp.Core.Strategy;

public static class ServerSelectorFactory
{
    public static IServerSelector Create(Config config)
    {
        if (string.Equals(config.Strategy, "ha", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(config.Strategy, "high-availability", StringComparison.OrdinalIgnoreCase))
        {
            return new HighAvailabilityServerSelector();
        }

        return new StaticServerSelector();
    }
}
