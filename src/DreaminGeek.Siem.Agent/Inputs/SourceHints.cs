using System.Net;
using DreaminGeek.Siem.Core.Agents;

namespace DreaminGeek.Siem.Agent.Inputs;

/// <summary>Resolves a sender address to a dataset hint (e.g. the UDM at 192.168.1.1 → <c>unifi</c>).</summary>
public sealed class SourceHints
{
    private readonly (IPNetwork Network, string Dataset)[] _rules;

    public SourceHints(IEnumerable<SourceHint> hints)
    {
        ArgumentNullException.ThrowIfNull(hints);
        _rules = hints
            .Select(h => (Ok: TryParse(h.Source, out var net), Net: net, h.Dataset))
            .Where(r => r.Ok)
            .Select(r => (r.Net, r.Dataset))
            .ToArray();
    }

    public string? Resolve(IPAddress? address, string? inputDefault)
    {
        if (address is not null)
        {
            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }
            foreach (var (network, dataset) in _rules)
            {
                if (network.Contains(address))
                {
                    return dataset;
                }
            }
        }
        return inputDefault;
    }

    private static bool TryParse(string source, out IPNetwork network)
    {
        if (IPNetwork.TryParse(source, out network))
        {
            return true;
        }
        if (IPAddress.TryParse(source, out var ip))
        {
            network = new IPNetwork(ip, ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128);
            return true;
        }
        return false;
    }
}
