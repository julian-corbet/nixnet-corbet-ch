# Private dual-stack transit

The recovery path for an IPv6-only host does not need IPv4/IPv6 translation.
WireGuard transports both address families inside one authenticated UDP
session, so a v4-reachable client can use the host's private tunnel IPv4
address while the host still has no public IPv4 address.

The public hub has one UDP listener. Every participant authenticates with an
explicit WireGuard public key; its `AllowedIPs` is the source-address policy.
The hub forwards only from the tunnel interface back to that same interface,
never to an arbitrary uplink. Private keys are runtime files supplied by the
consumer's existing secret mechanism, never Nix store values.

For the e2 recovery route, Vultr is the hub, e2 initiates over its public IPv6
path, and other approved hosts initiate over Vultr's public IPv4 or IPv6.
This remains separate from NetBird: Vultr is still not a NetBird client and no
new control plane is introduced.
