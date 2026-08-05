{ lib }:
{
  archPackages = entries:
    lib.unique (map (entry: entry.arch)
      (lib.filter (entry: !(entry.aur or false)) entries));

  aurPackages = entries:
    lib.unique (map (entry: entry.arch)
      (lib.filter (entry: entry.aur or false) entries));
}
