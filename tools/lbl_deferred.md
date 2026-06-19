# lbl_ naming — deferred units

Units whose lbl_ naming is blocked by an unrelated **upstream compile break**
(damage from the recent extern/comment cleanup sweeps), so they can't be built
or verified yet. Re-attempt once they compile on main.

- `src/main/dll/dll_0242_dbstealerworm.c` — orphan comment fragment (missing `/*`
  at the EN-annotation line) AND undefined `p2..p5` params at line ~984. Mapping
  ready (54 symbols, `gDbStealerworm*`).
