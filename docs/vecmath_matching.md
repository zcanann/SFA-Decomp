# Vector-math matrix temporary lifetimes

EN GSAE01, common GC/1.3 compiler, existing whole-TU
`nopeephole,noschedule,nostrength` profile. No compiler flags or pragmas changed.

`mtxRotateByVec3s` reuses its completed rotation temporaries for the translation
vector. Loading X, Y, then Z into these temporaries reproduces the retail load
order and all three translation dot products. The previous Z/X/Y order had a
slightly better fuzzy score than X/Y/Z with separate locals, but neither its
load order nor its register assignments matched retail.

The last rotation row also reuses an intermediate product after its previous
value is consumed. Keep the separate single-precision operations: contracting
or reassociating these expressions is not part of this change. The neutral
`component0..2` names reflect their successive rotation/translation roles.

The function remains 200 instructions / 800 bytes. Differing instruction rows
fall from 38 to 17, entirely register operands, and function fuzzy similarity
improves from 98.785% to 99.5%. The translation calculation is exact; the
remaining differences lie at instruction indices 132..151, where the shared
zero occupies f3 instead of retail's f0 and changes the adjacent product
registers. The TU improves from 99.808205% to 99.921074% fuzzy similarity.

All other 24 functions retain their exact bytes, and all 72 data bytes remain
exact. This is a partial matching improvement: the TU remains `NonMatching`.
Both `ninja all_source` and the strict retail-checksum build pass; the matching
link still uses the retail vecmath object.

The diagnostic backend capture reproduced the ordinary baseline object hash,
replayed all 84 FPR color choices, and found no high-degree removals. Probes of
declaration order, scoped temporaries, scalar qualifiers, small vector records,
inline helpers, and additional product spellings did not finish the match.
Whole-TU flag probes either retained the residual or regressed other functions;
none is adopted. The reduced source is the retained result, not those probes.
