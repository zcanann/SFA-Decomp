.include "macros.inc"
.file "placeholder_80080E28.s"

.text
.balign 4

.fn OSPhysicalToCached, global
/* 80080E28 82AF004C */ lwz r21, 0x4c(r15)
/* 80080E2C 3A400000 */ li r18, 0
.endfn OSPhysicalToCached

.fn OSPhysicalToUncached, global
/* 80080E30 39C00000 */ li r14, 0
/* 80080E34 48000001 */ bl fn_8002B9EC
.endfn OSPhysicalToUncached

.fn OSCachedToPhysical, global
/* 80080E38 7C711B78 */ mr r17, r3
/* 80080E3C 2C14FFFF */ cmpwi r20, -1
.endfn OSCachedToPhysical

.fn OSUncachedToPhysical, global
/* 80080E40 40820000 */ bne OSCachedToUncached+4
/* 80080E44 3860FFFF */ li r3, -1
.endfn OSUncachedToPhysical

.fn OSCachedToUncached, global
/* 80080E48 48000000 */ b fn_80081074+0x89c
/* 80080E4C 2C140000 */ cmpwi r20, 0
.endfn OSCachedToUncached

.fn OSUncachedToCached, global
/* 80080E50 41800000 */ blt fn_80080E58+0xc
/* 80080E54 806F0050 */ lwz r3, 0x50(r15)
.endfn OSUncachedToCached
