.include "macros.inc"
.file "fragment"

.text
.balign 4

.fn __unregister_fragment, global
cmpwi r3, 0x0
bltlr
cmpwi r3, 0x1
bgelr
mulli r4, r3, 0xc
lis r3, fragmentinfo_803D68E0@ha
li r0, 0x0
addi r3, r3, fragmentinfo_803D68E0@l
add r3, r3, r4
stw r0, 0x0(r3)
stw r0, 0x4(r3)
stw r0, 0x8(r3)
blr
.endfn __unregister_fragment

.fn __register_fragment, global
lis r5, fragmentinfo_803D68E0@ha
addi r5, r5, fragmentinfo_803D68E0@l
lwz r0, 0x8(r5)
cmpwi r0, 0x0
bne .L_80286F18
stw r3, 0x0(r5)
li r0, 0x1
li r3, 0x0
stw r4, 0x4(r5)
stw r0, 0x8(r5)
blr
.L_80286F18:
li r3, -0x1
blr
.endfn __register_fragment
