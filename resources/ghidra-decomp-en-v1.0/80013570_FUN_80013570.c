// Function: FUN_80013570
// Entry: 80013570
// Size: 484 bytes

void FUN_80013570(void)

{
  int *piVar1;
  int iVar2;
  
  FUN_8001f768(&DAT_803dc8e0,0x35);
  iVar2 = 0;
  for (piVar1 = DAT_803dc8e0; *piVar1 != -1; piVar1 = piVar1 + 1) {
    iVar2 = iVar2 + 1;
  }
  DAT_803dc8c8 = iVar2 + -1;
  DAT_803dc8d8 = FUN_80023cc8(0x280,0x10,0);
  DAT_803387fc = 0;
  DAT_803387d0 = 0xfffffffe;
  DAT_803387b8 = 0x40000000;
  DAT_803dc8d0 = 0;
  DAT_803387a0 = 0;
  DAT_803387a2 = 0;
  DAT_80338800 = 0;
  DAT_803387d4 = 0xfffffffe;
  DAT_803387bc = 0x40000000;
  uRam803dc8d1 = 0;
  DAT_803387a4 = 0;
  DAT_803387a6 = 0;
  DAT_80338804 = 0;
  DAT_803387d8 = 0xfffffffe;
  DAT_803387c0 = 0x40000000;
  uRam803dc8d2 = 0;
  DAT_803387a8 = 0;
  DAT_803387aa = 0;
  DAT_80338808 = 0;
  DAT_803387dc = 0xfffffffe;
  DAT_803387c4 = 0x40000000;
  uRam803dc8d3 = 0;
  DAT_803387ac = 0;
  DAT_803387ae = 0;
  DAT_8033880c = 0;
  DAT_803387e0 = 0xfffffffe;
  DAT_803387c8 = 0x40000000;
  uRam803dc8d4 = 0;
  DAT_803387b0 = 0;
  DAT_803387b2 = 0;
  DAT_80338810 = 0;
  DAT_803387e4 = 0xfffffffe;
  DAT_803387cc = 0x40000000;
  uRam803dc8d5 = 0;
  DAT_803387b4 = 0;
  DAT_803387b6 = 0;
  DAT_803dc8cc = 0;
  DAT_803dc8dc = DAT_803dc8d8;
  DAT_803dc8c0 = FUN_80054c98(0x40,0x40,4,0,0,0,0,0,0);
  uRam803dc8c4 = FUN_80054c98(0x40,0x40,4,0,0,0,0,0,0);
  DAT_803dc8b8 = FUN_80054c98(0x10,0x10,4,0,0,0,0,0,0);
  uRam803dc8bc = FUN_80054c98(0x10,0x10,4,0,0,0,0,0,0);
  return;
}

