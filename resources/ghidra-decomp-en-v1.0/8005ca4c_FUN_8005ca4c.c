// Function: FUN_8005ca4c
// Entry: 8005ca4c
// Size: 728 bytes

void FUN_8005ca4c(void)

{
  undefined4 *puVar1;
  short *psVar2;
  int iVar3;
  
  DAT_803dcde8 = 0;
  DAT_803dce9c = FUN_80023cc8(0x100,5,0);
  DAT_803dce94 = FUN_80023cc8(0x80,5,0);
  DAT_803dce8c = FUN_80023cc8(0x40,5,0);
  DAT_803dce78 = FUN_80023cc8(0xd48,5,0);
  DAT_803822b4 = FUN_80023cc8(0x500,5,0);
  DAT_803822a0 = FUN_80023cc8(0x3c00,5,0);
  DAT_8038228c = FUN_80023cc8(0x500,5,0);
  DAT_803822b8 = DAT_803822b4 + 0x100;
  DAT_803822a4 = DAT_803822a0 + 0xc00;
  DAT_80382290 = DAT_8038228c + 0x100;
  DAT_803822bc = DAT_803822b4 + 0x200;
  DAT_803822a8 = DAT_803822a0 + 0x1800;
  DAT_80382294 = DAT_8038228c + 0x200;
  DAT_803822c0 = DAT_803822b4 + 0x300;
  DAT_803822ac = DAT_803822a0 + 0x2400;
  DAT_80382298 = DAT_8038228c + 0x300;
  DAT_803822c4 = DAT_803822b4 + 0x400;
  DAT_803822b0 = DAT_803822a0 + 0x3000;
  DAT_8038229c = DAT_8038228c + 0x400;
  FUN_8001f768(&DAT_803dce7c,0x1e);
  FUN_8001f768(&DAT_803dce80,0x29);
  puVar1 = &DAT_80386468;
  iVar3 = 3;
  do {
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    puVar1[5] = 0;
    puVar1[6] = 0;
    puVar1[7] = 0;
    puVar1[8] = 0;
    puVar1[9] = 0;
    puVar1[10] = 0;
    puVar1[0xb] = 0;
    puVar1[0xc] = 0;
    puVar1[0xd] = 0;
    puVar1[0xe] = 0;
    puVar1[0xf] = 0;
    puVar1[0x10] = 0;
    puVar1[0x11] = 0;
    puVar1[0x12] = 0;
    puVar1[0x13] = 0;
    puVar1[0x14] = 0;
    puVar1[0x15] = 0;
    puVar1[0x16] = 0;
    puVar1[0x17] = 0;
    puVar1[0x18] = 0;
    puVar1[0x19] = 0;
    puVar1[0x1a] = 0;
    puVar1[0x1b] = 0;
    puVar1[0x1c] = 0;
    puVar1[0x1d] = 0;
    puVar1[0x1e] = 0;
    puVar1[0x1f] = 0;
    puVar1[0x20] = 0;
    puVar1[0x21] = 0;
    puVar1[0x22] = 0;
    puVar1[0x23] = 0;
    puVar1[0x24] = 0;
    puVar1[0x25] = 0;
    puVar1[0x26] = 0;
    puVar1[0x27] = 0;
    puVar1 = puVar1 + 0x28;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  FUN_8001f768(&DAT_803dce84,0x27);
  DAT_803dce90 = 0;
  for (psVar2 = DAT_803dce84; *psVar2 != -1; psVar2 = psVar2 + 1) {
    DAT_803dce90 = DAT_803dce90 + 1;
  }
  DAT_803dce90 = DAT_803dce90 + -1;
  DAT_803dceba = 0xffff;
  DAT_803dceb8 = 0xfffe;
  DAT_803dce6c = FUN_80023cc8(0x500,5,0);
  FUN_800033a8(DAT_803dce6c,0,0x500);
  DAT_803dce68 = FUN_80023cc8(0x3a0,5,0);
  FUN_800033a8(DAT_803dce68,0,0x3a0);
  FUN_800033a8(&DAT_803868d8,0,4000);
  DAT_803868d8 = 0xffffffff;
  return;
}

