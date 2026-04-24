// Function: FUN_802085f4
// Entry: 802085f4
// Size: 212 bytes

void FUN_802085f4(undefined2 *param_1,int param_2)

{
  uint uVar1;
  short *psVar2;
  
  psVar2 = *(short **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_8020816c;
  *(undefined *)(psVar2 + 3) = *(undefined *)(param_2 + 0x19);
  *psVar2 = *(short *)(param_2 + 0x1e);
  psVar2[1] = *(short *)(param_2 + 0x20);
  psVar2[2] = 1;
  DAT_803add98 = 0;
  DAT_803add9c = 0;
  DAT_803adda0 = 0;
  DAT_803adda4 = 0;
  DAT_803adda8 = 0;
  DAT_803addac = 0;
  DAT_803addb0 = 0;
  DAT_803addb4 = 0;
  FUN_800146a8();
  uVar1 = FUN_80020078((int)*psVar2);
  if (uVar1 != 0) {
    *(byte *)(psVar2 + 4) = *(byte *)(psVar2 + 4) & 0xdf | 0x20;
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

