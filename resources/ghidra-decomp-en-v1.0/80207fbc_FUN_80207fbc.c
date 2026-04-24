// Function: FUN_80207fbc
// Entry: 80207fbc
// Size: 212 bytes

void FUN_80207fbc(undefined2 *param_1,int param_2)

{
  int iVar1;
  short *psVar2;
  
  psVar2 = *(short **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_80207b34;
  *(undefined *)(psVar2 + 3) = *(undefined *)(param_2 + 0x19);
  *psVar2 = *(short *)(param_2 + 0x1e);
  psVar2[1] = *(short *)(param_2 + 0x20);
  psVar2[2] = 1;
  DAT_803ad138 = 0;
  DAT_803ad13c = 0;
  DAT_803ad140 = 0;
  DAT_803ad144 = 0;
  DAT_803ad148 = 0;
  DAT_803ad14c = 0;
  DAT_803ad150 = 0;
  DAT_803ad154 = 0;
  FUN_8001467c();
  iVar1 = FUN_8001ffb4((int)*psVar2);
  if (iVar1 != 0) {
    *(byte *)(psVar2 + 4) = *(byte *)(psVar2 + 4) & 0xdf | 0x20;
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

