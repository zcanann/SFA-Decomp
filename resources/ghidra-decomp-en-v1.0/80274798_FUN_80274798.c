// Function: FUN_80274798
// Entry: 80274798
// Size: 296 bytes

undefined4 FUN_80274798(short param_1,int param_2,uint param_3)

{
  uint uVar1;
  short *psVar2;
  uint uVar3;
  
  uVar1 = 0;
  uVar3 = (uint)DAT_803de292;
  for (psVar2 = &DAT_803c9e78; ((int)uVar1 < (int)uVar3 && (param_1 != *psVar2));
      psVar2 = psVar2 + 4) {
    uVar1 = uVar1 + 1;
  }
  if ((uVar1 != uVar3) || (0x7f < uVar3)) {
    return 0;
  }
  FUN_80284af4();
  uVar3 = (uint)DAT_803de292;
  uVar1 = param_3 & 0xffff;
  (&DAT_803c9e78)[uVar3 * 4] = param_1;
  (&DAT_803c9e7a)[uVar3 * 4] = (short)param_3;
  (&DAT_803c9e7c)[uVar3 * 2] = param_2;
  if (uVar1 != 0) {
    uVar3 = uVar1 >> 3;
    if (uVar3 != 0) {
      do {
        *(undefined *)(param_2 + 9) = 0x1f;
        *(undefined *)(param_2 + 0x13) = 0x1f;
        *(undefined *)(param_2 + 0x1d) = 0x1f;
        *(undefined *)(param_2 + 0x27) = 0x1f;
        *(undefined *)(param_2 + 0x31) = 0x1f;
        *(undefined *)(param_2 + 0x3b) = 0x1f;
        *(undefined *)(param_2 + 0x45) = 0x1f;
        *(undefined *)(param_2 + 0x4f) = 0x1f;
        param_2 = param_2 + 0x50;
        uVar3 = uVar3 - 1;
      } while (uVar3 != 0);
      uVar1 = param_3 & 7;
      if (uVar1 == 0) goto LAB_80274884;
    }
    do {
      *(undefined *)(param_2 + 9) = 0x1f;
      param_2 = param_2 + 10;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
  }
LAB_80274884:
  DAT_803de292 = DAT_803de292 + 1;
  FUN_80284abc();
  return 1;
}

