// Function: FUN_801ce62c
// Entry: 801ce62c
// Size: 580 bytes

undefined4 FUN_801ce62c(uint param_1,int param_2)

{
  byte bVar1;
  float fVar2;
  uint uVar3;
  char cVar4;
  undefined auStack_38 [4];
  undefined auStack_34 [12];
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  cVar4 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_38);
  if (*(char *)(param_2 + 0x45b) == '\0') {
    uVar3 = 0;
  }
  else {
    uVar3 = countLeadingZeros((int)*(char *)(param_2 + 0x453));
    uVar3 = uVar3 >> 5;
  }
  if (*(byte *)(param_2 + 0x408) < 0x14) {
    if (cVar4 == '\0') {
      return 0;
    }
    if (FLOAT_803e5ea4 < *(float *)(param_2 + 0x54)) {
      return 0xffffffff;
    }
    *(byte *)(param_2 + 0x409) = *(byte *)(param_2 + 0x408);
    *(undefined *)(param_2 + 0x408) = 0x14;
  }
  bVar1 = *(byte *)(param_2 + 0x408);
  if (bVar1 == 0x15) {
    if (uVar3 != 0) {
      FUN_8000bb38(param_1,0x14c);
    }
    *(float *)(param_2 + 4) = *(float *)(param_2 + 4) - FLOAT_803dc074;
    if ((cVar4 == '\0') && (*(float *)(param_2 + 4) <= FLOAT_803e5ea4)) {
      *(undefined *)(param_2 + 0x408) = 0x16;
    }
    fVar2 = *(float *)(param_2 + 0x1c) - FLOAT_803dc074;
    *(float *)(param_2 + 0x1c) = fVar2;
    if (fVar2 <= FLOAT_803e5ea4) {
      if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
        local_28 = *(undefined4 *)(param_2 + 0xc);
        local_24 = *(undefined4 *)(param_2 + 0x10);
        local_20 = *(undefined4 *)(param_2 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7f0,auStack_34,0x200001,0xffffffff,0);
      }
      *(float *)(param_2 + 0x1c) = FLOAT_803e5eb0;
    }
  }
  else if (bVar1 < 0x15) {
    if (0x13 < bVar1) {
      if (uVar3 != 0) {
        FUN_8000bb38(param_1,0x14b);
      }
      if ((*(byte *)(param_2 + 0x43c) & 2) != 0) {
        *(undefined *)(param_2 + 0x408) = 0x15;
        uVar3 = FUN_80022264(0,300);
        *(float *)(param_2 + 4) =
             (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e5eb8);
      }
    }
  }
  else if (bVar1 < 0x17) {
    if (uVar3 != 0) {
      FUN_8000bb38(param_1,0x14d);
    }
    if ((*(byte *)(param_2 + 0x43c) & 2) != 0) {
      *(undefined *)(param_2 + 0x408) = *(undefined *)(param_2 + 0x409);
    }
  }
  return 1;
}

