// Function: FUN_8021339c
// Entry: 8021339c
// Size: 256 bytes

int FUN_8021339c(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int local_8 [2];
  
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (*(char *)(param_2 + 0x346) != '\0') {
      iVar3 = (*(ushort *)((int)DAT_803de9d4 + 0xfa) >> 1 & 3) * 4;
      fVar1 = *(float *)(DAT_803de9d4[0x37] + iVar3) - *(float *)(DAT_803de9d4[0x34] + iVar3);
      fVar2 = *(float *)(DAT_803de9d4[0x39] + iVar3) - *(float *)(DAT_803de9d4[0x36] + iVar3);
      if (ABS(fVar1) <= ABS(fVar2)) {
        fVar1 = (*(float *)(param_1 + 0x14) - *(float *)(DAT_803de9d4[0x36] + iVar3)) / fVar2;
      }
      else {
        fVar1 = (*(float *)(param_1 + 0xc) - *(float *)(DAT_803de9d4[0x34] + iVar3)) / fVar1;
      }
      DAT_803de9d4[2] = fVar1;
      local_8[0] = 0;
      uVar4 = FUN_800138d4((short *)*DAT_803de9d4);
      if (uVar4 == 0) {
        FUN_80013900((short *)*DAT_803de9d4,(uint)local_8);
      }
      return local_8[0] + 1;
    }
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,2);
  }
  return 0;
}

