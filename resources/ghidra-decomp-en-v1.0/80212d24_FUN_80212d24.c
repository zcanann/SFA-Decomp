// Function: FUN_80212d24
// Entry: 80212d24
// Size: 256 bytes

int FUN_80212d24(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int local_8 [2];
  
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (*(char *)(param_2 + 0x346) != '\0') {
      iVar3 = (*(ushort *)((int)DAT_803ddd54 + 0xfa) >> 1 & 3) * 4;
      fVar1 = *(float *)(DAT_803ddd54[0x37] + iVar3) - *(float *)(DAT_803ddd54[0x34] + iVar3);
      fVar2 = *(float *)(DAT_803ddd54[0x39] + iVar3) - *(float *)(DAT_803ddd54[0x36] + iVar3);
      if (ABS(fVar1) <= ABS(fVar2)) {
        fVar1 = (*(float *)(param_1 + 0x14) - *(float *)(DAT_803ddd54[0x36] + iVar3)) / fVar2;
      }
      else {
        fVar1 = (*(float *)(param_1 + 0xc) - *(float *)(DAT_803ddd54[0x34] + iVar3)) / fVar1;
      }
      DAT_803ddd54[2] = fVar1;
      local_8[0] = 0;
      iVar3 = FUN_800138b4(*DAT_803ddd54);
      if (iVar3 == 0) {
        FUN_800138e0(*DAT_803ddd54,local_8);
      }
      return local_8[0] + 1;
    }
  }
  else {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,2);
  }
  return 0;
}

