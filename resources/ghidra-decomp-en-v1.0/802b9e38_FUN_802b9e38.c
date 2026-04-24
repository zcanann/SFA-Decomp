// Function: FUN_802b9e38
// Entry: 802b9e38
// Size: 392 bytes

undefined4 FUN_802b9e38(int param_1,uint *param_2)

{
  short sVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *param_2 = *param_2 | 0x200000;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  sVar1 = *(short *)(param_1 + 0xa0);
  if (sVar1 == 0x206) {
    if (*(char *)((int)param_2 + 0x346) != '\0') {
      if ((float)param_2[0xa8] <= FLOAT_803e8234) {
        return 8;
      }
      FUN_80030334(param_1,0x205,0);
      param_2[0xa8] = (uint)FLOAT_803e827c;
    }
    if (((*(short *)(iVar2 + 0xa88) != 0) && (FLOAT_803e8234 < (float)param_2[0xa8])) &&
       ((param_2[199] != 0 ||
        ((FLOAT_803e8234 != (float)param_2[0xa4] || (FLOAT_803e8234 != (float)param_2[0xa3])))))) {
      param_2[0xa8] = (uint)-(float)param_2[0xa8];
    }
  }
  else {
    if (sVar1 < 0x206) {
      if (0x204 < sVar1) {
        if (*(short *)(iVar2 + 0xa88) == 0) {
          return 0;
        }
        if (((param_2[199] == 0) && (FLOAT_803e8234 == (float)param_2[0xa4])) &&
           (FLOAT_803e8234 == (float)param_2[0xa3])) {
          return 0;
        }
        FUN_80030334((double)FLOAT_803e8234,param_1,0x207,0);
        param_2[0xa8] = (uint)FLOAT_803e8280;
        return 0;
      }
    }
    else if (sVar1 < 0x208) {
      if (*(char *)((int)param_2 + 0x346) == '\0') {
        return 0;
      }
      return 8;
    }
    FUN_80030334((double)FLOAT_803e8234,param_1,0x206,0);
    param_2[0xa8] = (uint)FLOAT_803e8280;
  }
  return 0;
}

