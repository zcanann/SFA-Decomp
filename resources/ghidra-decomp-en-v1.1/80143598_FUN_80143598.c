// Function: FUN_80143598
// Entry: 80143598
// Size: 188 bytes

undefined4 FUN_80143598(int param_1,int *param_2)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  
  iVar2 = FUN_80144994(param_1,param_2);
  if (iVar2 == 0) {
    sVar1 = *(short *)(param_1 + 0xa0);
    if (sVar1 == 0x24) {
      if (((param_2[0x15] & 0x8000000U) != 0) && (uVar3 = FUN_80022264(0,3), uVar3 == 0)) {
        *(undefined *)((int)param_2 + 10) = 0;
      }
    }
    else if (((sVar1 < 0x24) && (0x22 < sVar1)) && ((param_2[0x15] & 0x8000000U) != 0)) {
      FUN_8013a778((double)FLOAT_803e3108,param_1,0x24,0);
    }
  }
  return 1;
}

