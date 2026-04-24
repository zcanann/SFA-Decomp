// Function: FUN_801ed2cc
// Entry: 801ed2cc
// Size: 244 bytes

void FUN_801ed2cc(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar1 + 0x421) = (char)param_2;
  if (param_2 == 2) {
    FUN_800201ac((int)*(short *)(iVar1 + 0x448),1);
    FUN_801ecea8(param_1,iVar1);
    if ((*(byte *)(iVar1 + 0x428) >> 5 & 1) != 0) {
      *(float *)(iVar1 + 0x4b8) = FLOAT_803e6828;
      *(float *)(iVar1 + 0x4c0) = FLOAT_803e6784;
      *(float *)(iVar1 + 0x4bc) = FLOAT_803e682c;
      if (*(char *)(iVar1 + 0x421) == '\x02') {
        (**(code **)(*DAT_803dd6e8 + 0x58))((int)*(float *)(iVar1 + 0x4b8),0x5cd);
        (**(code **)(*DAT_803dd6e8 + 0x68))((double)FLOAT_803e6830);
      }
    }
    if (*(short *)(param_1 + 0x46) == 0x72) {
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x6a) = 0x14;
      *(undefined *)(*(int *)(param_1 + 0x54) + 0x6b) = 0x14;
    }
  }
  return;
}

