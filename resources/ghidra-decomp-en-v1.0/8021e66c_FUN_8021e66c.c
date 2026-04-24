// Function: FUN_8021e66c
// Entry: 8021e66c
// Size: 220 bytes

void FUN_8021e66c(short *param_1,int param_2,int *param_3)

{
  int iVar1;
  short sVar2;
  undefined auStack40 [12];
  float local_1c;
  undefined4 local_18;
  float local_14;
  
  if (param_2 == 3) {
    *param_3 = 1;
  }
  else if (param_2 < 3) {
    if (1 < param_2) {
      iVar1 = FUN_80114184(0x11,auStack40);
      if (iVar1 == 0) {
        *param_3 = *param_1 + 0x4000;
      }
      else {
        sVar2 = FUN_800217c0((double)(local_1c - *(float *)(param_1 + 6)),
                             (double)(local_14 - *(float *)(param_1 + 10)));
        *param_3 = (int)sVar2 + (int)DAT_803dc328;
        iVar1 = *(int *)(param_1 + 0x5c);
        *(float *)(iVar1 + 0xc1c) = local_1c;
        *(undefined4 *)(iVar1 + 0xc20) = local_18;
        *(float *)(iVar1 + 0xc24) = local_14;
      }
    }
  }
  else if (param_2 < 5) {
    *param_3 = 0;
  }
  return;
}

