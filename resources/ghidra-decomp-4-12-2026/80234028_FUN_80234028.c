// Function: FUN_80234028
// Entry: 80234028
// Size: 308 bytes

void FUN_80234028(int param_1)

{
  int iVar1;
  char *pcVar2;
  double dVar3;
  
  pcVar2 = *(char **)(param_1 + 0xb8);
  iVar1 = FUN_8022de2c();
  if (iVar1 == 0) {
    iVar1 = FUN_8002bac4();
  }
  dVar3 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18));
  if (dVar3 < (double)FLOAT_803e7eb4) {
    iVar1 = (int)(FLOAT_803e7eb8 * FLOAT_803dc074 +
                 (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) -
                        DOUBLE_803e7ec0));
    if (0xff < iVar1) {
      iVar1 = 0xff;
    }
    *(char *)(param_1 + 0x36) = (char)iVar1;
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    FUN_80036018(param_1);
    if (*(int *)(param_1 + 0xf4) == 0) {
      if (*pcVar2 == '\x01') {
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      }
      *(undefined4 *)(param_1 + 0xf4) = 1;
    }
  }
  return;
}

