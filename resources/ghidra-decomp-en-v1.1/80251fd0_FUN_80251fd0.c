// Function: FUN_80251fd0
// Entry: 80251fd0
// Size: 160 bytes

void FUN_80251fd0(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803decf8;
  if (DAT_803decf8 == 0) {
    DAT_803decf4 = param_1;
    DAT_803decf8 = param_1;
    DAT_803decfc = param_1;
    *(undefined4 *)(param_1 + 0x3c) = 0;
    *(undefined4 *)(param_1 + 0x38) = 0;
    return;
  }
  do {
    iVar1 = DAT_803decf8;
    if (iVar2 == 0) {
LAB_80252048:
      DAT_803decf8 = iVar1;
      if (iVar2 == 0) {
        *(int *)(DAT_803decf4 + 0x38) = param_1;
        *(undefined4 *)(param_1 + 0x38) = 0;
        *(int *)(param_1 + 0x3c) = DAT_803decf4;
        DAT_803decf4 = param_1;
        return;
      }
      return;
    }
    if (*(uint *)(param_1 + 4) < *(uint *)(iVar2 + 4)) {
      *(undefined4 *)(param_1 + 0x3c) = *(undefined4 *)(iVar2 + 0x3c);
      *(int *)(iVar2 + 0x3c) = param_1;
      *(int *)(param_1 + 0x38) = iVar2;
      iVar1 = param_1;
      if (*(int *)(param_1 + 0x3c) != 0) {
        *(int *)(*(int *)(param_1 + 0x3c) + 0x38) = param_1;
        iVar1 = DAT_803decf8;
      }
      goto LAB_80252048;
    }
    iVar2 = *(int *)(iVar2 + 0x38);
  } while( true );
}

