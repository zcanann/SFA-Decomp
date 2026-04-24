// Function: FUN_800417e8
// Entry: 800417e8
// Size: 208 bytes

void FUN_800417e8(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  if (FLOAT_803df684 == *(float *)(param_1 + 8)) {
    DAT_803dd8a4 = 0;
  }
  else {
    piVar1 = (int *)FUN_8002b660(param_1);
    iVar2 = *piVar1;
    if (*(char *)(iVar2 + 0xf6) == '\0') {
      FUN_800404b8(param_1,param_1,iVar2,1);
    }
    else {
      FUN_8003fda8(param_1,param_1,iVar2);
    }
    if (*(short *)(param_1 + 0x44) == 1) {
      iVar2 = param_1;
      for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_1 + 0xeb); iVar3 = iVar3 + 1) {
        if (*(int *)(iVar2 + 200) != 0) {
          FUN_800418b8(*(int *)(iVar2 + 200),param_1,1);
        }
        iVar2 = iVar2 + 4;
      }
    }
  }
  return;
}

