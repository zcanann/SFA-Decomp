// Function: FUN_80113278
// Entry: 80113278
// Size: 124 bytes

undefined4 FUN_80113278(int param_1,int param_2,char param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  if (((param_3 == '\0') || ('\0' < *(char *)(param_2 + 0x354))) ||
     (*(char *)(param_1 + 0x36) != '\0')) {
    if ((*(int *)(param_1 + 0x30) == 0) &&
       (iVar2 = FUN_8005b2fc((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                             (double)*(float *)(param_1 + 0x14)), iVar2 < 0)) {
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

