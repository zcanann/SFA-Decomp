// Function: FUN_800d5f80
// Entry: 800d5f80
// Size: 392 bytes

void FUN_800d5f80(undefined4 param_1,float *param_2,char *param_3)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  undefined auStack56 [8];
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  
  iVar2 = FUN_800d5530(param_1,auStack56);
  if (iVar2 != 0) {
    uStack44 = FUN_800221a0(0xffffff9d,99);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    *param_2 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e04f0) / FLOAT_803e0500;
    uStack36 = FUN_800221a0(0xffffff9d,99);
    uStack36 = uStack36 ^ 0x80000000;
    local_28 = 0x43300000;
    param_2[1] = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e04f0) / FLOAT_803e0500;
    uStack28 = FUN_800221a0(0,99);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    param_2[2] = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e04f0) / FLOAT_803e0500;
    bVar1 = false;
    if ((*(int *)(iVar2 + 0x20) != 0) &&
       (iVar3 = FUN_800d5530(*(int *)(iVar2 + 0x20),auStack56), -1 < *(int *)(iVar3 + 0x20))) {
      bVar1 = true;
    }
    if (*param_3 == '\0') {
      if (bVar1) {
        param_2[4] = *(float *)(iVar2 + 0x20);
      }
      else if (-1 < (int)*(float *)(iVar2 + 0x18)) {
        param_2[4] = *(float *)(iVar2 + 0x18);
        *param_3 = '\x01';
      }
    }
    else if (*(float *)(iVar2 + 0x18) == 0.0) {
      if (bVar1) {
        param_2[4] = *(float *)(iVar2 + 0x20);
        *param_3 = '\0';
      }
    }
    else {
      param_2[4] = *(float *)(iVar2 + 0x18);
    }
  }
  return;
}

