// Function: FUN_800d620c
// Entry: 800d620c
// Size: 392 bytes

void FUN_800d620c(uint param_1,float *param_2,char *param_3)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int aiStack_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  iVar2 = FUN_800d57bc(param_1,aiStack_38);
  if (iVar2 != 0) {
    uStack_2c = FUN_80022264(0xffffff9d,99);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    *param_2 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e1170) / FLOAT_803e1180;
    uStack_24 = FUN_80022264(0xffffff9d,99);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    param_2[1] = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1170) / FLOAT_803e1180;
    uStack_1c = FUN_80022264(0,99);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    param_2[2] = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e1170) / FLOAT_803e1180;
    bVar1 = false;
    if ((*(uint *)(iVar2 + 0x20) != 0) &&
       (iVar3 = FUN_800d57bc(*(uint *)(iVar2 + 0x20),aiStack_38), -1 < *(int *)(iVar3 + 0x20))) {
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

