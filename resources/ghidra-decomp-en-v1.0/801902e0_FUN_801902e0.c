// Function: FUN_801902e0
// Entry: 801902e0
// Size: 308 bytes

void FUN_801902e0(int param_1,int param_2)

{
  int iVar1;
  undefined4 local_18 [2];
  undefined4 local_10;
  uint uStack12;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  local_18[0] = 0x21;
  *(float *)(param_1 + 8) = FLOAT_803e3e80 * *(float *)(*(int *)(param_1 + 0x50) + 4);
  *(undefined2 *)(iVar1 + 0x112) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined2 *)(iVar1 + 0x110) = *(undefined2 *)(param_2 + 0x20);
  *(undefined2 *)(iVar1 + 0x114) = 0xfffe;
  *(undefined2 *)(iVar1 + 0x116) = *(undefined2 *)(param_2 + 0x22);
  *(undefined2 *)(iVar1 + 0x118) = *(undefined2 *)(param_2 + 0x18);
  *(undefined2 *)(iVar1 + 0x11a) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(iVar1 + 0x11c) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x10);
  if (*(short *)(iVar1 + 0x110) == 0) {
    *(undefined *)(iVar1 + 0x11e) = 0;
  }
  else {
    *(undefined *)(iVar1 + 0x11e) = 1;
  }
  if (*(char *)(param_2 + 0x24) != '\0') {
    *(byte *)(iVar1 + 0x120) = *(byte *)(iVar1 + 0x120) | 1;
    uStack12 = (int)*(char *)(param_2 + 0x25) ^ 0x80000000;
    local_10 = 0x43300000;
    *(float *)(iVar1 + 0x10c) =
         (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e3e90) / FLOAT_803e3e84;
    (**(code **)(*DAT_803dca9c + 0x8c))((double)FLOAT_803e3e88,iVar1,param_1,local_18,0xffffffff);
  }
  FUN_80037200(param_1,0x1c);
  return;
}

