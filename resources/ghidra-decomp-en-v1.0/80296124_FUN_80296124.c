// Function: FUN_80296124
// Entry: 80296124
// Size: 128 bytes

void FUN_80296124(undefined2 *param_1,undefined4 *param_2,undefined2 *param_3)

{
  undefined2 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) & 0xffffbfff;
  if (param_2 != (undefined4 *)0x0) {
    *(undefined4 *)(param_1 + 6) = *param_2;
    *(undefined4 *)(param_1 + 8) = param_2[1];
    *(undefined4 *)(param_1 + 10) = param_2[2];
    *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x4000;
  }
  if (param_3 == (undefined2 *)0x0) {
    return;
  }
  uVar1 = *param_3;
  *param_1 = uVar1;
  *(undefined2 *)(iVar2 + 0x478) = uVar1;
  *(undefined2 *)(iVar2 + 0x484) = uVar1;
  *(undefined2 *)(iVar2 + 0x484) = *(undefined2 *)(iVar2 + 0x478);
  param_1[1] = param_3[1];
  param_1[2] = param_3[2];
  *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x4000;
  return;
}

