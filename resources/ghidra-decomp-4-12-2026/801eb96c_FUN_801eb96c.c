// Function: FUN_801eb96c
// Entry: 801eb96c
// Size: 236 bytes

void FUN_801eb96c(undefined2 *param_1)

{
  undefined2 uVar1;
  float fVar2;
  int iVar3;
  
  fVar2 = FLOAT_803e6780;
  iVar3 = *(int *)(param_1 + 0x5c);
  if ((*(byte *)(iVar3 + 0x428) >> 1 & 1) == 0) {
    *(float *)(iVar3 + 0x494) = FLOAT_803e6780;
    *(float *)(iVar3 + 0x498) = fVar2;
    *(float *)(iVar3 + 0x49c) = FLOAT_803e6834;
    *(byte *)(iVar3 + 0x428) = *(byte *)(iVar3 + 0x428) & 0x7f;
    *(float *)(iVar3 + 0x424) = fVar2;
    uVar1 = *param_1;
    *(undefined2 *)(iVar3 + 0x40e) = uVar1;
    *(undefined2 *)(iVar3 + 0x40c) = uVar1;
    *(float *)(iVar3 + 0x430) = FLOAT_803e680c;
  }
  FUN_80036018((int)param_1);
  (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar3 + 0x178);
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x10) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x14) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x18) = *(undefined4 *)(param_1 + 10);
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x1c) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x20) = *(undefined4 *)(param_1 + 0xe);
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x24) = *(undefined4 *)(param_1 + 0x10);
  return;
}

