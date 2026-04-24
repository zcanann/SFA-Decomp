// Function: FUN_8022a9c8
// Entry: 8022a9c8
// Size: 416 bytes

void FUN_8022a9c8(undefined2 *param_1,int param_2)

{
  short *psVar1;
  int iVar2;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  float local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined auStack80 [68];
  
  psVar1 = (short *)FUN_8000faac();
  local_5c = *(undefined4 *)(param_1 + 6);
  local_58 = *(undefined4 *)(param_1 + 8);
  local_54 = *(undefined4 *)(param_1 + 10);
  local_68 = *param_1;
  local_66 = param_1[1];
  local_64 = 0;
  local_60 = FLOAT_803e6ed0;
  FUN_80021ee8(auStack80,&local_68);
  iVar2 = *(int *)(param_2 + 0x418);
  FUN_800226cc((double)FLOAT_803e6ecc,(double)FLOAT_803e6ecc,(double)FLOAT_803e6ef0,auStack80,
               iVar2 + 0xc,iVar2 + 0x10,iVar2 + 0x14);
  *(undefined4 *)(*(int *)(param_2 + 0x418) + 0x18) =
       *(undefined4 *)(*(int *)(param_2 + 0x418) + 0xc);
  *(undefined4 *)(*(int *)(param_2 + 0x418) + 0x1c) =
       *(undefined4 *)(*(int *)(param_2 + 0x418) + 0x10);
  *(undefined4 *)(*(int *)(param_2 + 0x418) + 0x20) =
       *(undefined4 *)(*(int *)(param_2 + 0x418) + 0x14);
  *(short *)(*(int *)(param_2 + 0x418) + 4) = -psVar1[2];
  *(short *)(*(int *)(param_2 + 0x418) + 2) = -psVar1[1];
  **(short **)(param_2 + 0x418) = -0x8000 - *psVar1;
  iVar2 = *(int *)(param_2 + 0x41c);
  FUN_800226cc((double)FLOAT_803e6ecc,(double)FLOAT_803e6ecc,(double)FLOAT_803e6ef4,auStack80,
               iVar2 + 0xc,iVar2 + 0x10,iVar2 + 0x14);
  *(undefined4 *)(*(int *)(param_2 + 0x41c) + 0x18) =
       *(undefined4 *)(*(int *)(param_2 + 0x41c) + 0xc);
  *(undefined4 *)(*(int *)(param_2 + 0x41c) + 0x1c) =
       *(undefined4 *)(*(int *)(param_2 + 0x41c) + 0x10);
  *(undefined4 *)(*(int *)(param_2 + 0x41c) + 0x20) =
       *(undefined4 *)(*(int *)(param_2 + 0x41c) + 0x14);
  *(short *)(*(int *)(param_2 + 0x41c) + 4) = -psVar1[2];
  *(short *)(*(int *)(param_2 + 0x41c) + 2) = -psVar1[1];
  **(short **)(param_2 + 0x41c) = -0x8000 - *psVar1;
  return;
}

