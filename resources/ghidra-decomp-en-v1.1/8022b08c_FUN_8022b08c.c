// Function: FUN_8022b08c
// Entry: 8022b08c
// Size: 416 bytes

void FUN_8022b08c(ushort *param_1,int param_2)

{
  short *psVar1;
  int iVar2;
  ushort local_68;
  ushort local_66;
  undefined2 local_64;
  float local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  float afStack_50 [17];
  
  psVar1 = FUN_8000facc();
  local_5c = *(undefined4 *)(param_1 + 6);
  local_58 = *(undefined4 *)(param_1 + 8);
  local_54 = *(undefined4 *)(param_1 + 10);
  local_68 = *param_1;
  local_66 = param_1[1];
  local_64 = 0;
  local_60 = FLOAT_803e7b68;
  FUN_80021fac(afStack_50,&local_68);
  iVar2 = *(int *)(param_2 + 0x418);
  FUN_80022790((double)FLOAT_803e7b64,(double)FLOAT_803e7b64,(double)FLOAT_803e7b88,afStack_50,
               (float *)(iVar2 + 0xc),(float *)(iVar2 + 0x10),(float *)(iVar2 + 0x14));
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
  FUN_80022790((double)FLOAT_803e7b64,(double)FLOAT_803e7b64,(double)FLOAT_803e7b8c,afStack_50,
               (float *)(iVar2 + 0xc),(float *)(iVar2 + 0x10),(float *)(iVar2 + 0x14));
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

