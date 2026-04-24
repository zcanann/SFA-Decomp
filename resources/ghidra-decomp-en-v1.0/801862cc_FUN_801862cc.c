// Function: FUN_801862cc
// Entry: 801862cc
// Size: 408 bytes

void FUN_801862cc(undefined2 *param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = 0;
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x4c) = 0x10;
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x48) = 0x10;
  FUN_80035f00();
  FUN_80037200(param_1,0x10);
  *(undefined2 *)(puVar2 + 4) = 0;
  *(undefined *)((int)puVar2 + 0x23) = 0;
  if (*(short *)(param_2 + 0x1c) == 0) {
    puVar2[1] = 0;
  }
  else {
    puVar2[1] = *(short *)(param_2 + 0x1c) * 0x34bc0;
  }
  *puVar2 = 0;
  *(undefined *)((int)puVar2 + 0x25) = 0;
  DAT_803ddad0 = FUN_80013ec8(0x5b,1);
  DAT_803ddad4 = FUN_80013ec8(0xaa,1);
  *(undefined2 *)((int)puVar2 + 0x16) = 100;
  *(undefined2 *)(puVar2 + 6) = 400;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined2 *)(puVar2 + 5) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined2 *)((int)puVar2 + 0x12) = *(undefined2 *)(param_2 + 0x20);
  if (*(short *)((int)puVar2 + 0x12) == 0) {
    *(undefined2 *)((int)puVar2 + 0x12) = 0x1e;
  }
  *(undefined2 *)((int)puVar2 + 0x1a) = 800;
  *(undefined2 *)((int)puVar2 + 0x1e) = 0;
  *(undefined *)((int)puVar2 + 0x26) = 0xff;
  *(undefined *)((int)puVar2 + 0x27) = 0;
  if ((int)*(char *)(param_2 + 0x19) == 0) {
    puVar2[2] = FLOAT_803e3a84;
  }
  else {
    puVar2[2] = FLOAT_803e3a80 *
                (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000) -
                       DOUBLE_803e3a78);
  }
  *(undefined4 *)(param_1 + 0x7a) = 0;
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0x8000;
  }
  return;
}

