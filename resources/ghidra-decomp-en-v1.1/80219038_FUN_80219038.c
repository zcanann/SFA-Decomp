// Function: FUN_80219038
// Entry: 80219038
// Size: 348 bytes

void FUN_80219038(int param_1,int param_2)

{
  double dVar1;
  uint uVar2;
  int iVar3;
  undefined4 *puVar4;
  
  puVar4 = *(undefined4 **)(param_1 + 0xb8);
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6e) = 0x13;
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6f) = 1;
  *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x10);
  dVar1 = DOUBLE_803e7608;
  *(float *)(param_1 + 0x24) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x18)) - DOUBLE_803e7608);
  *(float *)(param_1 + 0x28) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x19)) - dVar1);
  *(float *)(param_1 + 0x2c) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1a)) - dVar1);
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined2 *)(*(int *)(param_1 + 0x54) + 0xb2) = 1;
  }
  FUN_800372f8(param_1,2);
  *(undefined *)(puVar4 + 1) = 0;
  *(undefined *)((int)puVar4 + 5) = 0;
  puVar4[2] = 0;
  *puVar4 = 0;
  puVar4[3] = FLOAT_803e75f4;
  iVar3 = 0;
  do {
    uVar2 = FUN_80022264(0xffff8001,0x7fff);
    *(short *)(puVar4 + 4) = (short)uVar2;
    uVar2 = FUN_80022264(0xfffffc00,0x400);
    *(short *)((int)puVar4 + 0x1a) = (short)uVar2;
    uVar2 = FUN_80022264(0xffff8001,0x7fff);
    *(short *)(puVar4 + 9) = (short)uVar2;
    uVar2 = FUN_80022264(0xfffffc00,0x400);
    *(short *)((int)puVar4 + 0x2e) = (short)uVar2;
    puVar4 = (undefined4 *)((int)puVar4 + 2);
    iVar3 = iVar3 + 1;
  } while (iVar3 < 5);
  return;
}

