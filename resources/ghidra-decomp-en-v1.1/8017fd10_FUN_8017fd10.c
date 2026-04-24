// Function: FUN_8017fd10
// Entry: 8017fd10
// Size: 272 bytes

void FUN_8017fd10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined2 param_10)

{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  piVar3 = *(int **)(param_9 + 0xb8);
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_8002becc(0x30,param_10);
    *(undefined *)(puVar2 + 0xd) = 0x14;
    puVar2[0x16] = 0xffff;
    puVar2[0xe] = 0xffff;
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
    puVar2[0x12] = 0xffff;
    *(undefined *)(puVar2 + 2) = *(undefined *)(iVar4 + 4);
    *(undefined *)(puVar2 + 3) = *(undefined *)(iVar4 + 6);
    *(undefined *)((int)puVar2 + 5) = *(undefined *)(iVar4 + 5);
    *(char *)((int)puVar2 + 7) = *(char *)(iVar4 + 7) + -0xf;
    iVar4 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,
                         in_r9,in_r10);
    if (iVar4 == 0) {
      FUN_800238c4((uint)puVar2);
      *piVar3 = 0;
    }
    else {
      FUN_80037e24(param_9,iVar4,0);
      *piVar3 = iVar4;
    }
  }
  return;
}

