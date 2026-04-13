// Function: FUN_80205010
// Entry: 80205010
// Size: 284 bytes

void FUN_80205010(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  iVar3 = *(int *)(param_9 + 0xb8);
  uVar1 = FUN_8002e144();
  if (((((uVar1 & 0xff) != 0) && (*(short *)(iVar4 + 0x1a) == 7)) &&
      (*(short *)(iVar3 + 0x10) = *(short *)(iVar3 + 0x10) - (short)(int)FLOAT_803dc074,
      *(short *)(iVar3 + 0x10) < 1)) &&
     (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0xc)), uVar1 != 0)) {
    *(undefined2 *)(iVar3 + 0x10) = *(undefined2 *)(iVar3 + 0xe);
    puVar2 = FUN_8002becc(0x24,0x71b);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 8);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0xc);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x10);
    *(undefined *)(puVar2 + 2) = *(undefined *)(iVar4 + 4);
    *(undefined *)((int)puVar2 + 5) = *(undefined *)(iVar4 + 5);
    *(undefined *)(puVar2 + 3) = *(undefined *)(iVar4 + 6);
    *(undefined *)((int)puVar2 + 7) = *(undefined *)(iVar4 + 7);
    puVar2[0xf] = 0xffff;
    puVar2[0x10] = 0xffff;
    puVar2[0xd] = 0xdc;
    iVar3 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,
                         in_r9,in_r10);
    *(int *)(iVar3 + 0xf4) = (int)*(char *)(iVar4 + 0x1e);
  }
  return;
}

