// Function: FUN_8015281c
// Entry: 8015281c
// Size: 208 bytes

undefined4
FUN_8015281c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined2 param_10
            )

{
  uint uVar1;
  undefined4 uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  FUN_8002bac4();
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) == 0) {
    uVar2 = 0;
  }
  else {
    puVar3 = FUN_8002becc(0x24,param_10);
    *puVar3 = param_10;
    *(undefined *)(puVar3 + 2) = *(undefined *)(iVar4 + 4);
    *(undefined *)(puVar3 + 3) = *(undefined *)(iVar4 + 6);
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)((int)puVar3 + 7) = *(undefined *)(iVar4 + 7);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)((int)puVar3 + 0x19) = 0;
    puVar3[0x10] = 0x95;
    uVar2 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,
                         in_r9,in_r10);
  }
  return uVar2;
}

