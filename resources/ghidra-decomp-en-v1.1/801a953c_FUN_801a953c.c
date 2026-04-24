// Function: FUN_801a953c
// Entry: 801a953c
// Size: 264 bytes

undefined4
FUN_801a953c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10)

{
  byte bVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_10 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_10 + iVar3 + 0x81);
    if (bVar1 == 2) {
      iVar4 = *(int *)(param_9 + 200);
      if (iVar4 != 0) {
        uVar5 = FUN_80037da8(param_9,iVar4);
        param_1 = FUN_8002cc9c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
      }
      *(undefined4 *)(param_9 + 0xf8) = 0xffffffff;
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      *(undefined4 *)(param_9 + 0xf8) = 0x30b;
      iVar4 = *(int *)(param_9 + 200);
      if (iVar4 != 0) {
        uVar5 = FUN_80037da8(param_9,iVar4);
        param_1 = FUN_8002cc9c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
      }
      puVar2 = FUN_8002becc(0x20,(short)*(undefined4 *)(param_9 + 0xf8));
      iVar4 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,4,
                           *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),
                           in_r8,in_r9,in_r10);
      param_1 = FUN_80037e24(param_9,iVar4,0);
    }
  }
  return 0;
}

