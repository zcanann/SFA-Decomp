// Function: FUN_8014a4b8
// Entry: 8014a4b8
// Size: 248 bytes

void FUN_8014a4b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  iVar3 = *(int *)(param_9 + 0x4c);
  if ((*(short *)(param_10 + 0x2b4) != *(short *)(param_10 + 0x2b6)) &&
     (*(char *)(param_9 + 0x36) != '\0')) {
    iVar4 = *(int *)(param_9 + 200);
    if (iVar4 != 0) {
      uVar5 = FUN_80037da8(param_9,iVar4);
      param_1 = FUN_8002cc9c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
    }
    uVar1 = FUN_8002e144();
    if ((uVar1 & 0xff) == 0) {
      *(undefined2 *)(param_10 + 0x2b4) = 0;
    }
    else if (0 < *(short *)(param_10 + 0x2b6)) {
      puVar2 = FUN_8002becc(0x20,*(short *)(param_10 + 0x2b6));
      *(byte *)((int)puVar2 + 5) = *(byte *)((int)puVar2 + 5) | *(byte *)(iVar3 + 5) & 0x18;
      iVar3 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,4,
                           *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),
                           in_r8,in_r9,in_r10);
      FUN_80037e24(param_9,iVar3,0);
      *(undefined2 *)(param_10 + 0x2b4) = *(undefined2 *)(param_10 + 0x2b6);
    }
  }
  return;
}

