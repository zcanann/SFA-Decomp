// Function: FUN_802b8d44
// Entry: 802b8d44
// Size: 212 bytes

void FUN_802b8d44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
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
  
  iVar4 = *(int *)(param_10 + 0x40c);
  if ((*(short *)(iVar4 + 0x26) != *(short *)(iVar4 + 0x28)) && (*(char *)(param_9 + 0x36) != '\0'))
  {
    iVar3 = *(int *)(param_9 + 200);
    if (iVar3 != 0) {
      uVar5 = FUN_80037da8(param_9,iVar3);
      param_1 = FUN_8002cc9c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3);
    }
    uVar1 = FUN_8002e144();
    if ((uVar1 & 0xff) == 0) {
      *(undefined2 *)(iVar4 + 0x26) = 0;
    }
    else if (0 < *(short *)(iVar4 + 0x28)) {
      puVar2 = FUN_8002becc(0x20,*(short *)(iVar4 + 0x28));
      iVar3 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,4,
                           *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),
                           in_r8,in_r9,in_r10);
      FUN_80037e24(param_9,iVar3,0);
      *(undefined2 *)(iVar4 + 0x26) = *(undefined2 *)(iVar4 + 0x28);
    }
  }
  return;
}

