// Function: FUN_801d7ab4
// Entry: 801d7ab4
// Size: 216 bytes

void FUN_801d7ab4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  float local_38;
  float local_34;
  float local_30 [12];
  
  uVar6 = FUN_80286838();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  iVar5 = *(int *)(iVar1 + 0xb8);
  if (param_6 != '\0') {
    FUN_8003b9ec(iVar1);
    iVar2 = FUN_8002bac4();
    if ((iVar2 != 0) && (uVar3 = FUN_80296bc4(iVar2), uVar3 != 0)) {
      iVar4 = FUN_8002b660(iVar2);
      *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
      FUN_80038524(iVar1,(uint)*(byte *)(iVar5 + 8),&local_38,&local_34,local_30,0);
      FUN_8029628c((double)local_38,(double)local_34,(double)local_30[0],iVar2);
      FUN_802b5830(iVar2,(int)uVar6,param_3,param_4,param_5,-1);
    }
  }
  FUN_80286884();
  return;
}

