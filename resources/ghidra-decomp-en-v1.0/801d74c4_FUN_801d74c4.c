// Function: FUN_801d74c4
// Entry: 801d74c4
// Size: 216 bytes

void FUN_801d74c4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  float local_38;
  float local_34;
  float local_30 [12];
  
  uVar5 = FUN_802860d4();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  iVar4 = *(int *)(iVar1 + 0xb8);
  if (param_6 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e549c);
    iVar2 = FUN_8002b9ec();
    if ((iVar2 != 0) && (iVar3 = FUN_80296464(), iVar3 != 0)) {
      iVar3 = FUN_8002b588(iVar2);
      *(ushort *)(iVar3 + 0x18) = *(ushort *)(iVar3 + 0x18) & 0xfff7;
      FUN_8003842c(iVar1,*(undefined *)(iVar4 + 8),&local_38,&local_34,local_30,0);
      FUN_80295b2c((double)local_38,(double)local_34,(double)local_30[0],iVar2);
      FUN_802b50d0(iVar2,(int)uVar5,param_3,param_4,param_5,0xffffffff);
    }
  }
  FUN_80286120();
  return;
}

