// Function: FUN_802201e0
// Entry: 802201e0
// Size: 168 bytes

void FUN_802201e0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860d4();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar3 = *(int *)(iVar1 + 0xb8);
  iVar2 = *(int *)(iVar3 + 0x2c);
  if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0')) {
    FUN_800604b4();
  }
  if ((param_6 != '\0') && ((*(byte *)(iVar3 + 0x41) >> 1 & 1) != 0)) {
    FUN_8003b8f4((double)FLOAT_803e6b78,iVar1,(int)uVar4,param_3,param_4,param_5);
  }
  FUN_80286120();
  return;
}

