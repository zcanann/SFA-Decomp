// Function: FUN_802bb3c0
// Entry: 802bb3c0
// Size: 240 bytes

void FUN_802bb3c0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860d4();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0xb8);
  if (param_6 == -1) {
    FUN_8003b8f4((double)FLOAT_803e8258);
    FUN_8003842c(iVar1,1,iVar2 + 0x9e8,iVar2 + 0x9ec,iVar2 + 0x9f0,0);
    FUN_80038280(iVar1,2,4,iVar2 + 0x9b0);
  }
  if ((*(char *)(iVar2 + 0xa8a) != '\x02') && (param_6 != '\0')) {
    FUN_8003b8f4((double)FLOAT_803e8258,iVar1,(int)uVar3,param_3,param_4,param_5);
    FUN_8003842c(iVar1,1,iVar2 + 0x9e8,iVar2 + 0x9ec,iVar2 + 0x9f0,0);
    FUN_80038280(iVar1,2,4,iVar2 + 0x9b0);
  }
  FUN_80286120();
  return;
}

