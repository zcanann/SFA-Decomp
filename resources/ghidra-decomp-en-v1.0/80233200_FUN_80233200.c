// Function: FUN_80233200
// Entry: 80233200
// Size: 128 bytes

void FUN_80233200(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar3 = *(int *)(iVar1 + 0xb8);
  if ((*(int *)(iVar3 + 4) != 0) && (iVar2 = FUN_8001db64(), iVar2 != 0)) {
    FUN_800604b4(*(undefined4 *)(iVar3 + 4));
  }
  FUN_8003b8f4((double)FLOAT_803e71e4,iVar1,(int)uVar4,param_3,param_4,param_5);
  FUN_80286124();
  return;
}

