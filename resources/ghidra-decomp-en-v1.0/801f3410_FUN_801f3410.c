// Function: FUN_801f3410
// Entry: 801f3410
// Size: 152 bytes

void FUN_801f3410(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = **(int **)(iVar1 + 0xb8);
  if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0')) {
    FUN_800604b4();
  }
  if (param_6 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e5e08,iVar1,(int)uVar3,param_3,param_4,param_5);
  }
  FUN_80286124();
  return;
}

