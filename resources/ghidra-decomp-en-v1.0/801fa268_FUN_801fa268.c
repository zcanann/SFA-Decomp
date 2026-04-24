// Function: FUN_801fa268
// Entry: 801fa268
// Size: 136 bytes

void FUN_801fa268(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar2 >> 0x20);
  if ((param_6 != '\0') && (*(char *)(iVar1 + 0x36) != '\0')) {
    FUN_80053ed0(8);
    FUN_8003b8f4((double)FLOAT_803e6088,iVar1,(int)uVar2,param_3,param_4,param_5);
    FUN_80053ebc(8);
  }
  FUN_80286128();
  return;
}

