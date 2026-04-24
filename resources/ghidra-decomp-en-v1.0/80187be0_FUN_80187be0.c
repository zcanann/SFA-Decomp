// Function: FUN_80187be0
// Entry: 80187be0
// Size: 140 bytes

void FUN_80187be0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  if ((*(char *)(*(int *)(iVar1 + 0xb8) + 10) == '\0') &&
     (iVar2 = (**(code **)(*DAT_803dcac0 + 0xc))(iVar1,(int)param_6), iVar2 != 0)) {
    FUN_8003b8f4((double)FLOAT_803e3b40,iVar1,(int)uVar3,param_3,param_4,param_5);
  }
  FUN_80286128();
  return;
}

