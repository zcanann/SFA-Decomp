// Function: FUN_801f7340
// Entry: 801f7340
// Size: 144 bytes

void FUN_801f7340(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  uVar2 = (undefined4)uVar3;
  if ((param_6 != '\0') && (*(char *)(*(int *)(iVar1 + 0xb8) + 0xd) != '\0')) {
    FUN_8005d148(uVar2,0x10000);
    FUN_8003b8f4((double)FLOAT_803e5f24,iVar1,uVar2,param_3,param_4,param_5);
    FUN_8005d14c(uVar2,0x10000);
  }
  FUN_80286128();
  return;
}

