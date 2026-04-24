// Function: FUN_8017a38c
// Entry: 8017a38c
// Size: 140 bytes

void FUN_8017a38c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0x4c);
  if (param_6 != '\0') {
    if ((*(byte *)(iVar2 + 0x23) & 1) != 0) {
      FUN_8003b608(*(undefined *)(iVar2 + 0x20),*(undefined *)(iVar2 + 0x21),
                   *(undefined *)(iVar2 + 0x22));
    }
    FUN_8003b8f4((double)FLOAT_803e3700,iVar1,(int)uVar3,param_3,param_4,param_5);
  }
  FUN_80286128();
  return;
}

