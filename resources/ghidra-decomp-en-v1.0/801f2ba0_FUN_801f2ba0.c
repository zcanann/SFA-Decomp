// Function: FUN_801f2ba0
// Entry: 801f2ba0
// Size: 192 bytes

void FUN_801f2ba0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  char cVar3;
  int iVar2;
  undefined8 uVar4;
  
  uVar4 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  if (param_6 != '\0') {
    cVar3 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar1 + 0xac));
    if (cVar3 == '\x04') {
      iVar2 = FUN_8001ffb4(0x2bd);
      if (iVar2 != 0) {
        FUN_8003b8f4((double)FLOAT_803e5dc0,iVar1,(int)uVar4,param_3,param_4,param_5);
      }
    }
    else {
      FUN_8003b8f4((double)FLOAT_803e5dc0,iVar1,(int)uVar4,param_3,param_4,param_5);
    }
  }
  FUN_80286128();
  return;
}

