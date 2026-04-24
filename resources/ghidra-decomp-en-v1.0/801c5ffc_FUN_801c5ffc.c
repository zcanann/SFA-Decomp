// Function: FUN_801c5ffc
// Entry: 801c5ffc
// Size: 184 bytes

void FUN_801c5ffc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int *piVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  piVar2 = *(int **)(iVar1 + 0xb8);
  if (param_6 == '\0') {
    if (*piVar2 != 0) {
      FUN_8001db6c((double)FLOAT_803e4fc8,*piVar2,0);
    }
  }
  else {
    if (*piVar2 != 0) {
      FUN_8001db6c((double)FLOAT_803e4fc8,*piVar2,1);
    }
    FUN_8003b8f4((double)FLOAT_803e4fc8,iVar1,(int)uVar3,param_3,param_4,param_5);
    FUN_80099d84((double)FLOAT_803e4fc8,(double)FLOAT_803e4fc8,iVar1,7,*piVar2);
  }
  FUN_80286124();
  return;
}

