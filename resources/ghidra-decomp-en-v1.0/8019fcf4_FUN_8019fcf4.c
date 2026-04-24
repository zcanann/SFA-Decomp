// Function: FUN_8019fcf4
// Entry: 8019fcf4
// Size: 484 bytes

void FUN_8019fcf4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int *piVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_802860d4();
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  uVar3 = (undefined4)uVar5;
  piVar4 = *(int **)(iVar2 + 0xb8);
  iVar1 = FUN_8001ffb4(0x50);
  if (iVar1 == 0) {
    iVar1 = FUN_8001ffb4(0x4d);
    if ((iVar1 == 0) || (param_6 == '\0')) {
      if ((piVar4 != (int *)0x0) && (*piVar4 != 0)) {
        if (*(char *)((int)piVar4 + 0x73) == '\0') {
          if (param_6 != '\0') {
            iVar1 = FUN_8005a194();
            if (iVar1 != 0) {
              FUN_8003b8f4((double)FLOAT_803e4288,*piVar4,uVar3,param_3,param_4,param_5);
              FUN_8003842c(*piVar4,0,iVar2 + 0xc,iVar2 + 0x10,iVar2 + 0x14,0);
            }
            FUN_8003b8f4((double)FLOAT_803e4288,iVar2,uVar3,param_3,param_4,param_5);
          }
        }
        else {
          iVar1 = FUN_8005a194();
          if (iVar1 != 0) {
            FUN_8003b8f4((double)FLOAT_803e4288,*piVar4,uVar3,param_3,param_4,param_5);
          }
          if (param_6 != '\0') {
            FUN_8003b8f4((double)FLOAT_803e4288,iVar2,uVar3,param_3,param_4,param_5);
          }
        }
      }
    }
    else {
      FUN_8003b8f4((double)FLOAT_803e4288,iVar2,uVar3,param_3,param_4,param_5);
      if ((*piVar4 != 0) && (iVar2 = FUN_8005a194(), iVar2 != 0)) {
        FUN_8003b8f4((double)FLOAT_803e4288,*piVar4,uVar3,param_3,param_4,param_5);
      }
    }
  }
  else if ((*piVar4 != 0) && (iVar2 = FUN_8005a194(), iVar2 != 0)) {
    FUN_8003b8f4((double)FLOAT_803e4288,*piVar4,uVar3,param_3,param_4,param_5);
  }
  FUN_80286120();
  return;
}

