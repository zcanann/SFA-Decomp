// Function: FUN_8020dd9c
// Entry: 8020dd9c
// Size: 516 bytes

void FUN_8020dd9c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  short sVar1;
  int iVar2;
  int iVar3;
  char cVar4;
  undefined4 uVar5;
  int *piVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860d8();
  iVar2 = (int)((ulonglong)uVar7 >> 0x20);
  uVar5 = (undefined4)uVar7;
  piVar6 = *(int **)(iVar2 + 0xb8);
  sVar1 = **(short **)(iVar2 + 0x4c);
  if (sVar1 == 0x5f5) {
    FUN_8003b8f4((double)FLOAT_803e6678);
  }
  else if ((param_6 != '\0') && (sVar1 != 0x61e)) {
    if (sVar1 < 0x61e) {
      if (sVar1 == 0x5de) {
        if (*(char *)((int)piVar6 + 0x27d) == '\0') {
          FUN_8003b8f4((double)FLOAT_803e6678);
        }
        goto LAB_8020df8c;
      }
      if ((0x5dd < sVar1) && (sVar1 == 0x5e3)) {
        iVar3 = FUN_800221a0(0,0x19);
        if ((iVar3 != 0) && (*(char *)((int)piVar6 + 0x27d) != '\0')) {
          FUN_8025d324(0x1e0,0x32,0x82,0x96);
          FUN_8003b8f4((double)FLOAT_803e6678,iVar2,uVar5,param_3,param_4,param_5);
          FUN_8000f0b8(uVar5);
        }
        goto LAB_8020df8c;
      }
    }
    else {
      if (sVar1 == 0x80f) {
        if ((*piVar6 != 0) && (iVar3 = FUN_8001db64(), iVar3 != 0)) {
          FUN_800604b4(*piVar6);
        }
        FUN_8003b8f4((double)FLOAT_803e6678,iVar2,uVar5,param_3,param_4,param_5);
        goto LAB_8020df8c;
      }
      if ((sVar1 < 0x80f) && (sVar1 == 0x740)) {
        if ((*(char *)((int)piVar6 + 0x27d) == '\0') ||
           ((cVar4 = FUN_8012ddac(), cVar4 != '\0' ||
            (iVar3 = (**(code **)(*DAT_803dca4c + 0x14))(), iVar3 == 0)))) {
          DAT_803ddd34 = 2;
        }
        else if (DAT_803ddd34 == 0) {
          FUN_8003b8f4((double)FLOAT_803e6678,iVar2,uVar5,param_3,param_4,param_5);
        }
        else {
          DAT_803ddd34 = DAT_803ddd34 + -1;
        }
        goto LAB_8020df8c;
      }
    }
    FUN_8003b8f4((double)FLOAT_803e6678,iVar2,uVar5,param_3,param_4,param_5);
  }
LAB_8020df8c:
  FUN_80286124();
  return;
}

