// Function: FUN_801a0270
// Entry: 801a0270
// Size: 484 bytes

void FUN_801a0270(void)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  char in_r8;
  int *piVar4;
  
  iVar1 = FUN_80286838();
  piVar4 = *(int **)(iVar1 + 0xb8);
  uVar2 = FUN_80020078(0x50);
  if (uVar2 == 0) {
    uVar2 = FUN_80020078(0x4d);
    if ((uVar2 == 0) || (in_r8 == '\0')) {
      if ((piVar4 != (int *)0x0) && (iVar3 = *piVar4, iVar3 != 0)) {
        if (*(char *)((int)piVar4 + 0x73) == '\0') {
          if (in_r8 != '\0') {
            iVar3 = FUN_8005a310(iVar3);
            if (iVar3 != 0) {
              FUN_8003b9ec(*piVar4);
              FUN_80038524(*piVar4,0,(float *)(iVar1 + 0xc),(undefined4 *)(iVar1 + 0x10),
                           (float *)(iVar1 + 0x14),0);
            }
            FUN_8003b9ec(iVar1);
          }
        }
        else {
          iVar3 = FUN_8005a310(iVar3);
          if (iVar3 != 0) {
            FUN_8003b9ec(*piVar4);
          }
          if (in_r8 != '\0') {
            FUN_8003b9ec(iVar1);
          }
        }
      }
    }
    else {
      FUN_8003b9ec(iVar1);
      if ((*piVar4 != 0) && (iVar1 = FUN_8005a310(*piVar4), iVar1 != 0)) {
        FUN_8003b9ec(*piVar4);
      }
    }
  }
  else if ((*piVar4 != 0) && (iVar1 = FUN_8005a310(*piVar4), iVar1 != 0)) {
    FUN_8003b9ec(*piVar4);
  }
  FUN_80286884();
  return;
}

