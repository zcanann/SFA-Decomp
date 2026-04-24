// Function: FUN_8028d574
// Entry: 8028d574
// Size: 308 bytes

void FUN_8028d574(int param_1)

{
  int *piVar1;
  int *piVar2;
  uint uVar3;
  bool bVar4;
  
  if (DAT_803de400 == '\0') {
    FUN_800033a8(&DAT_803dabb8,0,0x34);
    DAT_803de400 = '\x01';
  }
  if (param_1 != 0) {
    if ((*(uint *)(param_1 + -4) & 1) == 0) {
      uVar3 = *(uint *)(*(uint *)(param_1 + -4) + 8);
    }
    else {
      uVar3 = (*(uint *)(param_1 + -8) & 0xfffffff8) - 8;
    }
    if (uVar3 < 0x45) {
      FUN_8028d6a8(&DAT_803dabb8,param_1);
    }
    else {
      piVar1 = (int *)(*(uint *)(param_1 + -4) & 0xfffffffe);
      FUN_8028d960(piVar1,param_1 + -8);
      bVar4 = false;
      if (((piVar1[4] & 2U) == 0) && ((piVar1[4] & 0xfffffff8U) == (piVar1[3] & 0xfffffff8U) - 0x18)
         ) {
        bVar4 = true;
      }
      if (bVar4) {
        piVar2 = (int *)piVar1[1];
        if (piVar2 == piVar1) {
          piVar2 = (int *)0x0;
        }
        if (DAT_803dabb8 == piVar1) {
          DAT_803dabb8 = piVar2;
        }
        if (piVar2 != (int *)0x0) {
          *piVar2 = *piVar1;
          *(int **)(*piVar2 + 4) = piVar2;
        }
        piVar1[1] = 0;
        *piVar1 = 0;
        FUN_802867bc(piVar1);
      }
    }
  }
  return;
}

