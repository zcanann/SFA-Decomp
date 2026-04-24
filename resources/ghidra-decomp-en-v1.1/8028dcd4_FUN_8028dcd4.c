// Function: FUN_8028dcd4
// Entry: 8028dcd4
// Size: 308 bytes

void FUN_8028dcd4(int *param_1)

{
  bool bVar1;
  int *piVar2;
  int *piVar3;
  uint uVar4;
  
  if (DAT_803df080 == '\0') {
    FUN_800033a8(-0x7fc247e8,0,0x34);
    DAT_803df080 = '\x01';
  }
  if (param_1 != (int *)0x0) {
    if ((param_1[-1] & 1U) == 0) {
      uVar4 = *(uint *)(param_1[-1] + 8);
    }
    else {
      uVar4 = (param_1[-2] & 0xfffffff8U) - 8;
    }
    if (uVar4 < 0x45) {
      FUN_8028de08(&DAT_803db818,param_1,uVar4);
    }
    else {
      piVar2 = (int *)(param_1[-1] & 0xfffffffe);
      FUN_8028e0c0((int)piVar2,(uint *)(param_1 + -2));
      bVar1 = false;
      if (((piVar2[4] & 2U) == 0) && ((piVar2[4] & 0xfffffff8U) == (piVar2[3] & 0xfffffff8U) - 0x18)
         ) {
        bVar1 = true;
      }
      if (bVar1) {
        piVar3 = (int *)piVar2[1];
        if (piVar3 == piVar2) {
          piVar3 = (int *)0x0;
        }
        if (DAT_803db818 == piVar2) {
          DAT_803db818 = piVar3;
        }
        if (piVar3 != (int *)0x0) {
          *piVar3 = *piVar2;
          *(int **)(*piVar3 + 4) = piVar3;
        }
        piVar2[1] = 0;
        *piVar2 = 0;
        FUN_80286f20((int)piVar2);
      }
    }
  }
  return;
}

