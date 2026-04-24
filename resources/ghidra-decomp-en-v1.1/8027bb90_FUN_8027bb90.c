// Function: FUN_8027bb90
// Entry: 8027bb90
// Size: 612 bytes

/* WARNING: Removing unreachable block (ram,0x8027bbb8) */

void FUN_8027bb90(uint param_1,int *param_2,byte param_3,int param_4)

{
  ushort uVar1;
  int *piVar2;
  
  uVar1 = (ushort)param_1;
  if (param_3 == 2) {
    uVar1 = uVar1 | 0x4000;
    if (param_4 == 0) {
      if (param_2 == (int *)0x0) {
        piVar2 = (int *)0x0;
      }
      else {
        for (piVar2 = (int *)((int)param_2 + param_2[2]); *piVar2 != -1;
            piVar2 = (int *)((int)piVar2 + *piVar2)) {
          if ((uint)*(ushort *)(piVar2 + 1) == (param_1 & 0xffff | 0x4000)) goto LAB_8027bca0;
        }
        piVar2 = (int *)0x0;
      }
LAB_8027bca0:
      if (piVar2 == (int *)0x0) {
        FUN_8027411c(uVar1,0);
      }
      else {
        FUN_8027411c(uVar1,piVar2 + 2);
      }
    }
    else {
      FUN_8027430c(uVar1);
    }
  }
  else if (param_3 < 2) {
    if (param_3 == 0) {
      if (param_4 == 0) {
        if (param_2 == (int *)0x0) {
          piVar2 = (int *)0x0;
        }
        else {
          for (piVar2 = (int *)((int)param_2 + *param_2); *piVar2 != -1;
              piVar2 = (int *)((int)piVar2 + *piVar2)) {
            if ((uint)*(ushort *)(piVar2 + 1) == (param_1 & 0xffff)) goto LAB_8027bc20;
          }
          piVar2 = (int *)0x0;
        }
LAB_8027bc20:
        if (piVar2 == (int *)0x0) {
          FUN_80275024(param_1,0);
        }
        else {
          FUN_80275024(param_1,piVar2 + 2);
        }
      }
      else {
        FUN_80275334(param_1);
      }
    }
    else if (param_4 == 0) {
      FUN_80274d8c(uVar1);
    }
    else {
      FUN_80274e64(uVar1);
    }
  }
  else if (param_3 == 4) {
    if (param_4 == 0) {
      if (param_2 == (int *)0x0) {
        piVar2 = (int *)0x0;
      }
      else {
        for (piVar2 = (int *)((int)param_2 + param_2[1]); *piVar2 != -1;
            piVar2 = (int *)((int)piVar2 + *piVar2)) {
          if ((uint)*(ushort *)(piVar2 + 1) == (param_1 & 0xffff)) goto LAB_8027bda8;
        }
        piVar2 = (int *)0x0;
      }
LAB_8027bda8:
      if (piVar2 == (int *)0x0) {
        FUN_802748a4(uVar1,0);
      }
      else {
        FUN_802748a4(uVar1,piVar2 + 2);
      }
    }
    else {
      FUN_80274a9c(uVar1);
    }
  }
  else if (param_3 < 4) {
    uVar1 = uVar1 | 0x8000;
    if (param_4 == 0) {
      if (param_2 == (int *)0x0) {
        piVar2 = (int *)0x0;
      }
      else {
        for (piVar2 = (int *)((int)param_2 + param_2[3]); *piVar2 != -1;
            piVar2 = (int *)((int)piVar2 + *piVar2)) {
          if ((uint)*(ushort *)(piVar2 + 1) == (param_1 & 0xffff | 0x8000)) goto LAB_8027bd20;
        }
        piVar2 = (int *)0x0;
      }
LAB_8027bd20:
      if (piVar2 == (int *)0x0) {
        FUN_80274490(uVar1,0,0);
      }
      else {
        FUN_80274490(uVar1,piVar2 + 3,(short)piVar2[2]);
      }
    }
    else {
      FUN_802746d8(uVar1);
    }
  }
  return;
}

