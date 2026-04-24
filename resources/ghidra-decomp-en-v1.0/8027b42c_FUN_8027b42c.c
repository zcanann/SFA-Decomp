// Function: FUN_8027b42c
// Entry: 8027b42c
// Size: 612 bytes

/* WARNING: Removing unreachable block (ram,0x8027b454) */

void FUN_8027b42c(uint param_1,int *param_2,byte param_3,int param_4)

{
  if (param_3 == 2) {
    if (param_4 == 0) {
      if (param_2 == (int *)0x0) {
        param_2 = (int *)0x0;
      }
      else {
        for (param_2 = (int *)((int)param_2 + param_2[2]); *param_2 != -1;
            param_2 = (int *)((int)param_2 + *param_2)) {
          if ((uint)*(ushort *)(param_2 + 1) == (param_1 & 0xffff | 0x4000)) goto LAB_8027b53c;
        }
        param_2 = (int *)0x0;
      }
LAB_8027b53c:
      if (param_2 == (int *)0x0) {
        FUN_802739b8(param_1 | 0x4000,0);
      }
      else {
        FUN_802739b8(param_1 | 0x4000,param_2 + 2);
      }
    }
    else {
      FUN_80273ba8();
    }
  }
  else if (param_3 < 2) {
    if (param_3 == 0) {
      if (param_4 == 0) {
        if (param_2 == (int *)0x0) {
          param_2 = (int *)0x0;
        }
        else {
          for (param_2 = (int *)((int)param_2 + *param_2); *param_2 != -1;
              param_2 = (int *)((int)param_2 + *param_2)) {
            if ((uint)*(ushort *)(param_2 + 1) == (param_1 & 0xffff)) goto LAB_8027b4bc;
          }
          param_2 = (int *)0x0;
        }
LAB_8027b4bc:
        if (param_2 == (int *)0x0) {
          FUN_802748c0(param_1,0);
        }
        else {
          FUN_802748c0(param_1,param_2 + 2);
        }
      }
      else {
        FUN_80274bd0();
      }
    }
    else if (param_4 == 0) {
      FUN_80274628();
    }
    else {
      FUN_80274700();
    }
  }
  else if (param_3 == 4) {
    if (param_4 == 0) {
      if (param_2 == (int *)0x0) {
        param_2 = (int *)0x0;
      }
      else {
        for (param_2 = (int *)((int)param_2 + param_2[1]); *param_2 != -1;
            param_2 = (int *)((int)param_2 + *param_2)) {
          if ((uint)*(ushort *)(param_2 + 1) == (param_1 & 0xffff)) goto LAB_8027b644;
        }
        param_2 = (int *)0x0;
      }
LAB_8027b644:
      if (param_2 == (int *)0x0) {
        FUN_80274140(param_1,0);
      }
      else {
        FUN_80274140(param_1,param_2 + 2);
      }
    }
    else {
      FUN_80274338();
    }
  }
  else if (param_3 < 4) {
    if (param_4 == 0) {
      if (param_2 == (int *)0x0) {
        param_2 = (int *)0x0;
      }
      else {
        for (param_2 = (int *)((int)param_2 + param_2[3]); *param_2 != -1;
            param_2 = (int *)((int)param_2 + *param_2)) {
          if ((uint)*(ushort *)(param_2 + 1) == (param_1 & 0xffff | 0x8000)) goto LAB_8027b5bc;
        }
        param_2 = (int *)0x0;
      }
LAB_8027b5bc:
      if (param_2 == (int *)0x0) {
        FUN_80273d2c(param_1 | 0x8000,0,0);
      }
      else {
        FUN_80273d2c(param_1 | 0x8000,param_2 + 3,param_2[2] & 0xffff);
      }
    }
    else {
      FUN_80273f74();
    }
  }
  return;
}

