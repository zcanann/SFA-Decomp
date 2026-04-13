// Function: FUN_8000cd0c
// Entry: 8000cd0c
// Size: 360 bytes

int * FUN_8000cd0c(int param_1,ushort param_2,short param_3,int param_4)

{
  int *piVar1;
  int *piVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  
  piVar1 = &DAT_80336c60;
  piVar2 = (int *)0x0;
  if (param_4 == 2) {
    uVar4 = 0;
  }
  else {
    uVar4 = 0xffffffff;
  }
  uVar3 = (int)uVar4 >> 0x1f;
  DAT_803dd4bc = 0;
  iVar5 = 0x38;
  do {
    if ((((*piVar1 != -1) && ((param_1 == 0 || (piVar1[6] == param_1)))) &&
        (((param_2 & 0xff) == 0 || ((param_2 & 0xff & *(ushort *)(piVar1 + 7)) != 0)))) &&
       ((param_3 == 0 || (*(short *)((int)piVar1 + 0x1e) == param_3)))) {
      DAT_803dd4bc = DAT_803dd4bc + 1;
      if (param_4 == 2) {
        if (uVar3 < (uint)(uVar4 < (uint)piVar1[0xd]) + piVar1[0xc]) {
          piVar2 = piVar1;
          uVar3 = piVar1[0xc];
          uVar4 = piVar1[0xd];
        }
      }
      else if (param_4 < 2) {
        if (param_4 == 0) {
          return piVar1;
        }
        if (-1 < param_4) {
LAB_8000ce14:
          if ((uint)piVar1[0xc] < ((uint)piVar1[0xd] < uVar4) + uVar3) {
            piVar2 = piVar1;
            uVar3 = piVar1[0xc];
            uVar4 = piVar1[0xd];
          }
        }
      }
      else if (param_4 < 4) goto LAB_8000ce14;
      if ((param_4 != 3) && (DAT_803dd4bc == 3)) {
        return piVar2;
      }
    }
    piVar1 = piVar1 + 0xe;
    iVar5 = iVar5 + -1;
    if (iVar5 == 0) {
      return piVar2;
    }
  } while( true );
}

