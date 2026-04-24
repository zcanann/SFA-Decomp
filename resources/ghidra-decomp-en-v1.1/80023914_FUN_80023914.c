// Function: FUN_80023914
// Entry: 80023914
// Size: 984 bytes

void FUN_80023914(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  ulonglong uVar12;
  
  uVar12 = FUN_80286830();
  iVar9 = (int)(uVar12 >> 0x20);
  uVar7 = (uint)uVar12;
  iVar6 = 0;
  iVar8 = 0;
  if ((&DAT_80341304)[iVar9 * 5] + 1 == (&DAT_80341300)[iVar9 * 5]) {
    FUN_8007d858();
  }
  else {
    if ((uVar12 & 0x1f) != 0) {
      uVar7 = (uVar7 & 0xffffffe0) + 0x20;
    }
    iVar11 = -1;
    iVar3 = 0x7fffffff;
    iVar10 = (&DAT_80341308)[iVar9 * 5];
    iVar5 = 0;
    if ((iVar9 == 0) && (iVar2 = iVar10, (int)uVar7 < 210000)) {
      while (iVar1 = (int)*(short *)(iVar2 + 0xc), iVar1 != -1) {
        iVar5 = iVar1;
        iVar2 = iVar10 + iVar1 * 0x1c;
      }
      do {
        iVar2 = iVar10 + iVar5 * 0x1c;
        if (*(short *)(iVar2 + 8) == 0) {
          iVar1 = *(int *)(iVar2 + 4);
          if (iVar1 < (int)uVar7) {
            if (iVar6 < iVar1) {
              iVar6 = iVar1;
            }
          }
          else if (iVar1 < iVar3) {
            iVar3 = iVar1;
            iVar11 = iVar5;
          }
        }
        iVar5 = (int)*(short *)(iVar2 + 10);
      } while (iVar5 != -1);
    }
    else {
      do {
        iVar2 = iVar10 + iVar5 * 0x1c;
        if (*(short *)(iVar2 + 8) == 0) {
          iVar1 = *(int *)(iVar2 + 4);
          if (iVar1 < (int)uVar7) {
            if (iVar6 < iVar1) {
              iVar6 = iVar1;
            }
          }
          else if ((iVar1 < iVar3) && (iVar3 = iVar1, iVar11 = iVar5, iVar9 == 0)) break;
        }
        iVar5 = (int)*(short *)(iVar2 + 0xc);
      } while (iVar5 != -1);
    }
    if (iVar11 == -1) {
      if ((((iVar9 == 2) && (0x3000 < (int)uVar7)) || (iVar9 == 3)) || (iVar9 == 1)) {
        FUN_8007d858();
        iVar6 = DAT_80341308;
        iVar9 = 0;
        while (iVar3 = DAT_8034131c, *(short *)(iVar6 + 0xc) != -1) {
          iVar6 = DAT_80341308 + *(short *)(iVar6 + 0xc) * 0x1c;
          if ((iVar9 < *(int *)(iVar6 + 4)) && (*(short *)(iVar6 + 8) == 0)) {
            iVar9 = *(int *)(iVar6 + 4);
          }
        }
        while (*(short *)(iVar3 + 0xc) != -1) {
          iVar3 = DAT_8034131c + *(short *)(iVar3 + 0xc) * 0x1c;
          if ((iVar8 < *(int *)(iVar3 + 4)) && (*(short *)(iVar3 + 8) == 0)) {
            iVar8 = *(int *)(iVar3 + 4);
          }
        }
        FUN_8013817c();
      }
    }
    else {
      piVar4 = (int *)(&DAT_80341310 + iVar9 * 0x14);
      *piVar4 = *piVar4 + uVar7;
      if ((*piVar4 < 0) || ((int)(&DAT_8034130c)[iVar9 * 5] < *piVar4)) {
        FUN_8007d858();
      }
      if (((DAT_803dc090 == 0) || (iVar9 != 0)) || (209999 < (int)uVar7)) {
        FUN_800230cc(iVar9,iVar11,uVar7,1,0,param_3);
      }
      else {
        iVar11 = FUN_80022f48(0,iVar11,uVar7,1,0,param_3);
      }
      if (DAT_803dd78c == 0x3ef) {
        FUN_8007d858();
      }
      iVar6 = DAT_803dd78c + 1;
      *(int *)(iVar10 + iVar11 * 0x1c + 0x18) = DAT_803dd78c;
      DAT_803dd78c = iVar6;
      DAT_803dd794 = DAT_803dd794 + 1;
    }
  }
  FUN_8028687c();
  return;
}

