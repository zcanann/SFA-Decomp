// Function: FUN_80023850
// Entry: 80023850
// Size: 984 bytes

void FUN_80023850(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  ulonglong uVar14;
  
  uVar14 = FUN_802860cc();
  iVar11 = (int)(uVar14 >> 0x20);
  uVar9 = (uint)uVar14;
  iVar7 = 0;
  iVar10 = 0;
  if ((&DAT_803406a4)[iVar11 * 5] + 1 == (&DAT_803406a0)[iVar11 * 5]) {
    FUN_8007d6dc(s_1______mm_Error____________s__No_802caaa8,param_4,iVar11);
    uVar1 = 0;
  }
  else {
    if ((uVar14 & 0x1f) != 0) {
      uVar9 = (uVar9 & 0xffffffe0) + 0x20;
    }
    iVar13 = -1;
    iVar4 = 0x7fffffff;
    iVar12 = (&DAT_803406a8)[iVar11 * 5];
    iVar6 = 0;
    if ((iVar11 == 0) && (iVar3 = iVar12, (int)uVar9 < 210000)) {
      while (iVar2 = (int)*(short *)(iVar3 + 0xc), iVar2 != -1) {
        iVar6 = iVar2;
        iVar3 = iVar12 + iVar2 * 0x1c;
      }
      do {
        iVar3 = iVar12 + iVar6 * 0x1c;
        if (*(short *)(iVar3 + 8) == 0) {
          iVar2 = *(int *)(iVar3 + 4);
          if (iVar2 < (int)uVar9) {
            if (iVar7 < iVar2) {
              iVar7 = iVar2;
            }
          }
          else if (iVar2 < iVar4) {
            iVar4 = iVar2;
            iVar13 = iVar6;
          }
        }
        iVar6 = (int)*(short *)(iVar3 + 10);
      } while (iVar6 != -1);
    }
    else {
      do {
        iVar3 = iVar12 + iVar6 * 0x1c;
        if (*(short *)(iVar3 + 8) == 0) {
          iVar2 = *(int *)(iVar3 + 4);
          if (iVar2 < (int)uVar9) {
            if (iVar7 < iVar2) {
              iVar7 = iVar2;
            }
          }
          else if ((iVar2 < iVar4) && (iVar4 = iVar2, iVar13 = iVar6, iVar11 == 0)) break;
        }
        iVar6 = (int)*(short *)(iVar3 + 0xc);
      } while (iVar6 != -1);
    }
    if (iVar13 == -1) {
      if ((((iVar11 == 2) && (0x3000 < (int)uVar9)) || (iVar11 == 3)) || (iVar11 == 1)) {
        FUN_8007d6dc(s__2______mm_Error____________s__r_802cab3c,param_4,iVar11,param_3,uVar9);
        iVar7 = DAT_803406a8;
        iVar11 = 0;
        while (iVar4 = DAT_803406bc, *(short *)(iVar7 + 0xc) != -1) {
          iVar7 = DAT_803406a8 + *(short *)(iVar7 + 0xc) * 0x1c;
          if ((iVar11 < *(int *)(iVar7 + 4)) && (*(short *)(iVar7 + 8) == 0)) {
            iVar11 = *(int *)(iVar7 + 4);
          }
        }
        while (*(short *)(iVar4 + 0xc) != -1) {
          iVar4 = DAT_803406bc + *(short *)(iVar4 + 0xc) * 0x1c;
          if ((iVar10 < *(int *)(iVar4 + 4)) && (*(short *)(iVar4 + 8) == 0)) {
            iVar10 = *(int *)(iVar4 + 4);
          }
        }
        iVar6 = ((int)DAT_803406d4 >> 10) +
                (uint)((int)DAT_803406d4 < 0 && (DAT_803406d4 & 0x3ff) != 0);
        iVar4 = ((int)DAT_803406c0 >> 10) +
                (uint)((int)DAT_803406c0 < 0 && (DAT_803406c0 & 0x3ff) != 0);
        iVar7 = ((int)DAT_803406ac >> 10) +
                (uint)((int)DAT_803406ac < 0 && (DAT_803406ac & 0x3ff) != 0);
        FUN_80137df4(iVar7,iVar7 - (((int)DAT_803dcb20 >> 10) +
                                   (uint)((int)DAT_803dcb20 < 0 && (DAT_803dcb20 & 0x3ff) != 0)),
                     iVar4,iVar4 - (((int)DAT_803dcb24 >> 10) +
                                   (uint)((int)DAT_803dcb24 < 0 && (DAT_803dcb24 & 0x3ff) != 0)),
                     iVar6,iVar6 - (((int)DAT_803dcb28 >> 10) +
                                   (uint)((int)DAT_803dcb28 < 0 && (DAT_803dcb28 & 0x3ff) != 0)),
                     DAT_803dcc7c,DAT_803dcb1c,uVar9,iVar11,iVar10);
      }
      uVar1 = 0;
    }
    else {
      piVar5 = (int *)(&DAT_803406b0 + iVar11 * 0x14);
      *piVar5 = *piVar5 + uVar9;
      if ((*piVar5 < 0) || ((int)(&DAT_803406ac)[iVar11 * 5] < *piVar5)) {
        FUN_8007d6dc(s__ERROR_alloc__memory_usage_value_802caafc);
      }
      if (((DAT_803db430 == 0) || (iVar11 != 0)) || (209999 < (int)uVar9)) {
        FUN_80023008(iVar11,iVar13,uVar9,1,0,param_3,param_4);
      }
      else {
        iVar13 = FUN_80022e84(0,iVar13,uVar9,1,0,param_3,param_4);
      }
      puVar8 = (undefined4 *)(iVar12 + iVar13 * 0x1c);
      if (DAT_803dcb0c == 0x3ef) {
        FUN_8007d6dc(s_mmUniqueIdent_802cab2c);
      }
      iVar7 = DAT_803dcb0c + 1;
      puVar8[6] = DAT_803dcb0c;
      DAT_803dcb0c = iVar7;
      DAT_803dcb14 = DAT_803dcb14 + 1;
      uVar1 = *puVar8;
    }
  }
  FUN_80286118(uVar1);
  return;
}

