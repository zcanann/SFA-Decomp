// Function: FUN_80049200
// Entry: 80049200
// Size: 748 bytes

void FUN_80049200(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined *puVar8;
  int *piVar9;
  undefined **ppuVar10;
  undefined2 *puVar11;
  int *piVar12;
  
  FUN_802860c8();
  if (DAT_803dcc90 == '\0') {
    DAT_803dcc90 = '\x01';
    DAT_803dcc88 = 0;
    DAT_803dcc8c = FUN_8002417c(0x5e,0x40);
    iVar7 = 0;
    puVar6 = &DAT_8035f208;
    do {
      *puVar6 = 0;
      if ((iVar7 < 0x50) && (iVar7 != 0x49)) {
        uVar1 = countLeadingZeros(0x43 - iVar7);
        uVar2 = countLeadingZeros(5 - iVar7);
        if ((uVar1 | uVar2) >> 5 != 0) goto LAB_80049290;
      }
      else {
LAB_80049290:
        FUN_80048328(0,iVar7,0);
      }
      puVar6 = puVar6 + 1;
      iVar7 = iVar7 + 1;
    } while (iVar7 < 0x75);
    uVar1 = 0;
    DAT_803dcc98 = 0;
    iVar7 = 0;
    piVar12 = &DAT_8035f3e8;
    puVar11 = &DAT_8035f548;
    puVar6 = &DAT_8035ef48;
    ppuVar10 = &PTR_s_AUDIO_tab_802cb2f4;
    piVar9 = &DAT_8035f0a8;
    puVar8 = &DAT_8035eef0;
    do {
      if (uVar1 < 0x57) {
                    /* WARNING: Could not recover jumptable at 0x800492f4. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (**(code **)((int)&PTR_LAB_802cc534 + iVar7))();
        return;
      }
      if (*piVar12 == 0) {
        iVar3 = FUN_800240d8(DAT_803dcc8c);
        FUN_80248b9c(*ppuVar10,iVar3);
        *piVar9 = *(int *)(iVar3 + 0x34);
        iVar4 = FUN_80023cc8(*piVar9 + 0x20,0x7d7d7d7d,0);
        *piVar12 = iVar4;
        DAT_803dcc88 = DAT_803dcc88 + 1;
        FUN_80248eac(iVar3,*piVar12,*piVar9,0,FUN_80041d30,2);
      }
      *puVar11 = 0xffff;
      *puVar6 = 0xffffffff;
      *puVar8 = 0;
      piVar12 = piVar12 + 1;
      puVar11 = puVar11 + 1;
      puVar6 = puVar6 + 1;
      ppuVar10 = ppuVar10 + 1;
      piVar9 = piVar9 + 1;
      puVar8 = puVar8 + 1;
      uVar1 = uVar1 + 1;
      iVar7 = iVar7 + 4;
    } while ((int)uVar1 < 0x58);
  }
  if (DAT_803dcc88 == 0) {
    if ((((DAT_803dcc80 & 0x100) == 0) || ((DAT_803dcc80 & 0x400) == 0)) &&
       (((DAT_803dcc84 & 0x100) == 0 || ((DAT_803dcc84 & 0x400) == 0)))) {
      uVar5 = FUN_80022d3c(0);
      FUN_800443cc(5,0x23);
      FUN_800443cc(5,0x24);
      FUN_80022d3c(uVar5);
    }
    else if (((DAT_803dcc84 & 0x100) != 0) && ((DAT_803dcc84 & 0x400) != 0)) {
      FUN_80043ce8(&DAT_8035cef0,0x2a,0x45,0x800);
      FUN_80043ce8(&DAT_8035a010,0x2f,0x49,3000);
      FUN_80043ce8(&DAT_80356010,0x24,0x4e,0x1000);
      FUN_80043ce8(&DAT_80352010,0x21,0x4c,0x1000);
      FUN_80043ce8(&DAT_80350010,0x26,0x48,0x800);
      DAT_803dcc84 = 0;
      DAT_803dcc80 = 0;
      uVar5 = 1;
      goto LAB_800494ec;
    }
  }
  uVar5 = 0;
LAB_800494ec:
  FUN_80286114(uVar5);
  return;
}

