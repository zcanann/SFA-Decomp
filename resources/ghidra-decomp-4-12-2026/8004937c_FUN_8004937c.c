// Function: FUN_8004937c
// Entry: 8004937c
// Size: 748 bytes

void FUN_8004937c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 *puVar6;
  int iVar7;
  undefined *puVar8;
  int *piVar9;
  undefined **ppuVar10;
  undefined2 *puVar11;
  int *piVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_8028682c();
  if (DAT_803dd910 == '\0') {
    DAT_803dd910 = '\x01';
    DAT_803dd908 = 0;
    DAT_803dd90c = FUN_80024240(0x5e,0x40);
    iVar7 = 0;
    puVar6 = &DAT_8035fe68;
    do {
      *puVar6 = 0;
      if ((iVar7 < 0x50) && (iVar7 != 0x49)) {
        uVar1 = countLeadingZeros(0x43 - iVar7);
        uVar2 = countLeadingZeros(5 - iVar7);
        if (uVar1 >> 5 != 0 || uVar2 >> 5 != 0) goto LAB_8004940c;
      }
      else {
LAB_8004940c:
        uVar13 = FUN_800484a4(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,iVar7
                              ,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      }
      puVar6 = puVar6 + 1;
      iVar7 = iVar7 + 1;
    } while (iVar7 < 0x75);
    uVar1 = 0;
    DAT_803dd918 = 0;
    iVar7 = 0;
    piVar12 = &DAT_80360048;
    puVar11 = &DAT_803601a8;
    puVar6 = &DAT_8035fba8;
    ppuVar10 = &PTR_s_AUDIO_tab_802cbecc;
    piVar9 = &DAT_8035fd08;
    puVar8 = &DAT_8035fb50;
    do {
      if (uVar1 < 0x57) {
                    /* WARNING: Could not recover jumptable at 0x80049470. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (**(code **)((int)&PTR_LAB_802cd0ec + iVar7))();
        return;
      }
      if (*piVar12 == 0) {
        puVar3 = FUN_8002419c(DAT_803dd90c);
        FUN_80249300(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*ppuVar10,
                     (int)puVar3);
        *piVar9 = puVar3[0xd];
        iVar4 = FUN_80023d8c(*piVar9 + 0x20,0x7d7d7d7d);
        *piVar12 = iVar4;
        DAT_803dd908 = DAT_803dd908 + 1;
        FUN_80249610(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,*piVar12,
                     *piVar9,0,FUN_80041e28,2,in_r9,in_r10);
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
  if (DAT_803dd908 == 0) {
    if ((((DAT_803dd900 & 0x100) == 0) || ((DAT_803dd900 & 0x400) == 0)) &&
       (((DAT_803dd904 & 0x100) == 0 || ((DAT_803dd904 & 0x400) == 0)))) {
      uVar5 = FUN_80022e00(0);
      uVar13 = FUN_80044548(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_80044548(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_80022e00(uVar5);
    }
    else if (((DAT_803dd904 & 0x100) != 0) && ((DAT_803dd904 & 0x400) != 0)) {
      FUN_80043e64((uint *)&DAT_8035db50,0x2a,0x45);
      FUN_80043e64((uint *)&DAT_8035ac70,0x2f,0x49);
      FUN_80043e64((uint *)&DAT_80356c70,0x24,0x4e);
      FUN_80043e64((uint *)&DAT_80352c70,0x21,0x4c);
      FUN_80043e64((uint *)&DAT_80350c70,0x26,0x48);
      DAT_803dd904 = 0;
      DAT_803dd900 = 0;
    }
  }
  FUN_80286878();
  return;
}

