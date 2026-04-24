// Function: FUN_8001b86c
// Entry: 8001b86c
// Size: 960 bytes

/* WARNING: Removing unreachable block (ram,0x8001bc0c) */
/* WARNING: Removing unreachable block (ram,0x8001bc04) */
/* WARNING: Removing unreachable block (ram,0x8001b884) */
/* WARNING: Removing unreachable block (ram,0x8001b87c) */

void FUN_8001b86c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 *puVar1;
  bool bVar2;
  ushort *puVar3;
  undefined4 uVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int unaff_r29;
  uint uVar10;
  undefined8 uVar11;
  double in_f30;
  double dVar12;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  int local_58;
  uint local_54;
  int local_50;
  int local_4c;
  undefined4 local_48;
  uint uStack_44;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar11 = FUN_80286834();
  uVar10 = 0;
  dVar12 = (double)FLOAT_803df3b0;
  if (DAT_803dd670 != 0) {
    unaff_r29 = FUN_80019b4c();
    uVar11 = FUN_80019b54(1,1);
  }
  puVar3 = FUN_800195a8(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dd67c)
  ;
  DAT_803dd698 = 0;
  DAT_803dd694 = 0;
  for (iVar8 = 0; iVar8 < 0x100; iVar8 = iVar8 + 1) {
    (&DAT_8033c6a0)[iVar8] = FLOAT_803df3b4;
  }
  for (iVar8 = 0; iVar8 < (int)(uint)puVar3[1]; iVar8 = iVar8 + 1) {
    iVar9 = *(int *)(*(int *)(puVar3 + 4) + iVar8 * 4);
    iVar7 = FUN_80018f0c(iVar9,0xe018,&local_54);
    if (iVar7 != 0) {
      iVar7 = local_4c / 0x3c + (local_4c >> 0x1f);
      (&DAT_8033c6a0)[DAT_803dd698] =
           (float)((double)CONCAT44(0x43300000,
                                    local_50 + local_54 * 0x3c + (iVar7 - (iVar7 >> 0x1f)) ^
                                    0x80000000) - DOUBLE_803df3a8);
    }
    uStack_44 = (uint)DAT_802c7cc2;
    local_48 = 0x43300000;
    iVar7 = FUN_80016cd4((double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803df3b8),
                         (double)DAT_802c7ccc,iVar9,&local_58,(float *)0x0);
    if (iVar7 != 0) {
      for (iVar9 = 0; iVar9 < local_58; iVar9 = iVar9 + 1) {
        puVar1 = &DAT_8033c2a0 + DAT_803dd698;
        DAT_803dd698 = DAT_803dd698 + 1;
        *puVar1 = *(undefined4 *)(iVar7 + iVar9 * 4);
      }
      if ((&DAT_8033bea0)[DAT_803dd694] != 0) {
        uVar4 = FUN_800238f8(0);
        FUN_800238c4((&DAT_8033bea0)[DAT_803dd694]);
        FUN_800238f8(uVar4);
      }
      piVar5 = &DAT_8033bea0 + DAT_803dd694;
      DAT_803dd694 = DAT_803dd694 + 1;
      *piVar5 = iVar7;
    }
  }
  iVar8 = 0;
LAB_8001bbc8:
  if (DAT_803dd698 <= iVar8) {
    DAT_803dd688 = 0;
    DAT_803dd690 = 0;
    DAT_803dd684 = 2;
    if (DAT_803dd670 != 0) {
      FUN_80019b54(unaff_r29,1);
    }
    FUN_80286880();
    return;
  }
  if (FLOAT_803df3b4 == (float)(&DAT_8033c6a0)[iVar8]) {
    bVar2 = false;
    iVar7 = iVar8;
    for (iVar9 = 0; iVar9 < 0x100; iVar9 = iVar9 + 1) {
      uStack_44 = uVar10 ^ 0x80000000;
      local_48 = 0x43300000;
      if (iVar7 < 0xff) {
        if (FLOAT_803df3b4 != (float)(&DAT_8033c6a4)[iVar7]) {
          in_f31 = (double)(float)((double)(float)(&DAT_8033c6a4)[iVar7] - dVar12);
          bVar2 = true;
        }
        uVar6 = FUN_80018644((&DAT_8033c2a0)[iVar7]);
        uStack_44 = uVar6 ^ 0x80000000;
        (&DAT_8033c6a0)[iVar7] = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803df3a8);
        uVar10 = uVar10 + uVar6;
        if (bVar2) goto LAB_8001bba8;
        iVar7 = iVar7 + 1;
      }
      local_48 = 0x43300000;
    }
  }
  else {
    dVar12 = (double)(float)(&DAT_8033c6a0)[iVar8];
    uVar10 = FUN_80018644((&DAT_8033c2a0)[iVar8]);
  }
  goto LAB_8001bbc4;
LAB_8001bba8:
  for (; local_48 = 0x43300000, iVar8 <= iVar7; iVar7 = iVar7 + -1) {
    uStack_44 = uVar10 ^ 0x80000000;
    (&DAT_8033c6a0)[iVar7] =
         -(float)(in_f31 * (double)((float)(&DAT_8033c6a0)[iVar7] /
                                   (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803df3a8)
                                   ) - (double)(float)(&DAT_8033c6a4)[iVar7]);
  }
LAB_8001bbc4:
  iVar8 = iVar8 + 1;
  goto LAB_8001bbc8;
}

