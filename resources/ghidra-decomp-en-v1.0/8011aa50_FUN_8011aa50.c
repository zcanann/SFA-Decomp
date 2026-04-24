// Function: FUN_8011aa50
// Entry: 8011aa50
// Size: 976 bytes

void FUN_8011aa50(void)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined *puVar7;
  undefined4 *puVar8;
  int iVar9;
  undefined2 *puVar10;
  uint uVar11;
  double dVar12;
  double local_28;
  
  uVar3 = FUN_802860d0();
  iVar5 = DAT_803db9fb * 0xc;
  FUN_8001b444(FUN_80135a90);
  dVar12 = (double)(**(code **)(*DAT_803dca4c + 0x18))();
  uVar1 = (uint)((double)FLOAT_803e1d64 - dVar12);
  if ((uVar1 & 0xff) < 0x80) {
    local_28 = (double)CONCAT44(0x43300000,(uVar1 & 0xff) * 0x86 ^ 0x80000000);
    FUN_80135820((double)FLOAT_803e1d68,
                 -(double)((float)(local_28 - DOUBLE_803e1d78) * FLOAT_803e1d70 - FLOAT_803e1d6c));
    uVar11 = 0;
  }
  else {
    FUN_80135820((double)FLOAT_803e1d68,(double)FLOAT_803e1d74);
    uVar11 = (uVar1 & 0x7f) << 1;
  }
  uVar2 = countLeadingZeros(3 - DAT_803db9fb);
  FUN_80134d40(uVar11,uVar2 >> 5 & 0xff,0);
  if (DAT_803db9fb != '\x02') {
    if (DAT_803db9fb < '\x02') {
      if (DAT_803db9fb == '\0') {
        FUN_80019908(0xff,0xff,0xff,uVar11);
        (**(code **)(*DAT_803dcaa0 + 0x14))();
        if (DAT_803db424 != '\0') {
          DAT_803dd6b0 = DAT_803dd6a8;
          iVar4 = 0;
          iVar9 = 0;
          puVar8 = &DAT_803a8658;
          puVar10 = (undefined2 *)&DAT_803db9f0;
          do {
            FUN_8028f688(*puVar8,&DAT_803dba24,*(undefined *)(DAT_803dd6b0 + iVar9 + 4));
            FUN_80019908(0xff,0xff,0xff,uVar11);
            FUN_8001618c(*puVar8,*puVar10);
            iVar9 = iVar9 + 0x24;
            puVar8 = puVar8 + 1;
            puVar10 = puVar10 + 1;
            iVar4 = iVar4 + 1;
          } while (iVar4 < 3);
        }
      }
      else if (-1 < DAT_803db9fb) {
        FUN_80119dd4(uVar3,uVar11);
        FUN_80019908(0xff,0xff,0xff,uVar11);
        iVar9 = 0;
        for (iVar4 = DAT_803dd6b0 + DAT_803dd6a4 * 0x24; (iVar9 < 3 && (*(int *)(iVar4 + 0xc) != 0))
            ; iVar4 = iVar4 + 4) {
          iVar9 = iVar9 + 1;
        }
        puVar7 = &DAT_803db9f8 + (3U - iVar9 & 0xff);
        iVar6 = 0;
        for (iVar4 = 0; iVar4 < iVar9; iVar4 = iVar4 + 1) {
          FUN_8001618c(*(undefined4 *)(DAT_803dd6b0 + DAT_803dd6a4 * 0x24 + iVar6 + 0xc),*puVar7);
          puVar7 = puVar7 + 1;
          iVar6 = iVar6 + 4;
        }
        if (DAT_803dd6b8 != 0) {
          (**(code **)(*DAT_803dcaa4 + 0x18))(DAT_803dd6b8,0,uVar11);
        }
      }
    }
    else if (DAT_803db9fb < '\x04') {
      FUN_80019908(0xff,0xff,0xff,uVar11);
      FUN_80016870(0x324);
    }
  }
  FUN_80019908(0xff,0xff,0xff,uVar11);
  if (*(short *)(&DAT_8031a7c2 + iVar5) != -1) {
    if (uVar11 < 0x7f) {
      FUN_80019908(0xff,0xff,0xff,uVar11 * -2 + 0xff & 0xff);
      FUN_80016870(0x331);
    }
    else {
      FUN_80019908(0xff,0xff,0xff,(uVar11 - 0x7f) * 2 & 0xfe);
      FUN_80016870(*(undefined2 *)(&DAT_8031a7c2 + iVar5));
    }
  }
  if (*(short *)(&DAT_8031a7c4 + iVar5) != -1) {
    FUN_80019908(0xff,0xff,0xff,uVar11);
    FUN_80016870(*(undefined2 *)(&DAT_8031a7c4 + iVar5));
  }
  (**(code **)(*DAT_803dcaa0 + 0x30))(uVar1);
  (**(code **)(*DAT_803dcaa0 + 0x10))(uVar3);
  FUN_8001b444(0);
  FUN_80134c28(0);
  DAT_803dd6ce = DAT_803dd6ce + -1;
  if (DAT_803dd6ce < '\0') {
    DAT_803dd6ce = '\0';
  }
  FUN_8028611c();
  return;
}

