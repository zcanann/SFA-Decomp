// Function: FUN_800168dc
// Entry: 800168dc
// Size: 824 bytes

void FUN_800168dc(void)

{
  uint uVar1;
  int *extraout_r4;
  bool bVar2;
  uint *puVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  int local_28 [2];
  undefined4 local_20;
  uint uStack28;
  
  FUN_802860dc();
  if (*(int *)(DAT_803dc9ec + 0x1c) != 1) {
    uVar1 = FUN_80019570();
    bVar2 = false;
    if ((0x803399bf < uVar1) && (uVar1 < 0x80339a20)) {
      bVar2 = true;
    }
    if (bVar2) {
      extraout_r4[2] = 1;
    }
    else {
      iVar5 = *(int *)(*(int *)(uVar1 + 8) + extraout_r4[1] * 4);
      uVar7 = 0;
      iVar6 = 0;
      if (iVar5 != 0) {
        while (uVar4 = FUN_80015cb8(iVar5 + iVar6,local_28), uVar4 != 0) {
          iVar6 = iVar6 + local_28[0];
          if ((uVar4 < 0xe000) || (0xf8ff < uVar4)) {
            uVar7 = uVar7 + 1;
          }
          else {
            puVar3 = &DAT_802c86f0;
            iVar8 = 0x17;
            do {
              if (*puVar3 == uVar4) {
                uVar4 = puVar3[1];
                goto LAB_800169d4;
              }
              if (puVar3[2] == uVar4) {
                uVar4 = puVar3[3];
                goto LAB_800169d4;
              }
              puVar3 = puVar3 + 4;
              iVar8 = iVar8 + -1;
            } while (iVar8 != 0);
            uVar4 = 0;
LAB_800169d4:
            iVar6 = iVar6 + uVar4 * 2;
          }
        }
      }
      if (*extraout_r4 == 0) {
        DAT_803dc998 = 0;
        FLOAT_803dc994 = FLOAT_803de700;
        extraout_r4[4] = (uint)*(ushort *)(uVar1 + 2);
        extraout_r4[2] = 0;
        *extraout_r4 = 1;
      }
      if (FLOAT_803de700 == FLOAT_803dc994) {
        FUN_8000bb18(0,0x397);
      }
      DAT_803dc99c = 1;
      DAT_803dc998 = 0;
      FLOAT_803dc994 = FLOAT_803db414 * FLOAT_803db3d0 + FLOAT_803dc994;
      uStack28 = uVar7 - 2 ^ 0x80000000;
      local_20 = 0x43300000;
      if ((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803de6f8) <= FLOAT_803dc994) {
        FUN_8000b824(0,0x397);
      }
      if (extraout_r4[3] != 0) {
        uStack28 = uVar7 ^ 0x80000000;
        if ((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803de6f8) <= FLOAT_803dc994) {
          do {
            if (extraout_r4[3] < 1) {
              extraout_r4[1] = extraout_r4[1] + -1;
            }
            else {
              extraout_r4[1] = extraout_r4[1] + 1;
            }
            iVar5 = extraout_r4[1];
            uVar4 = (uint)*(ushort *)(uVar1 + 2);
          } while ((iVar5 < (int)uVar4) && (**(char **)(*(int *)(uVar1 + 8) + iVar5 * 4) == '\0'));
          if (iVar5 < 0) {
            extraout_r4[1] = 0;
          }
          else if (iVar5 < (int)uVar4) {
            FLOAT_803dc994 = FLOAT_803de700;
          }
          else {
            extraout_r4[1] = uVar4 - 1;
          }
          if (extraout_r4[1] < 0) {
            extraout_r4[1] = 0;
          }
          if ((extraout_r4[1] != *(ushort *)(uVar1 + 2) - 1) ||
             (extraout_r4[3] = 1,
             FLOAT_803dc994 <
             (float)((double)CONCAT44(0x43300000,uVar7 ^ 0x80000000) - DOUBLE_803de6f8))) {
            extraout_r4[2] = 0;
          }
          else {
            extraout_r4[2] = 1;
          }
          uStack28 = uVar7 ^ 0x80000000;
          local_20 = 0x43300000;
          extraout_r4[3] = 0;
        }
        else {
          local_20 = 0x43300000;
          FLOAT_803dc994 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803de6f8);
        }
      }
      FUN_80015e84(*(undefined4 *)(*(int *)(uVar1 + 8) + extraout_r4[1] * 4),0x7c);
    }
  }
  FUN_80286128();
  return;
}

