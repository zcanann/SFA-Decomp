// Function: FUN_801a1d48
// Entry: 801a1d48
// Size: 2208 bytes

void FUN_801a1d48(void)

{
  float fVar1;
  int iVar2;
  short *psVar3;
  int iVar4;
  undefined4 *puVar5;
  int iVar6;
  uint uVar7;
  undefined4 *puVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  double dVar12;
  int local_58;
  int local_54;
  int local_50;
  float local_4c;
  undefined4 local_48;
  uint uStack68;
  double local_40;
  double local_38;
  double local_30;
  
  iVar2 = FUN_802860d4();
  iVar11 = *(int *)(iVar2 + 0xb8);
  psVar3 = (short *)FUN_8002b9ec();
  iVar9 = *(int *)(iVar2 + 0x4c);
  if (*(float *)(iVar11 + 0x54) <= FLOAT_803e4334) {
    *(float *)(iVar11 + 0x54) = *(float *)(iVar11 + 0x54) + FLOAT_803db414;
  }
  iVar4 = FUN_80080150(iVar11 + 0x18);
  if (iVar4 == 0) {
    iVar4 = FUN_80080150(iVar11 + 0x1c);
    if (iVar4 == 0) {
      if ((*(byte *)(iVar11 + 0x4a) >> 5 & 1) == 0) {
        if (((*(byte *)(iVar11 + 0x4a) >> 1 & 1) == 0) || (iVar4 = FUN_80295cd4(psVar3), iVar4 != 0)
           ) {
          *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) & 0xef;
        }
        else {
          *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 0x10;
        }
      }
      if (*(int *)(iVar2 + 200) == 0) {
        local_4c = FLOAT_803e4338;
        iVar4 = FUN_80036e58(0x4c,iVar2,&local_4c);
        *(int *)(iVar11 + 0x10) = iVar4;
        if (((iVar4 != 0) && (iVar4 = FUN_80238604(*(undefined4 *)(iVar11 + 0x10)), iVar4 != 0)) &&
           (*(int *)(*(int *)(iVar11 + 0x10) + 0xc4) == 0)) {
          FUN_80037d2c(iVar2,*(int *)(iVar11 + 0x10),0);
        }
      }
      else {
        iVar4 = FUN_800379dc(*(undefined4 *)(iVar11 + 0x10));
        if ((iVar4 == 0) && (*(int *)(iVar11 + 0x10) != 0)) {
          FUN_80037cb0(iVar2);
          *(undefined4 *)(iVar11 + 0x10) = 0;
        }
      }
      local_54 = 0;
      local_50 = 0;
      while (iVar4 = FUN_800374ec(iVar2,&local_54,0,&local_50), iVar4 != 0) {
        if (local_54 == 0x10) {
          FUN_801a0e04(iVar2,0);
          if (local_50 != 0) {
            FUN_80037200(iVar2,0x16);
          }
        }
        else if ((local_54 < 0x10) && (0xe < local_54)) {
          FUN_801a0e04(iVar2,1);
        }
      }
      if ((*(byte *)(iVar11 + 0x4a) >> 5 & 1) == 0) {
        *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) & 0xf7;
      }
      else {
        *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
      }
      if (*(char *)(iVar11 + 0x17) == '\0') {
        if (*(char *)(iVar11 + 0x15) == '\0') {
          if ((((*(byte *)(iVar11 + 0x48) >> 6 & 1) != 0) &&
              ((*(byte *)(iVar11 + 0x4a) >> 4 & 1) != 0)) && ((*(byte *)(iVar11 + 0x49) & 2) == 0))
          {
            FUN_800e8370(iVar2);
          }
        }
        else {
          uVar7 = FUN_8029729c(psVar3);
          if ((uVar7 & 0x4000) == 0) {
            FUN_8011f3ec(4);
          }
          else {
            FUN_8011f3ec(5);
          }
        }
        if (((((*(byte *)(iVar11 + 0x49) & 2) == 0) && ((*(byte *)(iVar11 + 0x4a) >> 5 & 1) == 0))
            && (iVar9 = (**(code **)(*DAT_803dcac0 + 8))(iVar2,iVar11), iVar9 != 0)) &&
           (((*(byte *)(iVar11 + 0x4a) >> 1 & 1) == 0 || (iVar9 = FUN_80295cd4(psVar3), iVar9 != 0))
           )) {
          *(byte *)(iVar11 + 0x49) = *(byte *)(iVar11 + 0x49) | 1;
          if (*(char *)(iVar11 + 0x15) == '\0') {
            if (*(int *)(iVar11 + 0x10) != 0) {
              FUN_802385ec();
            }
            FUN_80036fa4(iVar2,0x16);
          }
          *(undefined *)(iVar11 + 0x15) = 1;
          *(byte *)(iVar11 + 0x4a) = *(byte *)(iVar11 + 0x4a) & 0xbf | 0x40;
          *(short *)(iVar11 + 0x50) = *psVar3;
          FUN_801a1230(iVar2);
        }
        else {
          FUN_80035f20(iVar2);
          FUN_801a1230(iVar2);
          *(undefined *)(iVar2 + 0x36) = 0xff;
          if (*(char *)(iVar11 + 0x15) != '\0') {
            *(undefined *)(iVar11 + 0x15) = 0;
            iVar9 = FUN_802966b4(psVar3);
            if (iVar9 == 0) {
              iVar9 = FUN_8029669c(psVar3);
              if (iVar9 == 0) {
                dVar12 = (double)FUN_80296214(psVar3);
                if ((double)FLOAT_803e42c0 == dVar12) {
                  FUN_80035ea4(iVar2);
                  FUN_801a0c14(iVar2,0);
                }
                else if (*(char *)(iVar11 + 0x17) == '\0') {
                  local_30 = (double)CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
                  dVar12 = (double)FUN_80293e80((double)((FLOAT_803e433c *
                                                         (float)(local_30 - DOUBLE_803e4300)) /
                                                        FLOAT_803e4340));
                  *(float *)(iVar11 + 0x20) = (float)dVar12;
                  *(float *)(iVar2 + 0x24) = (float)dVar12;
                  fVar1 = FLOAT_803e42c0;
                  *(float *)(iVar11 + 0x24) = FLOAT_803e42c0;
                  *(float *)(iVar2 + 0x28) = fVar1;
                  local_38 = (double)CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
                  dVar12 = (double)FUN_80294204((double)((FLOAT_803e433c *
                                                         (float)(local_38 - DOUBLE_803e4300)) /
                                                        FLOAT_803e4340));
                  *(float *)(iVar11 + 0x28) = (float)dVar12;
                  *(float *)(iVar2 + 0x2c) = (float)dVar12;
                  local_40 = (double)CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
                  dVar12 = (double)FUN_80293e80((double)((FLOAT_803e433c *
                                                         (float)(local_40 - DOUBLE_803e4300)) /
                                                        FLOAT_803e4340));
                  *(float *)(iVar2 + 0xc) =
                       (float)((double)FLOAT_803dbe80 * -dVar12 + (double)*(float *)(iVar2 + 0xc));
                  uStack68 = (int)*psVar3 ^ 0x80000000;
                  local_48 = 0x43300000;
                  dVar12 = (double)FUN_80294204((double)((FLOAT_803e433c *
                                                         (float)((double)CONCAT44(0x43300000,
                                                                                  uStack68) -
                                                                DOUBLE_803e4300)) / FLOAT_803e4340))
                  ;
                  *(float *)(iVar2 + 0x14) =
                       (float)((double)FLOAT_803dbe80 * -dVar12 + (double)*(float *)(iVar2 + 0x14));
                  FUN_80037200(iVar2,0x16);
                }
              }
              else {
                FUN_80035e8c(iVar2);
                FUN_801a0c14(iVar2,1);
              }
            }
            else {
              FUN_80035ea4(iVar2);
            }
            FUN_80037200(iVar2,0x16);
          }
          FUN_801a14f4(iVar2);
        }
        if (*(char *)(iVar11 + 0x4a) < '\0') {
          *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
          if (((*(byte *)(iVar11 + 0x4a) >> 6 & 1) != 0) && ((char)*(byte *)(iVar11 + 0x4a) < '\0'))
          {
            *(undefined4 *)(iVar11 + 0x20) = *(undefined4 *)(iVar2 + 0x24);
            *(undefined4 *)(iVar11 + 0x24) = *(undefined4 *)(iVar2 + 0x28);
            *(undefined4 *)(iVar11 + 0x28) = *(undefined4 *)(iVar2 + 0x2c);
            *(float *)(iVar11 + 0x24) = FLOAT_803e42c0;
            *(byte *)(iVar11 + 0x4a) = *(byte *)(iVar11 + 0x4a) & 0xbf;
          }
        }
        if ((*(int *)(iVar11 + 0x10) != 0) && (iVar2 = FUN_8023861c(), iVar2 != 0)) {
          *(undefined *)(iVar11 + 0x16) = 10;
        }
      }
      else {
        *(char *)(iVar11 + 0x17) = *(char *)(iVar11 + 0x17) + DAT_803db410;
        uStack68 = (uint)*(byte *)(iVar11 + 0x17);
        local_48 = 0x43300000;
        *(float *)(iVar11 + 0x2c) =
             *(float *)(iVar11 + 0x34) *
             (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e42f8) + FLOAT_803e42dc;
        fVar1 = *(float *)(iVar11 + 0x2c);
        local_40 = (double)(longlong)(int)fVar1;
        local_38 = (double)(longlong)(int)(-fVar1 * FLOAT_803e4328);
        local_30 = (double)(longlong)(int)(fVar1 * FLOAT_803e4328);
        FUN_80035b50(iVar2,(int)fVar1,(int)(-fVar1 * FLOAT_803e4328),(int)(fVar1 * FLOAT_803e4328));
        if (*(int *)(iVar11 + 0x10) != 0) {
          FUN_802385c8();
        }
        if (0x14 < *(byte *)(iVar11 + 0x17)) {
          if (*(char *)(iVar11 + 0x4a) < '\0') {
            FUN_801a0e04(iVar2,0);
          }
          iVar4 = 0;
          if (*(short *)(iVar9 + 0x1a) == 0) {
            iVar4 = FUN_80036e58(0x3a,iVar2,0);
          }
          else {
            puVar5 = (undefined4 *)FUN_80036f50(0x3a,&local_58);
            puVar8 = puVar5;
            for (iVar10 = 0; iVar10 < local_58; iVar10 = iVar10 + 1) {
              iVar6 = FUN_80221670(*puVar8);
              if (*(short *)(iVar9 + 0x1a) == iVar6) {
                iVar4 = puVar5[iVar10];
                break;
              }
              puVar8 = puVar8 + 1;
            }
          }
          if (iVar4 == 0) {
            FUN_8002ce88(iVar2);
            FUN_80035f00(iVar2);
            *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
            FUN_80080178(iVar11 + 0x18,0x3c);
          }
          else {
            FUN_800033a8(iVar11 + 0x20,0,0xc);
            FUN_800033a8(iVar2 + 0x24,0,0xc);
            *(byte *)(iVar11 + 0x49) = *(byte *)(iVar11 + 0x49) & 0xfd;
            FUN_80036044(iVar2);
            if (*(char *)(iVar11 + 0x48) < '\0') {
              FUN_80080178(iVar11 + 0x18,0x3c);
              FUN_8008016c(iVar11 + 0x1c);
              FUN_80080178(iVar11 + 0x1c,0x5a);
              FUN_80221680(iVar4,iVar2,0x46);
              FUN_80035dac(iVar2);
              FUN_80035f00(iVar2);
              *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
            }
            else {
              FUN_8002ce88(iVar2);
              FUN_80035f00(iVar2);
              *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
            }
          }
        }
      }
    }
    else {
      *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
      FUN_800801a8(iVar11 + 0x1c);
      FUN_800033a8(iVar11 + 0x20,0,0xc);
      FUN_800033a8(iVar2 + 0x24,0,0xc);
    }
  }
  else {
    *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
    iVar9 = FUN_800801a8(iVar11 + 0x18);
    if (iVar9 != 0) {
      *(undefined *)(iVar11 + 0x17) = 0;
      *(undefined *)(iVar11 + 0x16) = 0;
      *(byte *)(iVar11 + 0x49) = *(byte *)(iVar11 + 0x49) | 1;
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) & 0xbfff;
      FUN_80035dac(iVar2);
      FUN_80035b50(iVar2,8,0xfffffffe,0x19);
      FUN_80035f20(iVar2);
      FUN_80035ea4(iVar2);
      FUN_801a14f4(iVar2);
      FUN_801a0e04(iVar2,0);
    }
  }
  FUN_80286120();
  return;
}

