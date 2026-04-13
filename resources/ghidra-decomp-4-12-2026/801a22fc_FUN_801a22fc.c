// Function: FUN_801a22fc
// Entry: 801a22fc
// Size: 2208 bytes

void FUN_801a22fc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  uint uVar2;
  short *psVar3;
  uint uVar4;
  byte bVar8;
  int iVar5;
  int *piVar6;
  int iVar7;
  int *piVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 extraout_f1;
  undefined8 uVar13;
  double dVar14;
  int local_58;
  uint local_54;
  uint local_50;
  float local_4c [2];
  uint uStack_44;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  
  uVar2 = FUN_80286838();
  iVar12 = *(int *)(uVar2 + 0xb8);
  psVar3 = (short *)FUN_8002bac4();
  iVar10 = *(int *)(uVar2 + 0x4c);
  if (*(float *)(iVar12 + 0x54) <= FLOAT_803e4fcc) {
    *(float *)(iVar12 + 0x54) = *(float *)(iVar12 + 0x54) + FLOAT_803dc074;
  }
  uVar4 = FUN_800803dc((float *)(iVar12 + 0x18));
  if (uVar4 == 0) {
    uVar4 = FUN_800803dc((float *)(iVar12 + 0x1c));
    if (uVar4 == 0) {
      if ((*(byte *)(iVar12 + 0x4a) >> 5 & 1) == 0) {
        if (((*(byte *)(iVar12 + 0x4a) >> 2 & 1) == 0) ||
           (bVar8 = FUN_80296434((int)psVar3), bVar8 != 0)) {
          *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) & 0xef;
        }
        else {
          *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 0x10;
        }
      }
      if (*(int *)(uVar2 + 200) == 0) {
        local_4c[0] = FLOAT_803e4fd0;
        iVar5 = FUN_80036f50(0x4c,uVar2,local_4c);
        *(int *)(iVar12 + 0x10) = iVar5;
        if (((iVar5 != 0) && (uVar4 = FUN_80238cc8(*(int *)(iVar12 + 0x10)), uVar4 != 0)) &&
           (*(int *)(*(int *)(iVar12 + 0x10) + 0xc4) == 0)) {
          FUN_80037e24(uVar2,*(int *)(iVar12 + 0x10),0);
        }
      }
      else {
        iVar5 = FUN_80037ad4(*(int *)(iVar12 + 0x10));
        if ((iVar5 == 0) && (*(int *)(iVar12 + 0x10) != 0)) {
          FUN_80037da8(uVar2,*(int *)(iVar12 + 0x10));
          *(undefined4 *)(iVar12 + 0x10) = 0;
        }
      }
      local_54 = 0;
      local_50 = 0;
      while (iVar5 = FUN_800375e4(uVar2,&local_54,(uint *)0x0,&local_50), iVar5 != 0) {
        if (local_54 == 0x10) {
          FUN_801a1380(uVar2,'\0');
          if (local_50 != 0) {
            FUN_800372f8(uVar2,0x16);
          }
        }
        else if (((int)local_54 < 0x10) && (0xe < (int)local_54)) {
          FUN_801a1380(uVar2,'\x01');
        }
      }
      if ((*(byte *)(iVar12 + 0x4a) >> 5 & 1) == 0) {
        *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) & 0xf7;
      }
      else {
        *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
      }
      if (*(char *)(iVar12 + 0x17) == '\0') {
        if (*(char *)(iVar12 + 0x15) == '\0') {
          if ((((*(byte *)(iVar12 + 0x48) >> 6 & 1) != 0) &&
              ((*(byte *)(iVar12 + 0x4a) >> 4 & 1) != 0)) && ((*(byte *)(iVar12 + 0x49) & 2) == 0))
          {
            FUN_800e85f4(uVar2);
          }
        }
        else {
          uVar4 = FUN_802979fc((int)psVar3);
          if ((uVar4 & 0x4000) == 0) {
            FUN_8011f6d0(4);
          }
          else {
            FUN_8011f6d0(5);
          }
        }
        if (((((*(byte *)(iVar12 + 0x49) & 2) == 0) && ((*(byte *)(iVar12 + 0x4a) >> 5 & 1) == 0))
            && (iVar10 = (**(code **)(*DAT_803dd740 + 8))(uVar2,iVar12), iVar10 != 0)) &&
           ((uVar13 = extraout_f1, (*(byte *)(iVar12 + 0x4a) >> 2 & 1) == 0 ||
            (bVar8 = FUN_80296434((int)psVar3), bVar8 != 0)))) {
          *(byte *)(iVar12 + 0x49) = *(byte *)(iVar12 + 0x49) | 1;
          if (*(char *)(iVar12 + 0x15) == '\0') {
            if (*(int *)(iVar12 + 0x10) != 0) {
              FUN_80238cb0(*(int *)(iVar12 + 0x10));
            }
            uVar13 = FUN_8003709c(uVar2,0x16);
          }
          *(undefined *)(iVar12 + 0x15) = 1;
          *(byte *)(iVar12 + 0x4a) = *(byte *)(iVar12 + 0x4a) & 0xbf | 0x40;
          *(short *)(iVar12 + 0x50) = *psVar3;
          FUN_801a17ac(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
        else {
          uVar13 = FUN_80036018(uVar2);
          FUN_801a17ac(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          *(undefined *)(uVar2 + 0x36) = 0xff;
          if (*(char *)(iVar12 + 0x15) != '\0') {
            *(undefined *)(iVar12 + 0x15) = 0;
            uVar4 = FUN_80296e14((int)psVar3);
            if (uVar4 == 0) {
              uVar4 = FUN_80296dfc((int)psVar3);
              if (uVar4 == 0) {
                dVar14 = FUN_80296974((int)psVar3);
                if ((double)FLOAT_803e4f58 == dVar14) {
                  FUN_80035f9c(uVar2);
                  FUN_801a1190();
                }
                else if (*(char *)(iVar12 + 0x17) == '\0') {
                  local_30 = CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
                  dVar14 = (double)FUN_802945e0();
                  *(float *)(iVar12 + 0x20) = (float)dVar14;
                  *(float *)(uVar2 + 0x24) = (float)dVar14;
                  fVar1 = FLOAT_803e4f58;
                  *(float *)(iVar12 + 0x24) = FLOAT_803e4f58;
                  *(float *)(uVar2 + 0x28) = fVar1;
                  local_38 = CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
                  dVar14 = (double)FUN_80294964();
                  *(float *)(iVar12 + 0x28) = (float)dVar14;
                  *(float *)(uVar2 + 0x2c) = (float)dVar14;
                  local_40 = CONCAT44(0x43300000,(int)*psVar3 ^ 0x80000000);
                  dVar14 = (double)FUN_802945e0();
                  *(float *)(uVar2 + 0xc) =
                       (float)((double)FLOAT_803dcae8 * -dVar14 + (double)*(float *)(uVar2 + 0xc));
                  uStack_44 = (int)*psVar3 ^ 0x80000000;
                  local_4c[1] = 176.0;
                  dVar14 = (double)FUN_80294964();
                  *(float *)(uVar2 + 0x14) =
                       (float)((double)FLOAT_803dcae8 * -dVar14 + (double)*(float *)(uVar2 + 0x14));
                  FUN_800372f8(uVar2,0x16);
                }
              }
              else {
                FUN_80035f84(uVar2);
                FUN_801a1190();
              }
            }
            else {
              FUN_80035f9c(uVar2);
            }
            FUN_800372f8(uVar2,0x16);
          }
          FUN_801a1a78(uVar2);
        }
        if (*(char *)(iVar12 + 0x4a) < '\0') {
          *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
          if (((*(byte *)(iVar12 + 0x4a) >> 6 & 1) != 0) && ((char)*(byte *)(iVar12 + 0x4a) < '\0'))
          {
            *(undefined4 *)(iVar12 + 0x20) = *(undefined4 *)(uVar2 + 0x24);
            *(undefined4 *)(iVar12 + 0x24) = *(undefined4 *)(uVar2 + 0x28);
            *(undefined4 *)(iVar12 + 0x28) = *(undefined4 *)(uVar2 + 0x2c);
            *(float *)(iVar12 + 0x24) = FLOAT_803e4f58;
            *(byte *)(iVar12 + 0x4a) = *(byte *)(iVar12 + 0x4a) & 0xbf;
          }
        }
        if ((*(int *)(iVar12 + 0x10) != 0) &&
           (bVar8 = FUN_80238ce0(*(int *)(iVar12 + 0x10)), bVar8 != 0)) {
          *(undefined *)(iVar12 + 0x16) = 10;
        }
      }
      else {
        *(char *)(iVar12 + 0x17) = *(char *)(iVar12 + 0x17) + DAT_803dc070;
        uStack_44 = (uint)*(byte *)(iVar12 + 0x17);
        local_4c[1] = 176.0;
        *(float *)(iVar12 + 0x2c) =
             *(float *)(iVar12 + 0x34) *
             (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4f90) + FLOAT_803e4f74;
        fVar1 = *(float *)(iVar12 + 0x2c);
        local_40 = (longlong)(int)fVar1;
        local_38 = (longlong)(int)(-fVar1 * FLOAT_803e4fc0);
        local_30 = (longlong)(int)(fVar1 * FLOAT_803e4fc0);
        FUN_80035c48(uVar2,(short)(int)fVar1,(short)(int)(-fVar1 * FLOAT_803e4fc0),
                     (short)(int)(fVar1 * FLOAT_803e4fc0));
        if (*(int *)(iVar12 + 0x10) != 0) {
          FUN_80238c8c(*(int *)(iVar12 + 0x10));
        }
        if (0x14 < *(byte *)(iVar12 + 0x17)) {
          if (*(char *)(iVar12 + 0x4a) < '\0') {
            FUN_801a1380(uVar2,'\0');
          }
          iVar5 = 0;
          if (*(short *)(iVar10 + 0x1a) == 0) {
            iVar5 = FUN_80036f50(0x3a,uVar2,(float *)0x0);
          }
          else {
            piVar6 = FUN_80037048(0x3a,&local_58);
            piVar9 = piVar6;
            for (iVar11 = 0; iVar11 < local_58; iVar11 = iVar11 + 1) {
              iVar7 = FUN_80221cc0(*piVar9);
              if (*(short *)(iVar10 + 0x1a) == iVar7) {
                iVar5 = piVar6[iVar11];
                break;
              }
              piVar9 = piVar9 + 1;
            }
          }
          if (iVar5 == 0) {
            FUN_8002cf80(uVar2);
            FUN_80035ff8(uVar2);
            *(ushort *)(uVar2 + 6) = *(ushort *)(uVar2 + 6) | 0x4000;
            FUN_80080404((float *)(iVar12 + 0x18),0x3c);
          }
          else {
            FUN_800033a8(iVar12 + 0x20,0,0xc);
            FUN_800033a8(uVar2 + 0x24,0,0xc);
            *(byte *)(iVar12 + 0x49) = *(byte *)(iVar12 + 0x49) & 0xfd;
            FUN_8003613c(uVar2);
            if (*(char *)(iVar12 + 0x48) < '\0') {
              FUN_80080404((float *)(iVar12 + 0x18),0x3c);
              FUN_800803f8((undefined4 *)(iVar12 + 0x1c));
              FUN_80080404((float *)(iVar12 + 0x1c),0x5a);
              FUN_80221cd0(iVar5,uVar2,0x46);
              FUN_80035ea4(uVar2);
              FUN_80035ff8(uVar2);
              *(ushort *)(uVar2 + 6) = *(ushort *)(uVar2 + 6) | 0x4000;
            }
            else {
              FUN_8002cf80(uVar2);
              FUN_80035ff8(uVar2);
              *(ushort *)(uVar2 + 6) = *(ushort *)(uVar2 + 6) | 0x4000;
            }
          }
        }
      }
    }
    else {
      *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
      FUN_80080434((float *)(iVar12 + 0x1c));
      FUN_800033a8(iVar12 + 0x20,0,0xc);
      FUN_800033a8(uVar2 + 0x24,0,0xc);
    }
  }
  else {
    *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
    iVar10 = FUN_80080434((float *)(iVar12 + 0x18));
    if (iVar10 != 0) {
      *(undefined *)(iVar12 + 0x17) = 0;
      *(undefined *)(iVar12 + 0x16) = 0;
      *(byte *)(iVar12 + 0x49) = *(byte *)(iVar12 + 0x49) | 1;
      *(ushort *)(uVar2 + 6) = *(ushort *)(uVar2 + 6) & 0xbfff;
      FUN_80035ea4(uVar2);
      FUN_80035c48(uVar2,8,-2,0x19);
      FUN_80036018(uVar2);
      FUN_80035f9c(uVar2);
      FUN_801a1a78(uVar2);
      FUN_801a1380(uVar2,'\0');
    }
  }
  FUN_80286884();
  return;
}

