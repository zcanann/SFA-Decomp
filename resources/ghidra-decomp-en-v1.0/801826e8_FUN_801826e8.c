// Function: FUN_801826e8
// Entry: 801826e8
// Size: 2476 bytes

void FUN_801826e8(void)

{
  char cVar1;
  bool bVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  int iVar7;
  uint uVar8;
  short sVar9;
  undefined uVar10;
  short *psVar11;
  int iVar12;
  double dVar13;
  float local_48;
  short local_44;
  undefined2 local_42;
  undefined2 local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  double local_28;
  double local_20;
  
  iVar5 = FUN_802860dc();
  psVar6 = (short *)FUN_8002b9ec();
  iVar12 = *(int *)(iVar5 + 0x4c);
  local_48 = FLOAT_803e3950;
  (**(code **)(*DAT_803dca58 + 0x18))(&local_48);
  psVar11 = *(short **)(iVar5 + 0xb8);
  iVar7 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(iVar12 + 0x14));
  if (iVar7 != 0) {
    iVar7 = *(int *)(psVar6 + 0x5c);
    if (psVar11[9] < 1) {
      psVar11[9] = 800;
      psVar11[5] = 1;
      *(undefined *)((int)psVar11 + 9) = 0;
      *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) | 8;
      FUN_801816f8(iVar5,psVar6,psVar11);
      fVar3 = FLOAT_803e3938;
      *(float *)(iVar5 + 0x24) = FLOAT_803e3938;
      *(float *)(iVar5 + 0x2c) = fVar3;
    }
    if (*(int *)(psVar11 + 10) == 0) {
      if (*(char *)((int)psVar11 + 5) != '\x02') {
        local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar5 + 0x36));
        iVar4 = (int)(FLOAT_803e3978 * FLOAT_803db414 + (float)(local_28 - DOUBLE_803e39a0));
        local_20 = (double)(longlong)iVar4;
        if (0xff < iVar4) {
          iVar4 = 0xff;
        }
        *(char *)(iVar5 + 0x36) = (char)iVar4;
      }
      if (psVar11[5] != 0) {
        FUN_80035f00(iVar5);
        psVar11[5] = psVar11[5] - (ushort)DAT_803db410;
        if (psVar11[5] < 1) {
          if (*(int *)(psVar11 + 0xc) == 0) {
            *(undefined4 *)(psVar11 + 10) = 1;
          }
          else {
            *(int *)(psVar11 + 10) = *(int *)(psVar11 + 0xc);
          }
          local_20 = (double)CONCAT44(0x43300000,*(uint *)(psVar11 + 0xc) ^ 0x80000000);
          (**(code **)(*DAT_803dcaac + 100))
                    ((double)(float)(local_20 - DOUBLE_803e3968),*(undefined4 *)(iVar12 + 0x14));
          *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(iVar12 + 8);
          *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar12 + 0xc);
          *(undefined4 *)(iVar5 + 0x14) = *(undefined4 *)(iVar12 + 0x10);
          *(undefined4 *)(iVar5 + 0x80) = *(undefined4 *)(iVar12 + 8);
          *(undefined4 *)(iVar5 + 0x84) = *(undefined4 *)(iVar12 + 0xc);
          *(undefined4 *)(iVar5 + 0x88) = *(undefined4 *)(iVar12 + 0x10);
          fVar3 = FLOAT_803e3938;
          *(float *)(iVar5 + 0x24) = FLOAT_803e3938;
          *(float *)(iVar5 + 0x28) = fVar3;
          *(float *)(iVar5 + 0x2c) = fVar3;
        }
        if (psVar11[5] < 0x33) goto LAB_8018307c;
      }
      if (*(char *)((int)psVar11 + 9) == '\x01') {
        psVar11[9] = psVar11[9] - (ushort)DAT_803db410;
        if (*(char *)((int)psVar11 + 9) == '\x01') {
          FUN_80035df4(iVar5,0xe,1,0);
          if (FLOAT_803e3994 < *(float *)(iVar5 + 0x28)) {
            *(float *)(iVar5 + 0x28) = FLOAT_803e3998 * FLOAT_803db414 + *(float *)(iVar5 + 0x28);
          }
          FUN_80035f20(iVar5);
        }
        *(float *)(iVar5 + 0xc) =
             *(float *)(iVar5 + 0x24) * FLOAT_803db414 + *(float *)(iVar5 + 0xc);
        *(float *)(iVar5 + 0x10) =
             *(float *)(iVar5 + 0x28) * FLOAT_803db414 + *(float *)(iVar5 + 0x10);
        *(float *)(iVar5 + 0x14) =
             *(float *)(iVar5 + 0x2c) * FLOAT_803db414 + *(float *)(iVar5 + 0x14);
        FUN_801821fc(iVar5);
        fVar3 = FLOAT_803e3938;
        cVar1 = *(char *)(*(int *)(iVar5 + 0x54) + 0xad);
        if ((cVar1 == '\0') || (*(char *)((int)psVar11 + 9) != '\x01')) {
          if ((cVar1 != '\0') && (*(char *)((int)psVar11 + 9) == '\x02')) {
            *(float *)(iVar5 + 0x24) = FLOAT_803e3938;
            *(float *)(iVar5 + 0x2c) = fVar3;
            psVar11[5] = 500;
            *(undefined *)((int)psVar11 + 9) = 0;
            *(undefined4 *)(iVar5 + 0xf8) = 0;
            FUN_80035f20(iVar5);
            *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) & 0xf7;
            FUN_80035dac(iVar5);
          }
        }
        else {
          local_38 = *(float *)(iVar5 + 0xc);
          local_34 = *(float *)(iVar5 + 0x10);
          local_30 = *(float *)(iVar5 + 0x14);
          FUN_8009a1dc((double)FLOAT_803e3934,iVar5,&local_44,1,0);
          (**(code **)(*DAT_803ddac0 + 4))(iVar5,1,0,2,0xffffffff,0);
          FUN_8000bb18(iVar5,psVar11[8]);
          psVar11[5] = 0x32;
          *(undefined *)((int)psVar11 + 9) = 0;
          *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) | 8;
          FUN_801816f8(iVar5,psVar6,psVar11);
          fVar3 = FLOAT_803e3938;
          *(float *)(iVar5 + 0x24) = FLOAT_803e3938;
          *(float *)(iVar5 + 0x2c) = fVar3;
          FUN_80035dac(iVar5);
        }
      }
      else if (*(char *)((int)psVar11 + 5) == '\0') {
        uVar10 = 0;
        uVar8 = FUN_80014b24(0);
        if ((((uVar8 & 0x100) == 0) && (*(int *)(iVar5 + 0xf8) == 0)) &&
           (iVar7 = FUN_80038024(iVar5), iVar7 != 0)) {
          *psVar11 = -0x8000;
          psVar11[1] = 0;
          FUN_80035f00(iVar5);
          uVar10 = 1;
        }
        *(undefined *)((int)psVar11 + 5) = uVar10;
        if (*(char *)((int)psVar11 + 5) != '\0') {
          *(undefined *)(psVar11 + 3) = 1;
        }
        if (*(int *)(iVar5 + 0xf8) == 0) {
          FUN_80035f20(iVar5);
          if ((*(char *)(psVar11 + 0x10) == '\0') || (iVar7 = FUN_80295cd4(psVar6), iVar7 != 0)) {
            *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) & 0xef;
          }
          else {
            *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) | 0x10;
          }
        }
        *(undefined4 *)(iVar5 + 0x80) = *(undefined4 *)(iVar5 + 0xc);
        *(undefined4 *)(iVar5 + 0x84) = *(undefined4 *)(iVar5 + 0x14);
        *(undefined4 *)(iVar5 + 0x88) = *(undefined4 *)(iVar5 + 0x14);
      }
      else {
        FUN_80035f00(iVar5);
        *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) | 8;
        uVar8 = FUN_8029729c(psVar6);
        if ((uVar8 & 0x4000) == 0) {
          FUN_8011f3ec(4);
        }
        else {
          FUN_8011f3ec(5);
        }
        uVar8 = FUN_80014e70(0);
        if ((uVar8 & 0x100) != 0) {
          iVar4 = FUN_80295bf0(psVar6);
          if (iVar4 == 0) {
            FUN_8000bb18(0,0x10a);
          }
          else {
            *(undefined *)(psVar11 + 3) = 0;
            FUN_80014b3c(0,0x100);
          }
        }
        if (*(int *)(iVar5 + 0xf8) == 1) {
          *(undefined *)((int)psVar11 + 5) = 2;
        }
        if (((*(char *)((int)psVar11 + 5) == '\x02') && (*(int *)(iVar5 + 0xf8) == 0)) ||
           ((*(char *)(psVar11 + 0x10) != '\0' && (iVar4 = FUN_80295cd4(psVar6), iVar4 == 0)))) {
          iVar4 = FUN_8029669c(psVar6);
          if (iVar4 == 0) {
            iVar4 = FUN_802966b4(psVar6);
            if (iVar4 == 0) {
              *(undefined *)((int)psVar11 + 5) = 0;
              *(undefined *)((int)psVar11 + 9) = 1;
              *(float *)(iVar5 + 0x28) = FLOAT_803e3988 * *(float *)(iVar7 + 0x298) + FLOAT_803e3984
              ;
              *(float *)(iVar5 + 0x2c) = FLOAT_803e3990 * *(float *)(iVar7 + 0x298) + FLOAT_803e398c
              ;
              local_38 = FLOAT_803e3938;
              local_34 = FLOAT_803e3938;
              local_30 = FLOAT_803e3938;
              local_3c = FLOAT_803e3950;
              local_40 = 0;
              local_42 = 0;
              local_44 = *psVar6;
              FUN_80021ac8(&local_44,iVar5 + 0x24);
              FUN_8000bb18(iVar5,0x6b);
              *(undefined *)(psVar11 + 3) = 0;
              *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) | 8;
            }
            else {
              *(undefined *)((int)psVar11 + 5) = 0;
              *(undefined *)((int)psVar11 + 9) = 2;
              fVar3 = FLOAT_803e3938;
              *(float *)(iVar5 + 0x24) = FLOAT_803e3938;
              *(float *)(iVar5 + 0x28) = fVar3;
              *(float *)(iVar5 + 0x2c) = fVar3;
              FUN_80035f20(iVar5);
              *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) & 0xf7;
              FUN_80035dac(iVar5);
            }
          }
          else {
            *(undefined *)((int)psVar11 + 5) = 0;
            *(undefined *)((int)psVar11 + 9) = 1;
            *(float *)(iVar5 + 0x28) = FLOAT_803e397c * *(float *)(iVar7 + 0x298) + FLOAT_803e3958;
            *(float *)(iVar5 + 0x2c) = FLOAT_803e3980 * *(float *)(iVar7 + 0x298) + FLOAT_803e3974;
            local_38 = FLOAT_803e3938;
            local_34 = FLOAT_803e3938;
            local_30 = FLOAT_803e3938;
            local_3c = FLOAT_803e3950;
            local_40 = 0;
            local_42 = 0;
            local_44 = *psVar6;
            if (*(short **)(psVar6 + 0x18) != (short *)0x0) {
              local_44 = local_44 + **(short **)(psVar6 + 0x18);
            }
            FUN_80021ac8(&local_44,iVar5 + 0x24);
            FUN_8000bb18(iVar5,0x6b);
          }
        }
        if (*(char *)(psVar11 + 3) != '\0') {
          psVar11[5] = 0;
          *(undefined4 *)(psVar11 + 10) = 0;
          FUN_800378c4(psVar6,0x100010,iVar5,(int)psVar11[1] << 0x10 | (int)*psVar11 & 0xffffU);
        }
      }
      psVar11[7] = psVar11[7] - (ushort)DAT_803db410;
      if (*(char *)((int)psVar11 + 5) == '\0') {
        FUN_801814d0(iVar5,psVar6,psVar11);
      }
      else {
        dVar13 = (double)FUN_8002166c(iVar5 + 0x18,iVar12 + 8);
        fVar3 = FLOAT_803e3938;
        local_20 = (double)CONCAT44(0x43300000,(int)psVar11[6] * (int)psVar11[6] ^ 0x80000000);
        if ((double)(float)(local_20 - DOUBLE_803e3968) <= dVar13) {
          *(float *)(iVar5 + 0x24) = FLOAT_803e3938;
          *(float *)(iVar5 + 0x2c) = fVar3;
          psVar11[5] = 500;
          *(undefined *)((int)psVar11 + 9) = 0;
          *(undefined4 *)(iVar5 + 0xf8) = 0;
          FUN_80035f20(iVar5);
          *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) & 0xf7;
          FUN_80035dac(iVar5);
        }
      }
      if ((psVar11[7] < 1) && (*(char *)((int)psVar11 + 5) != '\0')) {
        cVar1 = *(char *)(psVar11 + 0xf);
        if ((cVar1 == '\x05') || (cVar1 == '\x06')) {
          FUN_8000bb18(iVar5,0x6c);
          sVar9 = FUN_800221a0(0,100);
          psVar11[7] = sVar9 + 300;
        }
        else if (((byte)(cVar1 - 1U) < 2) || (cVar1 == '\x03')) {
          FUN_8000bb18(iVar5,0x6d);
          sVar9 = FUN_800221a0(0,100);
          psVar11[7] = sVar9 + 300;
        }
      }
      if (*(int *)(iVar5 + 0xf8) == 0) {
        *(ushort *)(iVar5 + 6) = *(ushort *)(iVar5 + 6) & 0xbfff;
      }
    }
    else {
      bVar2 = false;
      *(undefined *)(iVar5 + 0x36) = 0;
      local_28 = (double)(longlong)(int)(FLOAT_803db414 * local_48);
      *(int *)(psVar11 + 10) = *(int *)(psVar11 + 10) - (int)(short)(int)(FLOAT_803db414 * local_48)
      ;
      if (*(int *)(psVar11 + 10) < 1) {
        iVar7 = FUN_8002b9ec();
        dVar13 = (double)FUN_80021704(iVar5 + 0x18,iVar7 + 0x18);
        if (((double)FLOAT_803e3930 < dVar13) && (psVar11[0xe] == -1)) {
          bVar2 = true;
        }
        if (bVar2) {
          *(undefined4 *)(psVar11 + 10) = 0;
          psVar11[5] = 0;
          FUN_80035f20(iVar5);
          FUN_80035ea4(iVar5);
          *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) & 0xf7;
          *(ushort *)(iVar5 + 6) = *(ushort *)(iVar5 + 6) & 0xbfff;
        }
        else {
          *(undefined4 *)(psVar11 + 10) = 1;
        }
      }
    }
  }
LAB_8018307c:
  FUN_80286128();
  return;
}

