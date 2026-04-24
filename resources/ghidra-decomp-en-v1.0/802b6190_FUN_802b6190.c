// Function: FUN_802b6190
// Entry: 802b6190
// Size: 2372 bytes

/* WARNING: Removing unreachable block (ram,0x802b6ab0) */

void FUN_802b6190(undefined2 *param_1)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  byte bVar4;
  float fVar5;
  short sVar6;
  short *psVar7;
  int iVar8;
  undefined uVar12;
  char cVar13;
  undefined4 uVar9;
  uint uVar10;
  uint uVar11;
  int iVar14;
  undefined4 uVar15;
  double dVar16;
  undefined8 in_f31;
  double dVar17;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  uint uStack60;
  longlong local_38;
  undefined4 local_30;
  uint uStack44;
  longlong local_28;
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar14 = *(int *)(param_1 + 0x5c);
  psVar7 = (short *)FUN_8000faac();
  fVar5 = FLOAT_803e7ef0;
  fVar2 = FLOAT_803e7ea4;
  fVar1 = *(float *)(iVar14 + 0x820);
  if (FLOAT_803e7ef0 <= fVar1) {
    if (FLOAT_803e7ea4 < fVar1) {
      *(float *)(iVar14 + 0x820) = fVar1 - FLOAT_803e7ee0;
      if (fVar2 < *(float *)(iVar14 + 0x820)) {
        if (fVar5 == *(float *)(iVar14 + 0x820)) {
          FUN_80020634(1,0);
          FUN_80020628(0xfd);
        }
      }
      else {
        FUN_80020634(0,0);
        *(undefined *)(iVar14 + 0x8cf) = 1;
      }
    }
  }
  else {
    iVar8 = FUN_80014940();
    if ((iVar8 != 4) && ((*(uint *)(iVar14 + 0x360) & 0x200000) == 0)) {
      if ((*(byte *)(iVar14 + 0x3f3) >> 3 & 1) != 0) {
        FUN_8011f3c8(10);
      }
      if (((*(int *)(param_1 + 0x18) == 0) && (*(int *)(iVar14 + 0x7f0) == 0)) &&
         (iVar8 = FUN_8005b16c((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 10)),
         iVar8 == 0)) {
        *(undefined4 *)(iVar14 + 0x2d0) = 0;
        *(undefined4 *)(iVar14 + 0x7ec) = 0;
        (**(code **)(*DAT_803dca50 + 0x48))(0);
        fVar1 = FLOAT_803e7ea4;
        *(float *)(iVar14 + 0x294) = FLOAT_803e7ea4;
        *(float *)(iVar14 + 0x284) = fVar1;
        *(float *)(iVar14 + 0x280) = fVar1;
        *(float *)(param_1 + 0x12) = fVar1;
        *(float *)(param_1 + 0x14) = fVar1;
        *(float *)(param_1 + 0x16) = fVar1;
        FUN_802ab5a4(param_1,iVar14,0xff);
      }
      else {
        uVar12 = (**(code **)(*DAT_803dca50 + 0x10))();
        *(undefined *)(iVar14 + 0x8c8) = uVar12;
        if ((*(char *)(iVar14 + 0x8c8) == 'D') && (*(short *)(iVar14 + 0x274) != 1)) {
          (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar14,1);
          fVar1 = FLOAT_803e7ea4;
          *(float *)(iVar14 + 0x294) = FLOAT_803e7ea4;
          *(float *)(iVar14 + 0x284) = fVar1;
          *(float *)(iVar14 + 0x280) = fVar1;
          *(float *)(param_1 + 0x12) = fVar1;
          *(float *)(param_1 + 0x14) = fVar1;
          *(float *)(param_1 + 0x16) = fVar1;
          *(code **)(iVar14 + 0x304) = FUN_802a514c;
        }
        FUN_802b249c(param_1,iVar14,iVar14);
        FUN_802b4a9c(param_1,iVar14,iVar14);
        FUN_802b07d8(param_1,iVar14);
        if ((DAT_803de448 == 0) && (cVar13 = FUN_8002e04c(), cVar13 != '\0')) {
          uVar9 = FUN_8002bdf4(0x18,0x66a);
          DAT_803de448 = FUN_8002df90(uVar9,4,0xffffffff,0xffffffff,*(undefined4 *)(param_1 + 0x18))
          ;
          FUN_80037d2c(param_1,DAT_803de448,3);
        }
        if ((DAT_803de448 != 0) &&
           (*(undefined4 *)(DAT_803de448 + 0x30) = *(undefined4 *)(param_1 + 0x18),
           *(short *)(iVar14 + 0x81a) == 0)) {
          *(ushort *)(DAT_803de448 + 6) = *(ushort *)(DAT_803de448 + 6) | 0x4000;
        }
        if ((DAT_803de450 == 0) && (cVar13 = FUN_8002e04c(), cVar13 != '\0')) {
          uVar9 = FUN_8002bdf4(0x24,0x773);
          DAT_803de450 = FUN_8002df90(uVar9,5,0xffffffff,0xffffffff,*(undefined4 *)(param_1 + 0x18))
          ;
        }
        if (DAT_803de450 != 0) {
          FUN_8003842c(param_1,4,DAT_803de450 + 0xc,DAT_803de450 + 0x10,DAT_803de450 + 0x14,0);
        }
        if (*(short **)(param_1 + 0x18) == (short *)0x0) {
          *(short *)(iVar14 + 0x330) = *psVar7;
        }
        else {
          iVar8 = ((int)**(short **)(param_1 + 0x18) & 0xffffU) - (0x8000U - (int)*psVar7 & 0xffff);
          if (0x8000 < iVar8) {
            iVar8 = iVar8 + -0xffff;
          }
          if (iVar8 < -0x8000) {
            iVar8 = iVar8 + 0xffff;
          }
          *(short *)(iVar14 + 0x330) = (short)iVar8 + -0x8000;
        }
        *(float *)(iVar14 + 0x778) = FLOAT_803e8164;
        *(undefined *)(iVar14 + 0x8c9) = 0;
        *(undefined4 *)(iVar14 + 0x310) = 0;
        for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(iVar14 + 0x8b8); iVar8 = iVar8 + 1) {
          *(uint *)(iVar14 + 0x310) =
               *(uint *)(iVar14 + 0x310) | 1 << (uint)*(byte *)(iVar14 + iVar8 + 0x8b9);
        }
        *(uint *)(iVar14 + 0x360) = *(uint *)(iVar14 + 0x360) & 0xfffff4ff;
        dVar17 = (double)FLOAT_803db414;
        FUN_802b19f8(dVar17,param_1,iVar14);
        FUN_802b4c18(dVar17,param_1,iVar14);
        FUN_802aef34(dVar17,param_1,iVar14);
        FUN_802b1e5c(dVar17,param_1,iVar14,iVar14);
        FUN_802b1bf8(dVar17,param_1,iVar14,iVar14);
        fVar1 = *(float *)(param_1 + 0x12);
        fVar2 = FLOAT_803e801c;
        if ((FLOAT_803e801c <= fVar1) && (fVar2 = fVar1, FLOAT_803e7f10 < fVar1)) {
          fVar2 = FLOAT_803e7f10;
        }
        *(float *)(param_1 + 0x12) = fVar2;
        fVar1 = *(float *)(param_1 + 0x14);
        fVar2 = FLOAT_803e811c;
        if ((FLOAT_803e811c <= fVar1) && (fVar2 = fVar1, FLOAT_803e80e4 < fVar1)) {
          fVar2 = FLOAT_803e80e4;
        }
        *(float *)(param_1 + 0x14) = fVar2;
        fVar1 = *(float *)(param_1 + 0x16);
        fVar2 = FLOAT_803e801c;
        if ((FLOAT_803e801c <= fVar1) && (fVar2 = fVar1, FLOAT_803e7f10 < fVar1)) {
          fVar2 = FLOAT_803e7f10;
        }
        *(float *)(param_1 + 0x16) = fVar2;
        dVar16 = (double)(float)((double)*(float *)(param_1 + 0x14) * dVar17);
        if ((double)FLOAT_803e7ed8 < (double)(float)((double)*(float *)(param_1 + 0x14) * dVar17)) {
          dVar16 = (double)FLOAT_803e7ed8;
        }
        FUN_8002b95c((double)(float)((double)*(float *)(param_1 + 0x12) * dVar17),dVar16,
                     (double)(float)((double)*(float *)(param_1 + 0x16) * dVar17),param_1);
        *param_1 = *(undefined2 *)(iVar14 + 0x478);
        local_58 = DAT_802c2c50;
        local_54 = DAT_802c2c54;
        local_50 = DAT_802c2c58;
        local_4c = DAT_802c2c5c;
        local_48 = DAT_802c2c60;
        local_44 = DAT_802c2c64;
        (**(code **)(*DAT_803dca68 + 0x24))(&local_58,6);
        FUN_802b0920(param_1,iVar14);
        sVar6 = *(short *)(iVar14 + 0x810) - (ushort)DAT_803db410;
        *(short *)(iVar14 + 0x810) = sVar6;
        if (sVar6 < 0) {
          *(ushort *)(iVar14 + 0x810) = (ushort)(byte)(&DAT_803dc6a8)[*(byte *)(iVar14 + 0x8b0)];
          *(undefined *)(iVar14 + 0x8b1) = (&DAT_803dc6b0)[*(byte *)(iVar14 + 0x8b0)];
        }
        FUN_802b066c(param_1,iVar14);
        if (*(char *)(iVar14 + 0x8ca) == '\x01') {
          *(float *)(iVar14 + 2000) =
               *(float *)(iVar14 + 0x7cc) * FLOAT_803db414 + *(float *)(iVar14 + 2000);
          if (*(float *)(iVar14 + 2000) < FLOAT_803e80c4) {
            if (*(float *)(iVar14 + 2000) <= FLOAT_803e7ea4) {
              *(float *)(iVar14 + 2000) = FLOAT_803e7ea4;
              *(float *)(iVar14 + 0x7cc) = FLOAT_803e7f14;
            }
          }
          else {
            *(float *)(iVar14 + 2000) = FLOAT_803e80c4;
            *(float *)(iVar14 + 0x7cc) = FLOAT_803e7ea4;
          }
        }
        FUN_802afb0c(param_1,iVar14,iVar14);
        if ((*(int *)(iVar14 + 0x7f8) != 0) && (iVar8 = FUN_800379dc(), iVar8 == 0)) {
          *(undefined *)(iVar14 + 0x800) = 0;
          if (*(int *)(iVar14 + 0x7f8) != 0) {
            sVar6 = *(short *)(*(int *)(iVar14 + 0x7f8) + 0x46);
            if ((sVar6 == 0x3cf) || (sVar6 == 0x662)) {
              FUN_80182504();
            }
            else {
              FUN_800ea774();
            }
            *(ushort *)(*(int *)(iVar14 + 0x7f8) + 6) =
                 *(ushort *)(*(int *)(iVar14 + 0x7f8) + 6) & 0xbfff;
            *(undefined4 *)(*(int *)(iVar14 + 0x7f8) + 0xf8) = 0;
            *(undefined4 *)(iVar14 + 0x7f8) = 0;
          }
        }
        if ((*(byte *)(*(int *)(param_1 + 0x5c) + 0xc4) & 0x40) == 0) {
          uStack44 = (uint)*(byte *)((int)param_1 + 0xf1);
          local_30 = 0x43300000;
          uVar11 = (uint)(FLOAT_803e80e4 * FLOAT_803db414 +
                         (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e7f38));
          local_28 = (longlong)(int)uVar11;
        }
        else {
          uStack60 = (uint)*(byte *)((int)param_1 + 0xf1);
          local_40 = 0x43300000;
          uVar11 = (uint)-(FLOAT_803e80e4 * FLOAT_803db414 -
                          (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e7f38));
          local_38 = (longlong)(int)uVar11;
        }
        uVar10 = FUN_80088e30(2);
        if ((int)uVar11 < (int)(uVar10 & 0xff)) {
          uVar11 = FUN_80088e30(2);
          uVar11 = uVar11 & 0xff;
        }
        else if (0xff < (int)uVar11) {
          uVar11 = 0xff;
        }
        *(char *)((int)param_1 + 0xf1) = (char)uVar11;
        FUN_802af7f8(param_1,iVar14);
        FUN_802af410(param_1,iVar14);
        if (((*(byte *)(iVar14 + 0x3f3) >> 5 & 1) != 0) &&
           (iVar8 = (**(code **)(*DAT_803dca4c + 0x14))(), iVar8 != 0)) {
          (**(code **)(*DAT_803dcaac + 0x28))();
        }
        if (((*(byte *)(iVar14 + 0x3f3) >> 5 & 1) == 0) && ((*(uint *)(iVar14 + 0x310) & 1) != 0)) {
          if (*(short *)(iVar14 + 0x81a) == 0) {
            uVar9 = 0x2d0;
          }
          else {
            uVar9 = 0x26;
          }
          iVar8 = FUN_8000b5d0(param_1,uVar9);
          if (iVar8 == 0) {
            if (*(short *)(iVar14 + 0x81a) == 0) {
              uVar9 = 0x2d0;
            }
            else {
              uVar9 = 0x26;
            }
            FUN_8000bb18(0,uVar9);
          }
          *(byte *)(iVar14 + 0x3f3) = *(byte *)(iVar14 + 0x3f3) & 0xdf | 0x20;
          (**(code **)(*DAT_803dca4c + 8))(0x1e,1);
          FUN_8012fdc0();
        }
        if (((DAT_803de44c != 0) && ((*(byte *)(iVar14 + 0x3f4) >> 6 & 1) != 0)) &&
           (*(ushort *)(DAT_803de44c + 0xb0) = *(ushort *)(DAT_803de44c + 0xb0) & 0xfff8,
           *(char *)(iVar14 + 0x8b3) == '\0')) {
          *(ushort *)(DAT_803de44c + 0xb0) = *(ushort *)(DAT_803de44c + 0xb0) | 2;
        }
        bVar4 = *(byte *)(iVar14 + 0x3f4) >> 6 & 1;
        if (bVar4 != 0) {
          if (*(char *)(iVar14 + 0x8b3) == '\0') {
            if (((*(int *)(iVar14 + 0x7f8) == 0) && (bVar4 != 0)) &&
               (((*(byte *)(iVar14 + 0x3f0) >> 5 & 1) == 0 &&
                ((*(byte *)(iVar14 + 0x3f0) >> 4 & 1) == 0)))) {
              bVar3 = true;
            }
            else {
              bVar3 = false;
            }
            if (bVar3) {
              FUN_8011f3ec(0xb);
            }
          }
          else {
            FUN_8011f3ec(1);
          }
          if (*(char *)(iVar14 + 0x8b3) != '\0') {
            FUN_8011f3c8(0xc);
          }
        }
        (**(code **)(*DAT_803dca50 + 0x68))(*(undefined *)(iVar14 + 0x8c9));
        *(undefined *)(iVar14 + 0x800) = 0;
        *(undefined *)(iVar14 + 0x8b8) = 0;
        *param_1 = *(undefined2 *)(iVar14 + 0x478);
        FUN_8006edcc((double)*(float *)(iVar14 + 0x280),(double)FLOAT_803e7ee0,param_1,
                     *(undefined4 *)(iVar14 + 0x314),*(undefined *)(iVar14 + 0x8a6),iVar14 + 0x3c4,
                     iVar14 + 4);
      }
    }
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  return;
}

