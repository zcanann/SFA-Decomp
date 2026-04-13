// Function: FUN_802b68f0
// Entry: 802b68f0
// Size: 2372 bytes

/* WARNING: Removing unreachable block (ram,0x802b7210) */
/* WARNING: Removing unreachable block (ram,0x802b6900) */

void FUN_802b68f0(short *param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  float fVar1;
  float fVar2;
  byte bVar3;
  short sVar4;
  ushort uVar5;
  short *psVar6;
  int iVar7;
  undefined uVar11;
  uint uVar8;
  undefined2 *puVar9;
  uint uVar10;
  bool bVar12;
  uint *puVar13;
  double dVar14;
  undefined8 extraout_f1;
  undefined8 uVar15;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  double dVar16;
  double dVar17;
  double in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  
  puVar13 = *(uint **)(param_1 + 0x5c);
  psVar6 = FUN_8000facc();
  dVar17 = (double)(float)puVar13[0x208];
  dVar16 = (double)FLOAT_803e8b88;
  if (dVar16 <= dVar17) {
    dVar14 = (double)FLOAT_803e8b3c;
    if (dVar14 < dVar17) {
      puVar13[0x208] = (uint)(float)(dVar17 - (double)FLOAT_803e8b78);
      if (dVar14 < (double)(float)puVar13[0x208]) {
        if (dVar16 == (double)(float)puVar13[0x208]) {
          FUN_800206f8(1,0);
          FUN_800206ec(0xfd);
        }
      }
      else {
        FUN_800206f8(0,0);
        *(undefined *)((int)puVar13 + 0x8cf) = 1;
      }
    }
  }
  else {
    iVar7 = FUN_8001496c();
    if ((iVar7 != 4) && ((puVar13[0xd8] & 0x200000) == 0)) {
      if ((*(byte *)((int)puVar13 + 0x3f3) >> 3 & 1) != 0) {
        FUN_8011f6ac(10);
      }
      if ((*(int *)(param_1 + 0x18) == 0) && (puVar13[0x1fc] == 0)) {
        dVar16 = (double)*(float *)(param_1 + 10);
        iVar7 = FUN_8005b2e8();
        if (iVar7 == 0) {
          puVar13[0xb4] = 0;
          puVar13[0x1fb] = 0;
          (**(code **)(*DAT_803dd6d0 + 0x48))(0);
          fVar1 = FLOAT_803e8b3c;
          puVar13[0xa5] = (uint)FLOAT_803e8b3c;
          puVar13[0xa1] = (uint)fVar1;
          puVar13[0xa0] = (uint)fVar1;
          *(float *)(param_1 + 0x12) = fVar1;
          *(float *)(param_1 + 0x14) = fVar1;
          *(float *)(param_1 + 0x16) = fVar1;
          FUN_802abd04((int)param_1,(int)puVar13,0xff);
          return;
        }
      }
      uVar11 = (**(code **)(*DAT_803dd6d0 + 0x10))();
      *(undefined *)(puVar13 + 0x232) = uVar11;
      uVar15 = extraout_f1;
      if ((*(char *)(puVar13 + 0x232) == 'D') && (*(short *)(puVar13 + 0x9d) != 1)) {
        param_4 = *DAT_803dd70c;
        uVar15 = (**(code **)(param_4 + 0x14))(param_1,puVar13,1);
        fVar1 = FLOAT_803e8b3c;
        puVar13[0xa5] = (uint)FLOAT_803e8b3c;
        puVar13[0xa1] = (uint)fVar1;
        puVar13[0xa0] = (uint)fVar1;
        *(float *)(param_1 + 0x12) = fVar1;
        *(float *)(param_1 + 0x14) = fVar1;
        *(float *)(param_1 + 0x16) = fVar1;
        puVar13[0xc1] = (uint)FUN_802a58ac;
      }
      FUN_802b2bfc(uVar15,dVar16,dVar17,in_f4,in_f5,in_f6,in_f7,in_f8,(uint)param_1,(int)puVar13,
                   (int)puVar13,param_4,param_5,param_6,param_7,param_8);
      uVar15 = FUN_802b51fc(param_1,(int)puVar13,(int)puVar13);
      uVar15 = FUN_802b0f38(uVar15,dVar16,dVar17,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1,
                            (int)puVar13);
      if ((DAT_803df0c8 == 0) && (uVar8 = FUN_8002e144(), (uVar8 & 0xff) != 0)) {
        puVar9 = FUN_8002becc(0x18,0x66a);
        DAT_803df0c8 = FUN_8002e088(uVar15,dVar16,dVar17,in_f4,in_f5,in_f6,in_f7,in_f8,puVar9,4,0xff
                                    ,0xffffffff,*(uint **)(param_1 + 0x18),param_6,param_7,param_8);
        uVar15 = FUN_80037e24((int)param_1,DAT_803df0c8,3);
      }
      if ((DAT_803df0c8 != 0) &&
         (*(undefined4 *)(DAT_803df0c8 + 0x30) = *(undefined4 *)(param_1 + 0x18),
         *(short *)((int)puVar13 + 0x81a) == 0)) {
        *(ushort *)(DAT_803df0c8 + 6) = *(ushort *)(DAT_803df0c8 + 6) | 0x4000;
      }
      if ((DAT_803df0d0 == 0) && (uVar8 = FUN_8002e144(), (uVar8 & 0xff) != 0)) {
        puVar9 = FUN_8002becc(0x24,0x773);
        DAT_803df0d0 = FUN_8002e088(uVar15,dVar16,dVar17,in_f4,in_f5,in_f6,in_f7,in_f8,puVar9,5,0xff
                                    ,0xffffffff,*(uint **)(param_1 + 0x18),param_6,param_7,param_8);
      }
      if (DAT_803df0d0 != 0) {
        FUN_80038524(param_1,4,(float *)(DAT_803df0d0 + 0xc),(undefined4 *)(DAT_803df0d0 + 0x10),
                     (float *)(DAT_803df0d0 + 0x14),0);
      }
      if (*(ushort **)(param_1 + 0x18) == (ushort *)0x0) {
        *(short *)(puVar13 + 0xcc) = *psVar6;
      }
      else {
        iVar7 = (uint)**(ushort **)(param_1 + 0x18) - (0x8000U - (int)*psVar6 & 0xffff);
        if (0x8000 < iVar7) {
          iVar7 = iVar7 + -0xffff;
        }
        if (iVar7 < -0x8000) {
          iVar7 = iVar7 + 0xffff;
        }
        *(short *)(puVar13 + 0xcc) = (short)iVar7 + -0x8000;
      }
      puVar13[0x1de] = (uint)FLOAT_803e8dfc;
      *(undefined *)((int)puVar13 + 0x8c9) = 0;
      puVar13[0xc4] = 0;
      for (iVar7 = 0; iVar7 < (int)(uint)*(byte *)(puVar13 + 0x22e); iVar7 = iVar7 + 1) {
        puVar13[0xc4] = puVar13[0xc4] | 1 << (uint)*(byte *)((int)puVar13 + iVar7 + 0x8b9);
      }
      puVar13[0xd8] = puVar13[0xd8] & 0xfffff4ff;
      dVar14 = (double)FLOAT_803dc074;
      FUN_802b2158(dVar14,(int)param_1,(int)puVar13);
      FUN_802b5378(dVar14,param_1,puVar13);
      FUN_802af694(dVar14,dVar16,dVar17,in_f4,in_f5,in_f6,in_f7,in_f8);
      FUN_802b25bc(dVar14,dVar16,dVar17,in_f4,in_f5,in_f6,in_f7,in_f8,(uint)param_1,(int)puVar13,
                   (int)puVar13);
      FUN_802b2358((int)param_1,(int)puVar13,puVar13);
      fVar1 = *(float *)(param_1 + 0x12);
      fVar2 = FLOAT_803e8cb4;
      if ((FLOAT_803e8cb4 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8ba8 < fVar1)) {
        fVar2 = FLOAT_803e8ba8;
      }
      *(float *)(param_1 + 0x12) = fVar2;
      fVar1 = *(float *)(param_1 + 0x14);
      fVar2 = FLOAT_803e8db4;
      if ((FLOAT_803e8db4 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8d7c < fVar1)) {
        fVar2 = FLOAT_803e8d7c;
      }
      *(float *)(param_1 + 0x14) = fVar2;
      fVar1 = *(float *)(param_1 + 0x16);
      fVar2 = FLOAT_803e8cb4;
      if ((FLOAT_803e8cb4 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8ba8 < fVar1)) {
        fVar2 = FLOAT_803e8ba8;
      }
      *(float *)(param_1 + 0x16) = fVar2;
      dVar16 = (double)(float)((double)*(float *)(param_1 + 0x14) * dVar14);
      if ((double)FLOAT_803e8b70 < (double)(float)((double)*(float *)(param_1 + 0x14) * dVar14)) {
        dVar16 = (double)FLOAT_803e8b70;
      }
      dVar17 = (double)(float)((double)*(float *)(param_1 + 0x16) * dVar14);
      FUN_8002ba34((double)(float)((double)*(float *)(param_1 + 0x12) * dVar14),dVar16,dVar17,
                   (int)param_1);
      *param_1 = *(short *)(puVar13 + 0x11e);
      local_58 = DAT_802c33d0;
      local_54 = DAT_802c33d4;
      local_50 = DAT_802c33d8;
      local_4c = DAT_802c33dc;
      local_48 = DAT_802c33e0;
      local_44 = DAT_802c33e4;
      (**(code **)(*DAT_803dd6e8 + 0x24))(&local_58,6);
      FUN_802b1080();
      sVar4 = *(short *)(puVar13 + 0x204);
      uVar5 = (ushort)DAT_803dc070;
      *(ushort *)(puVar13 + 0x204) = sVar4 - uVar5;
      if ((short)(sVar4 - uVar5) < 0) {
        *(ushort *)(puVar13 + 0x204) = (ushort)(byte)(&DAT_803dd310)[*(byte *)(puVar13 + 0x22c)];
        *(undefined *)((int)puVar13 + 0x8b1) = (&DAT_803dd318)[*(byte *)(puVar13 + 0x22c)];
      }
      dVar14 = (double)FUN_802b0dcc((uint)param_1,(int)puVar13);
      if (*(char *)((int)puVar13 + 0x8ca) == '\x01') {
        dVar16 = (double)(float)puVar13[499];
        puVar13[500] = (uint)(float)(dVar16 * (double)FLOAT_803dc074 + (double)(float)puVar13[500]);
        dVar14 = (double)(float)puVar13[500];
        if (dVar14 < (double)FLOAT_803e8d5c) {
          if (dVar14 <= (double)FLOAT_803e8b3c) {
            puVar13[500] = (uint)FLOAT_803e8b3c;
            puVar13[499] = (uint)FLOAT_803e8bac;
          }
        }
        else {
          puVar13[500] = (uint)FLOAT_803e8d5c;
          puVar13[499] = (uint)FLOAT_803e8b3c;
        }
      }
      FUN_802b026c(dVar14,dVar16,dVar17,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,puVar13,(int)puVar13);
      if ((puVar13[0x1fe] != 0) && (iVar7 = FUN_80037ad4(puVar13[0x1fe]), iVar7 == 0)) {
        *(undefined *)(puVar13 + 0x200) = 0;
        uVar8 = puVar13[0x1fe];
        if (uVar8 != 0) {
          if ((*(short *)(uVar8 + 0x46) == 0x3cf) || (*(short *)(uVar8 + 0x46) == 0x662)) {
            FUN_80182a5c(uVar8);
          }
          else {
            FUN_800ea9f8(uVar8);
          }
          *(ushort *)(puVar13[0x1fe] + 6) = *(ushort *)(puVar13[0x1fe] + 6) & 0xbfff;
          *(undefined4 *)(puVar13[0x1fe] + 0xf8) = 0;
          puVar13[0x1fe] = 0;
        }
      }
      if ((*(byte *)(*(int *)(param_1 + 0x5c) + 0xc4) & 0x40) == 0) {
        uStack_2c = (uint)*(byte *)((int)param_1 + 0xf1);
        local_30 = 0x43300000;
        uVar8 = (uint)(FLOAT_803e8d7c * FLOAT_803dc074 +
                      (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e8bd0));
        local_28 = (longlong)(int)uVar8;
      }
      else {
        uStack_3c = (uint)*(byte *)((int)param_1 + 0xf1);
        local_40 = 0x43300000;
        uVar8 = (uint)-(FLOAT_803e8d7c * FLOAT_803dc074 -
                       (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e8bd0));
        local_38 = (longlong)(int)uVar8;
      }
      dVar17 = (double)FLOAT_803e8d7c;
      dVar16 = (double)FLOAT_803dc074;
      uVar10 = FUN_800890bc(2);
      if ((int)uVar8 < (int)(uVar10 & 0xff)) {
        uVar8 = FUN_800890bc(2);
        uVar8 = uVar8 & 0xff;
        uVar15 = extraout_f1_01;
      }
      else {
        uVar15 = extraout_f1_00;
        if (0xff < (int)uVar8) {
          uVar8 = 0xff;
        }
      }
      *(char *)((int)param_1 + 0xf1) = (char)uVar8;
      FUN_802aff58(uVar15,dVar16,dVar17,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1,(int)puVar13);
      FUN_802afb70(param_1,(int)puVar13);
      if (((*(byte *)((int)puVar13 + 0x3f3) >> 5 & 1) != 0) &&
         (iVar7 = (**(code **)(*DAT_803dd6cc + 0x14))(), iVar7 != 0)) {
        (**(code **)(*DAT_803dd72c + 0x28))();
      }
      if (((*(byte *)((int)puVar13 + 0x3f3) >> 5 & 1) == 0) && ((puVar13[0xc4] & 1) != 0)) {
        if (*(short *)((int)puVar13 + 0x81a) == 0) {
          sVar4 = 0x2d0;
        }
        else {
          sVar4 = 0x26;
        }
        bVar12 = FUN_8000b5f0((int)param_1,sVar4);
        if (!bVar12) {
          if (*(short *)((int)puVar13 + 0x81a) == 0) {
            uVar5 = 0x2d0;
          }
          else {
            uVar5 = 0x26;
          }
          FUN_8000bb38(0,uVar5);
        }
        *(byte *)((int)puVar13 + 0x3f3) = *(byte *)((int)puVar13 + 0x3f3) & 0xdf | 0x20;
        (**(code **)(*DAT_803dd6cc + 8))(0x1e,1);
        FUN_80130118();
      }
      if (((DAT_803df0cc != 0) && ((*(byte *)(puVar13 + 0xfd) >> 6 & 1) != 0)) &&
         (*(ushort *)(DAT_803df0cc + 0xb0) = *(ushort *)(DAT_803df0cc + 0xb0) & 0xfff8,
         *(char *)((int)puVar13 + 0x8b3) == '\0')) {
        *(ushort *)(DAT_803df0cc + 0xb0) = *(ushort *)(DAT_803df0cc + 0xb0) | 2;
      }
      bVar3 = *(byte *)(puVar13 + 0xfd) >> 6 & 1;
      if (bVar3 != 0) {
        if (*(char *)((int)puVar13 + 0x8b3) == '\0') {
          if (((puVar13[0x1fe] == 0) && (bVar3 != 0)) &&
             (((*(byte *)(puVar13 + 0xfc) >> 5 & 1) == 0 &&
              ((*(byte *)(puVar13 + 0xfc) >> 4 & 1) == 0)))) {
            bVar12 = true;
          }
          else {
            bVar12 = false;
          }
          if (bVar12) {
            FUN_8011f6d0(0xb);
          }
        }
        else {
          FUN_8011f6d0(1);
        }
        if (*(char *)((int)puVar13 + 0x8b3) != '\0') {
          FUN_8011f6ac(0xc);
        }
      }
      (**(code **)(*DAT_803dd6d0 + 0x68))(*(undefined *)((int)puVar13 + 0x8c9));
      *(undefined *)(puVar13 + 0x200) = 0;
      *(undefined *)(puVar13 + 0x22e) = 0;
      *param_1 = *(short *)(puVar13 + 0x11e);
      FUN_8006ef48((double)(float)puVar13[0xa0],(double)FLOAT_803e8b78,param_1,puVar13[0xc5],
                   (uint)*(byte *)((int)puVar13 + 0x8a6),(int)(puVar13 + 0xf1),(int)(puVar13 + 1));
    }
  }
  return;
}

