// Function: FUN_802b3504
// Entry: 802b3504
// Size: 7416 bytes

/* WARNING: Removing unreachable block (ram,0x802b51dc) */
/* WARNING: Removing unreachable block (ram,0x802b51d4) */
/* WARNING: Removing unreachable block (ram,0x802b51cc) */
/* WARNING: Removing unreachable block (ram,0x802b3524) */
/* WARNING: Removing unreachable block (ram,0x802b351c) */
/* WARNING: Removing unreachable block (ram,0x802b3514) */

void FUN_802b3504(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,float *param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  ushort uVar2;
  bool bVar3;
  short sVar4;
  char cVar5;
  short *psVar6;
  short *psVar7;
  int iVar8;
  uint uVar9;
  undefined2 *puVar10;
  int iVar11;
  int *piVar12;
  int iVar13;
  char cVar14;
  ushort *puVar15;
  float *pfVar16;
  undefined4 *puVar17;
  float *pfVar18;
  undefined4 uVar19;
  int iVar20;
  int unaff_r27;
  int iVar21;
  undefined8 extraout_f1;
  double dVar22;
  double dVar23;
  double extraout_f1_00;
  undefined8 extraout_f1_01;
  double in_f29;
  double dVar24;
  double in_f30;
  double in_f31;
  double dVar25;
  double dVar26;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar27;
  float local_e8;
  int local_e4;
  float fStack_e0;
  undefined4 uStack_dc;
  float fStack_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  undefined4 local_c8;
  uint uStack_c4;
  longlong local_c0;
  undefined4 local_b8;
  uint uStack_b4;
  undefined4 local_b0;
  uint uStack_ac;
  longlong local_a8;
  undefined4 local_a0;
  uint uStack_9c;
  undefined4 local_98;
  uint uStack_94;
  longlong local_90;
  undefined4 local_88;
  uint uStack_84;
  undefined8 local_80;
  undefined4 local_78;
  uint uStack_74;
  undefined8 local_70;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar27 = FUN_80286828();
  psVar6 = (short *)((ulonglong)uVar27 >> 0x20);
  puVar15 = (ushort *)uVar27;
  iVar20 = *(int *)(puVar15 + 0x26);
  iVar21 = *(int *)(psVar6 + 0x5c);
  pfVar16 = param_12;
  uVar27 = extraout_f1;
  psVar7 = (short *)FUN_800396d0((int)psVar6,0);
  iVar8 = FUN_800396d0((int)psVar6,9);
  *(code **)(param_11 + 0xe8) = FUN_802a9b54;
  if (DAT_803df0d0 != (float *)0x0) {
    uVar27 = FUN_8017082c();
  }
  uVar27 = FUN_802b0f38(uVar27,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)psVar6,
                        iVar21);
  if ((DAT_803df0c8 == 0) && (uVar9 = FUN_8002e144(), (uVar9 & 0xff) != 0)) {
    puVar10 = FUN_8002becc(0x18,0x66a);
    pfVar16 = (float *)0xffffffff;
    DAT_803df0c8 = FUN_8002e088(uVar27,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                puVar10,4,0xff,0xffffffff,*(uint **)(psVar6 + 0x18),param_14,
                                param_15,param_16);
    uVar27 = FUN_80037e24((int)psVar6,DAT_803df0c8,3);
  }
  if ((DAT_803df0c8 != 0) &&
     (*(undefined4 *)(DAT_803df0c8 + 0x30) = *(undefined4 *)(psVar6 + 0x18),
     *(short *)(iVar21 + 0x81a) == 0)) {
    *(ushort *)(DAT_803df0c8 + 6) = *(ushort *)(DAT_803df0c8 + 6) | 0x4000;
  }
  if ((DAT_803df0d0 == (float *)0x0) && (uVar9 = FUN_8002e144(), (uVar9 & 0xff) != 0)) {
    puVar10 = FUN_8002becc(0x24,0x773);
    pfVar16 = (float *)0xffffffff;
    DAT_803df0d0 = (float *)FUN_8002e088(uVar27,param_2,param_3,param_4,param_5,param_6,param_7,
                                         param_8,puVar10,5,0xff,0xffffffff,*(uint **)(psVar6 + 0x18)
                                         ,param_14,param_15,param_16);
  }
  pfVar18 = DAT_803df0d0;
  if (DAT_803df0d0 != (float *)0x0) {
    pfVar16 = DAT_803df0d0 + 4;
    pfVar18 = DAT_803df0d0 + 5;
    param_14 = 0;
    FUN_80038524(psVar6,4,DAT_803df0d0 + 3,pfVar16,pfVar18,0);
  }
  if ((((*(byte *)(iVar21 + 0x3f3) >> 3 & 1) != 0) || (*(short *)(iVar21 + 0x80a) == 0x40)) &&
     (-1 < *(char *)(iVar21 + 0x3f4))) {
    FUN_802965f0();
    *(undefined2 *)(iVar21 + 0x80a) = 0xffff;
  }
  dVar22 = (double)FUN_80035ff8((int)psVar6);
  *(uint *)(iVar21 + 0x360) = *(uint *)(iVar21 + 0x360) & 0xfffffffd;
  if (*(char *)(param_11 + 0x56) == '\0') {
    *(ushort *)(param_11 + 0x6e) =
         *(ushort *)(param_11 + 0x6e) | *(ushort *)(param_11 + 0x70) & 0xfbff;
    *(undefined *)(iVar21 + 0x34c) = 0;
    fVar1 = FLOAT_803e8b3c;
    *(float *)(iVar21 + 0x290) = FLOAT_803e8b3c;
    *(float *)(iVar21 + 0x28c) = fVar1;
    *(undefined2 *)(iVar21 + 0x330) = 0;
    *(undefined4 *)(iVar21 + 0x31c) = 0;
    *(undefined4 *)(iVar21 + 0x318) = 0;
    if ((*(ushort *)(param_11 + 0x6e) & 1) != 0) {
      *(uint *)(iVar21 + 4) = *(uint *)(iVar21 + 4) | 0x100000;
      *(undefined *)(iVar21 + 0x25f) = 0;
    }
    for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar8 = iVar8 + 1) {
      switch(*(undefined *)(param_11 + iVar8 + 0x81)) {
      case 1:
        if (*(int *)(iVar21 + 0x684) != 0) {
          pfVar16 = (float *)0x0;
          FUN_800379bc(dVar22,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       *(int *)(iVar21 + 0x684),0x7000b,(uint)psVar6,0,pfVar18,param_14,param_15,
                       param_16);
          *(undefined4 *)(iVar21 + 0x684) = 0;
        }
        break;
      case 2:
        iVar20 = FUN_80295f14((int)psVar6);
        if (iVar20 != 0) {
          *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) | 4;
        }
        break;
      case 3:
        piVar12 = FUN_80037048(10,&local_e4);
        bVar3 = false;
        dVar25 = (double)FLOAT_803e8d44;
        for (iVar20 = 0; iVar20 < local_e4; iVar20 = iVar20 + 1) {
          iVar11 = *piVar12;
          if (((iVar11 != 0) &&
              (iVar13 = FUN_80080100((int *)&DAT_80333c5c,9,(int)*(short *)(iVar11 + 0x46)),
              iVar13 != -1)) &&
             ((dVar22 = FUN_80021794((float *)(iVar11 + 0x18),(float *)(psVar6 + 0xc)),
              dVar22 < dVar25 || (!bVar3)))) {
            *(int *)(iVar21 + 0x7f0) = iVar11;
            bVar3 = true;
            dVar25 = dVar22;
          }
          piVar12 = piVar12 + 1;
        }
        if (bVar3) {
          *(float *)(iVar21 + 0x6a4) = FLOAT_803e8b78;
          *(undefined4 *)(iVar21 + 0x6a8) = *(undefined4 *)(iVar21 + 0x768);
          *(undefined4 *)(iVar21 + 0x6ac) = *(undefined4 *)(iVar21 + 0x76c);
          *(undefined4 *)(iVar21 + 0x6b0) = *(undefined4 *)(iVar21 + 0x770);
          iVar20 = *(int *)(iVar21 + 0x7f0);
          (**(code **)(**(int **)(iVar20 + 0x68) + 0x3c))(iVar20,2);
          psVar6[3] = psVar6[3] | 8;
          *(uint *)(*(int *)(psVar6 + 0x32) + 0x30) =
               *(uint *)(*(int *)(psVar6 + 0x32) + 0x30) | 0x1000;
          *(undefined2 *)(*(int *)(psVar6 + 0x32) + 0x36) = 0;
          *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xfffb;
          sVar4 = *(short *)(iVar20 + 0x46);
          if (sVar4 == 0x416) {
            FUN_8000a538((int *)0xd5,1);
            *(short **)(iVar21 + 0x6e8) = &DAT_80333f58;
            *(undefined *)(iVar21 + 0x6ec) = 8;
            FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,psVar6,(int)DAT_80333f58,1,pfVar16,pfVar18,param_14,param_15,
                         param_16);
          }
          else if (sVar4 < 0x416) {
            if (sVar4 == 0x8c) {
              *(undefined **)(iVar21 + 0x6e8) = &DAT_80333f28;
              *(undefined *)(iVar21 + 0x6ec) = 4;
              FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,psVar6,0x7b,1,pfVar16,pfVar18,param_14,param_15,param_16);
              iVar11 = FUN_801e2398();
              if (iVar11 != 0) {
                (**(code **)(*DAT_803dd6d0 + 0x28))(iVar20,0);
                pfVar18 = (float *)*DAT_803dd6d4;
                (*(code *)pfVar18[0x14])(0x4a,1,0,0x78);
              }
            }
            else {
              if (sVar4 < 0x8c) {
                if (sVar4 == 0x72) {
LAB_802b44b8:
                  FUN_8000a538((int *)0x97,1);
                  FUN_800201ac(0xc1f,0);
                  *(undefined **)(iVar21 + 0x6e8) = &DAT_80333f10;
                  *(undefined *)(iVar21 + 0x6ec) = 3;
                  FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,
                               param_7,param_8,psVar6,0x17,1,pfVar16,pfVar18,param_14,param_15,
                               param_16);
                  goto LAB_802b4638;
                }
              }
              else if (sVar4 == 0x38c) goto LAB_802b44b8;
LAB_802b4608:
              FUN_8000a538((int *)0x1f,1);
LAB_802b4614:
              *(undefined2 **)(iVar21 + 0x6e8) = &DAT_80333f40;
              *(undefined *)(iVar21 + 0x6ec) = 4;
              FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,psVar6,0xf8,1,pfVar16,pfVar18,param_14,param_15,param_16);
            }
          }
          else if (sVar4 == 0x484) {
            FUN_8000a538((int *)0xe6,1);
            *(undefined2 **)(iVar21 + 0x6e8) = &DAT_80333f40;
            *(undefined *)(iVar21 + 0x6ec) = 4;
            FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,psVar6,0xf8,1,pfVar16,pfVar18,param_14,param_15,param_16);
          }
          else {
            if (0x483 < sVar4) {
              if (sVar4 != 0x714) goto LAB_802b4608;
              goto LAB_802b4614;
            }
            if (sVar4 != 0x419) goto LAB_802b4608;
            FUN_8000a538((int *)0xe6,1);
            *(undefined **)(iVar21 + 0x6e8) = &DAT_80333f28;
            *(undefined *)(iVar21 + 0x6ec) = 4;
            FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,psVar6,0x7b,1,pfVar16,pfVar18,param_14,param_15,param_16);
          }
LAB_802b4638:
          iVar20 = FUN_80080100((int *)&DAT_80333c80,4,(int)*(short *)(iVar20 + 0x46));
          if (iVar20 == -1) {
            pfVar16 = (float *)*DAT_803dd70c;
            dVar22 = (double)(*(code *)pfVar16[5])(psVar6,iVar21,0x18);
            *(code **)(iVar21 + 0x304) = FUN_8029fddc;
          }
          else {
            pfVar16 = (float *)*DAT_803dd70c;
            dVar22 = (double)(*(code *)pfVar16[5])(psVar6,iVar21,0x1a);
            *(code **)(iVar21 + 0x304) = FUN_8029fddc;
          }
        }
        break;
      case 4:
        iVar20 = *(int *)(iVar21 + 0x7f0);
        (**(code **)(*DAT_803dd6d0 + 0x28))(iVar20,0);
        pfVar18 = (float *)*DAT_803dd6d4;
        (*(code *)pfVar18[0x14])(0x45,0,0,0);
        *(undefined4 *)(iVar21 + 0x6e8) = 0;
        if ((iVar20 == 0) || (*(short *)(iVar20 + 0x46) != 0x22)) {
          pfVar16 = (float *)*DAT_803dd70c;
          dVar22 = (double)(*(code *)pfVar16[5])(psVar6,iVar21,0x18);
          *(code **)(iVar21 + 0x304) = FUN_8029fddc;
        }
        else {
          pfVar16 = (float *)*DAT_803dd70c;
          dVar22 = (double)(*(code *)pfVar16[5])(psVar6,iVar21,0x16);
          *(undefined4 *)(iVar21 + 0x304) = 0;
        }
        break;
      case 6:
        pfVar18 = (float *)*DAT_803dd6d4;
        (*(code *)pfVar18[0x14])(0x44,0,0,0);
        pfVar16 = (float *)*DAT_803dd70c;
        dVar22 = (double)(*(code *)pfVar16[5])(psVar6,iVar21,0x17);
        *(undefined4 *)(iVar21 + 0x304) = 0;
        break;
      case 7:
        *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xfffc;
        iVar20 = *(int *)(psVar6 + 0x5c);
        pfVar16 = (float *)*DAT_803dd70c;
        dVar22 = (double)(*(code *)pfVar16[5])(psVar6,iVar20,0x3e);
        *(undefined4 *)(iVar20 + 0x304) = 0;
        *(uint *)(iVar20 + 0x360) = *(uint *)(iVar20 + 0x360) | 1;
        psVar6[3] = psVar6[3] | 8;
        break;
      case 8:
        *(undefined2 *)(param_11 + 0x6e) = *(undefined2 *)(param_11 + 0x70);
        iVar20 = *(int *)(psVar6 + 0x5c);
        pfVar16 = (float *)*DAT_803dd70c;
        dVar22 = (double)(*(code *)pfVar16[5])(psVar6,iVar20,1);
        *(code **)(iVar20 + 0x304) = FUN_802a58ac;
        *(uint *)(iVar20 + 0x360) = *(uint *)(iVar20 + 0x360) & 0xfffffffe;
        psVar6[3] = psVar6[3] & 0xfff7;
        break;
      case 10:
        if ((DAT_803df0cc != 0) && ((*(byte *)(iVar21 + 0x3f4) >> 6 & 1) != 0)) {
          *(undefined *)(iVar21 + 0x8b4) = 2;
          *(byte *)(iVar21 + 0x3f4) = *(byte *)(iVar21 + 0x3f4) & 0xf7;
        }
        break;
      case 0xb:
        iVar20 = *(int *)(iVar21 + 0x7f0);
        if ((iVar20 == 0) || (*(short *)(iVar20 + 0x46) != 0x416)) {
          if ((iVar20 == 0) ||
             (iVar20 = FUN_80080100((int *)&DAT_80333c80,4,(int)*(short *)(iVar20 + 0x46)),
             iVar20 == -1)) {
            (**(code **)(*DAT_803dd6d0 + 0x24))(0,0x1d,0);
            pfVar16 = (float *)0x0;
            pfVar18 = (float *)*DAT_803dd6d4;
            dVar22 = (double)(*(code *)pfVar18[0x14])(0x42,4,0);
          }
          else {
            pfVar16 = (float *)0x0;
            pfVar18 = (float *)*DAT_803dd6d4;
            dVar22 = (double)(*(code *)pfVar18[0x14])(0x53,0,0);
          }
        }
        else {
          (**(code **)(*DAT_803dd6d0 + 0x28))(iVar20,0);
          (**(code **)(*DAT_803dd6d0 + 0x24))(0,0x69,0);
          pfVar16 = (float *)0x0;
          pfVar18 = (float *)*DAT_803dd6d4;
          dVar22 = (double)(*(code *)pfVar18[0x14])(0x42,4,0);
        }
        break;
      case 0xd:
        (**(code **)(*DAT_803dd6d4 + 0x7c))
                  ((int)*(short *)(*(int *)(psVar6 + 0x62) + 0x46),*(int *)(psVar6 + 0x62),0);
        iVar20 = *(int *)(psVar6 + 0x62);
        iVar11 = *(int *)(iVar20 + 0xb8);
        if (*(int *)(iVar20 + 0x54) == 0) {
          fVar1 = *(float *)(iVar20 + 0xa8) * *(float *)(iVar20 + 8);
        }
        else {
          local_70 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(*(int *)(iVar20 + 0x54) + 0x5a) ^ 0x80000000);
          fVar1 = (float)(local_70 - DOUBLE_803e8b58);
        }
        dVar25 = (double)fVar1;
        param_2 = (double)((*(float *)(*(int *)(iVar20 + 0x74) + 4) - *(float *)(iVar20 + 0x10)) -
                          FLOAT_803e8df0);
        uStack_74 = (int)*(short *)(iVar11 + 0x478) ^ 0x80000000;
        local_78 = 0x43300000;
        dVar22 = (double)FUN_80294964();
        param_3 = (double)(float)(dVar25 * -dVar22);
        local_80 = CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x478) ^ 0x80000000);
        dVar22 = (double)FUN_802945e0();
        (**(code **)(*DAT_803dd6d4 + 0x80))((double)(float)(dVar25 * -dVar22));
        pfVar16 = (float *)*DAT_803dd6d4;
        dVar22 = (double)(*(code *)pfVar16[0x12])(*(undefined4 *)(psVar6 + 0x7a),psVar6,0xffffffff);
        break;
      case 0xf:
        dVar22 = (double)FUN_80063000(psVar6,(short *)0x0,1);
        break;
      case 0x10:
        local_e8 = FLOAT_803e8df4;
        psVar7 = (short *)FUN_80036f50(6,psVar6,&local_e8);
        dVar22 = extraout_f1_00;
        if (psVar7 != (short *)0x0) {
          dVar22 = (double)FUN_80063000(psVar6,psVar7,1);
        }
        break;
      case 0x12:
        *(uint *)(iVar21 + 0x360) = *(uint *)(iVar21 + 0x360) | 0x8000;
        break;
      case 0x13:
        dVar22 = (double)FUN_80014974(1);
        break;
      case 0x14:
        *(uint *)(iVar21 + 0x360) = *(uint *)(iVar21 + 0x360) | 0x40000;
        break;
      case 0x15:
        *(uint *)(iVar21 + 0x360) = *(uint *)(iVar21 + 0x360) & 0xfffbffff;
        break;
      case 0x16:
        *(uint *)(iVar21 + 0x360) = *(uint *)(iVar21 + 0x360) | 0x20000;
        break;
      case 0x17:
        iVar20 = *(int *)(psVar6 + 0x5c);
        if (*(int *)(iVar20 + 0x7f8) != 0) {
          *(undefined *)(iVar20 + 0x800) = 0;
          iVar11 = *(int *)(iVar20 + 0x7f8);
          if (iVar11 != 0) {
            if ((*(short *)(iVar11 + 0x46) == 0x3cf) || (*(short *)(iVar11 + 0x46) == 0x662)) {
              FUN_80182a5c(iVar11);
            }
            else {
              FUN_800ea9f8(iVar11);
            }
            *(ushort *)(*(int *)(iVar20 + 0x7f8) + 6) =
                 *(ushort *)(*(int *)(iVar20 + 0x7f8) + 6) & 0xbfff;
            *(undefined4 *)(*(int *)(iVar20 + 0x7f8) + 0xf8) = 0;
            *(undefined4 *)(iVar20 + 0x7f8) = 0;
          }
          *(uint *)(iVar20 + 0x360) = *(uint *)(iVar20 + 0x360) | 0x800000;
          pfVar16 = (float *)*DAT_803dd70c;
          dVar22 = (double)(*(code *)pfVar16[5])(psVar6,iVar20,1);
          *(code **)(iVar20 + 0x304) = FUN_802a58ac;
        }
        break;
      case 0x18:
        if ((DAT_803df0cc != 0) && ((*(byte *)(iVar21 + 0x3f4) >> 6 & 1) != 0)) {
          *(undefined *)(iVar21 + 0x8b4) = 0;
          *(byte *)(iVar21 + 0x3f4) = *(byte *)(iVar21 + 0x3f4) & 0xf7;
        }
        break;
      case 0x19:
        dVar22 = (double)(**(code **)(*DAT_803dd72c + 0x28))();
        break;
      case 0x1a:
        if (*(int *)(iVar21 + 0x684) != 0) {
          iVar11 = *(int *)(*(int *)(iVar21 + 0x684) + 0x50);
          iVar20 = (int)*(short *)(iVar11 + 0x7a);
          if (iVar20 < 0) {
            pfVar16 = (float *)0x0;
            pfVar18 = (float *)*DAT_803dd6e8;
            dVar22 = (double)(*(code *)pfVar18[0xe])((int)*(short *)(iVar11 + 0x7c),0x154,300);
          }
          else {
            pfVar16 = (float *)0x0;
            pfVar18 = (float *)*DAT_803dd6e8;
            dVar22 = (double)(*(code *)pfVar18[0xe])(iVar20,0x154,300);
          }
        }
        break;
      case 0x1c:
        dVar22 = (double)FUN_80296454((int)psVar6,0);
        break;
      case 0x1d:
        pfVar16 = (float *)*DAT_803dd70c;
        dVar22 = (double)(*(code *)pfVar16[5])(psVar6,iVar21,0x1a);
        *(code **)(iVar21 + 0x304) = FUN_8029fddc;
        break;
      case 0x1e:
        pfVar16 = (float *)*DAT_803dd70c;
        dVar22 = (double)(*(code *)pfVar16[5])(psVar6,iVar21,1);
        *(code **)(iVar21 + 0x304) = FUN_802a58ac;
        break;
      case 0x1f:
        FUN_80026d0c(DAT_803df0a0);
        dVar22 = (double)FUN_80026cf4(DAT_803df0a0,1);
        break;
      case 0x20:
        dVar22 = (double)FUN_80026cf4(DAT_803df0a0,0);
        break;
      case 0x21:
        DAT_803dd2d4 = '\x02';
        break;
      case 0x22:
        DAT_803dd2d4 = '\x01';
        break;
      case 0x25:
        *(ushort *)(iVar21 + 0x8d8) = *(ushort *)(iVar21 + 0x8d8) ^ 1;
        break;
      case 0x26:
        *(ushort *)(iVar21 + 0x8d8) = *(ushort *)(iVar21 + 0x8d8) ^ 2;
        break;
      case 0x27:
        dVar22 = (double)FUN_8011f670(1);
        break;
      case 0x28:
        dVar22 = (double)*(float *)(psVar6 + 6);
        param_2 = (double)*(float *)(psVar6 + 10);
        iVar20 = FUN_8005b128();
        if (iVar20 == 0xd) {
          unaff_r27 = 0x18;
        }
        else if (iVar20 < 0xd) {
          if (iVar20 == 2) {
            unaff_r27 = 0x1c;
          }
          else if ((1 < iVar20) && (0xb < iVar20)) {
            unaff_r27 = 0x14;
          }
        }
        else if (iVar20 == 0x13) {
          unaff_r27 = 0x10;
        }
        if ((int)*(char *)(*(int *)(*(int *)(psVar6 + 0x5c) + 0x35c) + 1) <= unaff_r27 + -4) {
          if (unaff_r27 < 0) {
            cVar14 = '\0';
          }
          else {
            cVar14 = (char)unaff_r27;
            if (0x50 < unaff_r27) {
              cVar14 = 'P';
            }
          }
          *(char *)(*(int *)(*(int *)(psVar6 + 0x5c) + 0x35c) + 1) = cVar14;
          if (unaff_r27 < 0) {
            cVar5 = '\0';
          }
          else {
            cVar14 = *(char *)(*(int *)(*(int *)(psVar6 + 0x5c) + 0x35c) + 1);
            cVar5 = (char)unaff_r27;
            if (cVar14 < unaff_r27) {
              cVar5 = cVar14;
            }
          }
          **(char **)(*(int *)(psVar6 + 0x5c) + 0x35c) = cVar5;
        }
        break;
      case 0x29:
        dVar22 = (double)FUN_8011f670(0);
        break;
      case 0x2a:
        cVar14 = (**(code **)(*DAT_803dd72c + 0x40))(0xb);
        if (cVar14 == '\a') {
          uVar27 = FUN_80008b74(extraout_f1_01,param_2,param_3,param_4,param_5,param_6,param_7,
                                param_8,psVar6,psVar6,0x1fb,0,pfVar18,param_14,param_15,param_16);
          uVar27 = FUN_80008b74(uVar27,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                psVar6,psVar6,0x1ff,0,pfVar18,param_14,param_15,param_16);
          uVar27 = FUN_80008b74(uVar27,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                psVar6,psVar6,0x249,0,pfVar18,param_14,param_15,param_16);
          pfVar16 = (float *)0x0;
          FUN_80008b74(uVar27,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar6,psVar6,
                       0x1fd,0,pfVar18,param_14,param_15,param_16);
        }
        else {
          uVar27 = FUN_80008b74(extraout_f1_01,param_2,param_3,param_4,param_5,param_6,param_7,
                                param_8,psVar6,psVar6,0x217,0,pfVar18,param_14,param_15,param_16);
          uVar27 = FUN_80008b74(uVar27,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                psVar6,psVar6,0x216,0,pfVar18,param_14,param_15,param_16);
          uVar27 = FUN_80008b74(uVar27,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                psVar6,psVar6,0x22e,0,pfVar18,param_14,param_15,param_16);
          uVar27 = FUN_80008b74(uVar27,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                psVar6,psVar6,0x218,0,pfVar18,param_14,param_15,param_16);
          uVar27 = FUN_80008b74(uVar27,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                psVar6,psVar6,0x84,0,pfVar18,param_14,param_15,param_16);
          pfVar16 = (float *)0x0;
          FUN_80008b74(uVar27,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar6,psVar6,
                       0x8a,0,pfVar18,param_14,param_15,param_16);
        }
        dVar22 = (double)FUN_800890e0((double)FLOAT_803e8b3c,0);
        break;
      case 0x2b:
        *(uint *)(*(int *)(psVar6 + 0x32) + 0x30) =
             *(uint *)(*(int *)(psVar6 + 0x32) + 0x30) & 0xfffffffb;
        break;
      case 0x2c:
        *(uint *)(*(int *)(psVar6 + 0x32) + 0x30) = *(uint *)(*(int *)(psVar6 + 0x32) + 0x30) | 4;
        break;
      case 0x2d:
        dVar22 = (double)FUN_80055228(1);
        break;
      case 0x2e:
        dVar22 = (double)FUN_80055228(0);
        break;
      case 0x31:
        dVar22 = (double)FUN_80096c30();
        break;
      case 0x32:
        dVar22 = FUN_8000fc54();
        dVar22 = (double)FUN_80096c20(dVar22);
      }
    }
    if ((*(uint *)(*(int *)(psVar6 + 0x5c) + 0x360) & 1) != 0) {
      *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xfffc;
    }
  }
  else {
    *(uint *)(iVar21 + 0x360) = *(uint *)(iVar21 + 0x360) & 0xfffffbff;
    fVar1 = FLOAT_803e8b3c;
    *(float *)(iVar21 + 0x79c) = FLOAT_803e8b3c;
    *(float *)(iVar21 + 0x7a0) = fVar1;
    if (-1 < *(char *)(iVar21 + 0x3f2)) {
      if ((DAT_803df0cc != 0) && ((*(byte *)(iVar21 + 0x3f4) >> 6 & 1) != 0)) {
        *(undefined *)(iVar21 + 0x8b4) = 1;
        *(byte *)(iVar21 + 0x3f4) = *(byte *)(iVar21 + 0x3f4) & 0xf7 | 8;
      }
      *(undefined *)(iVar21 + 0x800) = 0;
      iVar11 = *(int *)(iVar21 + 0x7f8);
      if (iVar11 != 0) {
        if ((*(short *)(iVar11 + 0x46) == 0x3cf) || (*(short *)(iVar11 + 0x46) == 0x662)) {
          FUN_80182a5c(iVar11);
        }
        else {
          FUN_800ea9f8(iVar11);
        }
        *(ushort *)(*(int *)(iVar21 + 0x7f8) + 6) =
             *(ushort *)(*(int *)(iVar21 + 0x7f8) + 6) & 0xbfff;
        *(undefined4 *)(*(int *)(iVar21 + 0x7f8) + 0xf8) = 0;
        *(undefined4 *)(iVar21 + 0x7f8) = 0;
      }
    }
    if (((*(char *)(iVar20 + 0x20) == '\0') ||
        (cVar14 = *(char *)(param_11 + 0x56), cVar14 == '\x03')) || (cVar14 == '\x02')) {
      *(undefined2 *)(param_11 + 0x6e) = *(undefined2 *)(param_11 + 0x70);
      if (*(char *)(param_11 + 0x56) != '\x02') {
        *(float *)(param_11 + 0x4c) = FLOAT_803e8b78;
        *(float *)(param_11 + 0x40) = *(float *)(psVar6 + 6) - *(float *)(puVar15 + 6);
        *(float *)(param_11 + 0x44) = *(float *)(psVar6 + 8) - *(float *)(puVar15 + 8);
        *(float *)(param_11 + 0x48) = *(float *)(psVar6 + 10) - *(float *)(puVar15 + 10);
        *(ushort *)(param_11 + 0x50) = *(short *)(iVar21 + 0x478) - *puVar15;
        if (0x8000 < *(short *)(param_11 + 0x50)) {
          *(short *)(param_11 + 0x50) = *(short *)(param_11 + 0x50) + 1;
        }
        if (*(short *)(param_11 + 0x50) < -0x8000) {
          *(short *)(param_11 + 0x50) = *(short *)(param_11 + 0x50) + -1;
        }
        *(ushort *)(param_11 + 0x52) = psVar6[1] - puVar15[1];
        if (0x8000 < *(short *)(param_11 + 0x52)) {
          *(short *)(param_11 + 0x52) = *(short *)(param_11 + 0x52) + 1;
        }
        if (*(short *)(param_11 + 0x52) < -0x8000) {
          *(short *)(param_11 + 0x52) = *(short *)(param_11 + 0x52) + -1;
        }
        *(ushort *)(param_11 + 0x54) = puVar15[2] - psVar6[2];
        if (0x8000 < *(short *)(param_11 + 0x54)) {
          *(short *)(param_11 + 0x54) = *(short *)(param_11 + 0x54) + 1;
        }
        if (*(short *)(param_11 + 0x54) < -0x8000) {
          *(short *)(param_11 + 0x54) = *(short *)(param_11 + 0x54) + -1;
        }
        *(undefined *)(param_11 + 0x56) = 2;
      }
      param_2 = (double)*(float *)(param_11 + 0x24);
      *(float *)(param_11 + 0x4c) =
           -(float)(param_2 * (double)FLOAT_803dc074 - (double)*(float *)(param_11 + 0x4c));
      if (*(float *)(param_11 + 0x4c) <= FLOAT_803e8b3c) {
        *(undefined *)(param_11 + 0x56) = 0;
      }
      psVar6[0x51] = -1;
      *(undefined2 *)(iVar21 + 0x4d2) = 0;
      *(undefined2 *)(iVar21 + 0x4d0) = 0;
      *(undefined2 *)(iVar21 + 0x4d4) = 0;
      *(undefined2 *)(iVar21 + 0x4d6) = 0;
    }
    else if (cVar14 == '\x04') {
      *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xffb3;
      *(ushort *)(param_11 + 0x70) = *(ushort *)(param_11 + 0x70) & 0xffb7;
      iVar8 = FUN_800804c0();
      iVar20 = FUN_800396d0(iVar8,0);
      if (iVar20 == 0) {
        pfVar16 = *(float **)(iVar8 + 0x74);
        if (pfVar16 == (float *)0x0) {
          local_d4 = *(float *)(iVar8 + 0x18);
          local_d0 = *(float *)(iVar8 + 0x1c);
          local_cc = *(float *)(iVar8 + 0x20);
        }
        else {
          local_d4 = *pfVar16;
          local_d0 = pfVar16[1];
          local_cc = pfVar16[2];
        }
      }
      else {
        FUN_80039608(iVar8,0,&local_d4);
      }
      puVar17 = &uStack_dc;
      pfVar16 = &fStack_d8;
      uVar19 = 0;
      FUN_80038524(psVar6,5,&fStack_e0,puVar17,pfVar16,0);
      dVar22 = (double)(*(float *)(psVar6 + 0xc) - local_d4);
      dVar25 = (double)(*(float *)(psVar6 + 0x10) - local_cc);
      iVar8 = FUN_80021884();
      DAT_803df130 = (short)iVar8;
      iVar8 = (int)DAT_803df130 - (uint)*(ushort *)(iVar21 + 0x478);
      if (0x8000 < iVar8) {
        iVar8 = iVar8 + -0xffff;
      }
      if (iVar8 < -0x8000) {
        iVar8 = iVar8 + 0xffff;
      }
      *(short *)(iVar21 + 0x4d8) = -psVar7[1];
      *(short *)(iVar21 + 0x4dc) = -*psVar7;
      sVar4 = (short)iVar8;
      if (iVar8 < 0) {
        if (iVar8 < -0x2aaa) {
          *(undefined2 *)(iVar21 + 0x4da) = 0x2aaa;
          *(short *)(iVar21 + 0x4e0) = sVar4 + 0x2aaa;
        }
        else {
          *(short *)(iVar21 + 0x4da) = -sVar4;
          *(undefined2 *)(iVar21 + 0x4e0) = 0;
        }
      }
      else if (iVar8 < 0x2aab) {
        *(short *)(iVar21 + 0x4da) = -sVar4;
        *(undefined2 *)(iVar21 + 0x4e0) = 0;
      }
      else {
        *(undefined2 *)(iVar21 + 0x4da) = 0xd556;
        *(short *)(iVar21 + 0x4e0) = sVar4 + -0x2aaa;
      }
      dVar22 = FUN_80293900((double)(float)(dVar22 * dVar22 + (double)(float)(dVar25 * dVar25)));
      iVar8 = FUN_80021884();
      *(short *)(iVar21 + 0x4de) = (short)iVar8;
      sVar4 = *(short *)(iVar21 + 0x4de);
      if (sVar4 < -0x1000) {
        sVar4 = -0x1000;
      }
      else if (0x1000 < sVar4) {
        sVar4 = 0x1000;
      }
      *(short *)(iVar21 + 0x4de) = sVar4;
      *(undefined2 *)(param_11 + 0x54) = 0;
      *(float *)(param_11 + 0x4c) = FLOAT_803e8b3c;
      *(float *)(param_11 + 0x24) = FLOAT_803e8dec;
      *(undefined *)(param_11 + 0x56) = 5;
      if (*(int *)(iVar21 + 0x7f8) == 0) {
        iVar8 = 0;
      }
      else {
        iVar8 = 8;
      }
      if (psVar6[0x50] != iVar8) {
        FUN_8003042c((double)FLOAT_803e8b3c,dVar22,param_3,param_4,param_5,param_6,param_7,param_8,
                     psVar6,iVar8,0,puVar17,pfVar16,uVar19,param_15,param_16);
        FUN_8002f66c((int)psVar6,1);
      }
      param_2 = (double)FLOAT_803dc074;
      FUN_8002fb40((double)FLOAT_803e8c10,param_2);
    }
    else if (cVar14 == '\x05') {
      *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xffb3;
      *(ushort *)(param_11 + 0x70) = *(ushort *)(param_11 + 0x70) & 0xffb7;
      FUN_80036018((int)psVar6);
      if ((*(float *)(param_11 + 0x4c) < FLOAT_803e8b78) ||
         (iVar20 = (**(code **)(*DAT_803dd6d0 + 0x50))(), iVar20 != 0)) {
        fVar1 = *(float *)(param_11 + 0x4c);
        *(float *)(param_11 + 0x4c) = *(float *)(param_11 + 0x24) * FLOAT_803dc074 + fVar1;
        if (FLOAT_803e8b78 < *(float *)(param_11 + 0x4c)) {
          *(float *)(param_11 + 0x4c) = FLOAT_803e8b78;
        }
        uStack_c4 = (int)*(short *)(iVar21 + 0x4e0) ^ 0x80000000;
        local_c8 = 0x43300000;
        iVar20 = (int)((*(float *)(param_11 + 0x4c) - fVar1) *
                      (float)((double)CONCAT44(0x43300000,uStack_c4) - DOUBLE_803e8b58));
        local_c0 = (longlong)iVar20;
        *(short *)(iVar21 + 0x478) = *(short *)(iVar21 + 0x478) + (short)iVar20;
        *(short *)(iVar21 + 0x484) = *(short *)(iVar21 + 0x478);
        *psVar6 = *(short *)(iVar21 + 0x478);
        uStack_b4 = (int)*(short *)(iVar21 + 0x4d8) - (uint)*(ushort *)(iVar21 + 0x4da);
        if (0x8000 < (int)uStack_b4) {
          uStack_b4 = uStack_b4 - 0xffff;
        }
        if ((int)uStack_b4 < -0x8000) {
          uStack_b4 = uStack_b4 + 0xffff;
        }
        uStack_b4 = uStack_b4 ^ 0x80000000;
        local_b8 = 0x43300000;
        uStack_ac = (int)*(short *)(iVar21 + 0x4d8) ^ 0x80000000;
        local_b0 = 0x43300000;
        iVar20 = (int)((float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e8b58) *
                       *(float *)(param_11 + 0x4c) +
                      (float)((double)CONCAT44(0x43300000,uStack_ac) - DOUBLE_803e8b58));
        local_a8 = (longlong)iVar20;
        psVar7[1] = (short)iVar20;
        param_3 = DOUBLE_803e8b58;
        uStack_9c = (int)*(short *)(iVar21 + 0x4dc) - (uint)*(ushort *)(iVar21 + 0x4de);
        if (0x8000 < (int)uStack_9c) {
          uStack_9c = uStack_9c - 0xffff;
        }
        if ((int)uStack_9c < -0x8000) {
          uStack_9c = uStack_9c + 0xffff;
        }
        uStack_9c = uStack_9c ^ 0x80000000;
        local_a0 = 0x43300000;
        uStack_94 = (int)*(short *)(iVar21 + 0x4dc) ^ 0x80000000;
        local_98 = 0x43300000;
        iVar20 = (int)((float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803e8b58) *
                       *(float *)(param_11 + 0x4c) +
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e8b58));
        local_90 = (longlong)iVar20;
        *psVar7 = (short)iVar20;
        fVar1 = FLOAT_803e8b78;
        uStack_84 = (int)*(short *)(iVar21 + 0x4d2) ^ 0x80000000;
        local_88 = 0x43300000;
        iVar20 = (int)((float)((double)CONCAT44(0x43300000,uStack_84) - param_3) *
                      (FLOAT_803e8b78 - *(float *)(param_11 + 0x4c)));
        local_80 = (longlong)iVar20;
        *(short *)(iVar8 + 2) = (short)iVar20;
        uStack_74 = (int)*(short *)(iVar21 + 0x4d0) ^ 0x80000000;
        local_78 = 0x43300000;
        iVar20 = (int)((float)((double)CONCAT44(0x43300000,uStack_74) - param_3) *
                      (fVar1 - *(float *)(param_11 + 0x4c)));
        local_70 = (double)(longlong)iVar20;
        *(short *)(iVar8 + 4) = (short)iVar20;
        uVar2 = *(ushort *)(iVar8 + 4);
        psVar6[2] = ((short)uVar2 >> 2) + (ushort)((short)uVar2 < 0 && (uVar2 & 3) != 0);
        *(short *)(iVar21 + 0x4d4) = psVar7[1];
        *(short *)(iVar21 + 0x4d6) = -*psVar7;
      }
      else {
        *(undefined2 *)(iVar21 + 0x4d2) = 0;
        *(undefined2 *)(iVar21 + 0x4d0) = 0;
        if ((char)param_12 == '\0') {
          *(undefined *)(param_11 + 0x56) = 0;
        }
        else {
          *(undefined *)(param_11 + 0x56) = 6;
        }
        if (*(int *)(iVar21 + 0x7f0) == 0) {
          (**(code **)(*DAT_803dd70c + 0x14))(psVar6,iVar21,1);
          *(code **)(iVar21 + 0x304) = FUN_802a58ac;
          *(undefined2 *)(iVar21 + 0x276) = 1;
        }
        else {
          (**(code **)(*DAT_803dd70c + 0x14))(psVar6,iVar21,0x18);
          *(code **)(iVar21 + 0x304) = FUN_8029fddc;
        }
      }
      param_2 = (double)FLOAT_803dc074;
      FUN_8002fb40((double)FLOAT_803e8c10,param_2);
    }
    else if (cVar14 == '\x06') {
      *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xffb3;
      *(ushort *)(param_11 + 0x70) = *(ushort *)(param_11 + 0x70) & 0xffb7;
      FUN_80036018((int)psVar6);
      if ((char)param_12 == '\0') {
        *(undefined *)(param_11 + 0x56) = 0;
      }
      param_2 = (double)FLOAT_803dc074;
      FUN_8002fb40((double)FLOAT_803e8c10,param_2);
    }
    else {
      if (cVar14 != '\x01') {
        *(undefined4 *)(param_11 + 0x40) = *(undefined4 *)(psVar6 + 6);
        *(undefined4 *)(param_11 + 0x44) = *(undefined4 *)(psVar6 + 8);
        *(undefined4 *)(param_11 + 0x48) = *(undefined4 *)(psVar6 + 10);
        FLOAT_803df0e8 = FLOAT_803e8d44;
        DAT_803df0ec = '\0';
      }
      *(undefined2 *)(param_11 + 0x6e) = 0;
      *(undefined *)(param_11 + 0x56) = 1;
      param_2 = (double)(*(float *)(param_11 + 0x40) - *(float *)(psVar6 + 6));
      fVar1 = *(float *)(param_11 + 0x48) - *(float *)(psVar6 + 10);
      dVar22 = FUN_80293900((double)(float)(param_2 * param_2 + (double)(fVar1 * fVar1)));
      dVar24 = (double)(*(float *)(puVar15 + 6) - *(float *)(param_11 + 0x40));
      dVar26 = (double)(*(float *)(puVar15 + 10) - *(float *)(param_11 + 0x48));
      dVar25 = FUN_80293900((double)(float)(dVar24 * dVar24 + (double)(float)(dVar26 * dVar26)));
      if (dVar22 <= (double)FLOAT_803df0e8) {
        DAT_803df0ec = DAT_803df0ec + '\x01';
      }
      if ((dVar25 <= dVar22) || ('\x05' < DAT_803df0ec)) {
        iVar8 = (int)*(short *)(iVar21 + 0x478) - (uint)*puVar15;
        if (0x8000 < iVar8) {
          iVar8 = iVar8 + -0xffff;
        }
        if (iVar8 < -0x8000) {
          iVar8 = iVar8 + 0xffff;
        }
        if (0x4000 < iVar8) {
          iVar8 = 0x4000;
        }
        if (iVar8 < -0x4000) {
          iVar8 = -0x4000;
        }
        *(short *)(iVar21 + 0x478) =
             *(short *)(iVar21 + 0x478) - (short)((int)(iVar8 * (uint)DAT_803dc070) >> 3);
        *(undefined2 *)(iVar21 + 0x484) = *(undefined2 *)(iVar21 + 0x478);
        fVar1 = FLOAT_803e8b3c;
        if ('\x06' < DAT_803df0ec) {
          iVar8 = 0;
        }
        if ((iVar8 < 0x100) && (-0x100 < iVar8)) {
          *(undefined2 *)(param_11 + 0x6e) = *(undefined2 *)(param_11 + 0x70);
          *(undefined *)(param_11 + 0x56) = 0;
          *(short *)(param_11 + 0x5a) = *(short *)(param_11 + 0x58) + -1;
          psVar6[0x51] = -1;
        }
        else {
          *(float *)(iVar21 + 0x290) = FLOAT_803e8b3c;
          *(float *)(iVar21 + 0x28c) = fVar1;
          (**(code **)(*DAT_803dd70c + 0x10))(puVar15);
          *(undefined4 *)(iVar21 + 0x31c) = 0;
          *(undefined4 *)(iVar21 + 0x318) = 0;
          psVar6[0x7a] = 0;
          psVar6[0x7b] = 0;
          *(undefined2 *)(iVar21 + 0x330) = 0;
          *(undefined *)(iVar21 + 0x25f) = 1;
          *(uint *)(iVar21 + 4) = *(uint *)(iVar21 + 4) & 0xffefffff;
          *(undefined *)(iVar21 + 0x8c5) = 0;
          FUN_802b1604(psVar6,iVar21,iVar21);
          param_2 = (double)FLOAT_803dc074;
          (**(code **)(*DAT_803dd70c + 8))(psVar6,iVar21,&DAT_803dbc28,&DAT_803df138);
        }
      }
      else {
        dVar23 = (double)FLOAT_803e8d5c;
        *(float *)(iVar21 + 0x290) = (float)(dVar23 * -(double)(float)(dVar24 / dVar25));
        *(float *)(iVar21 + 0x28c) = (float)(dVar23 * (double)(float)(dVar26 / dVar25));
        *(float *)(psVar6 + 6) =
             (float)(dVar22 * (double)(float)(dVar24 / dVar25) + (double)*(float *)(param_11 + 0x40)
                    );
        *(float *)(psVar6 + 10) =
             (float)(dVar22 * (double)(float)(dVar26 / dVar25) + (double)*(float *)(param_11 + 0x48)
                    );
        (**(code **)(*DAT_803dd70c + 0x10))(puVar15);
        *(undefined4 *)(iVar21 + 0x31c) = 0;
        *(undefined4 *)(iVar21 + 0x318) = 0;
        psVar6[0x7a] = 0;
        psVar6[0x7b] = 0;
        *(undefined2 *)(iVar21 + 0x330) = 0;
        *(undefined *)(iVar21 + 0x25f) = 1;
        *(uint *)(iVar21 + 4) = *(uint *)(iVar21 + 4) & 0xffefffff;
        *(undefined *)(iVar21 + 0x8c5) = 0;
        FUN_802b1604(psVar6,iVar21,iVar21);
        param_2 = (double)FLOAT_803dc074;
        (**(code **)(*DAT_803dd70c + 8))(psVar6,iVar21,&DAT_803dbc28,&DAT_803df138);
      }
      FLOAT_803df0e8 = (float)dVar22;
    }
    if (*(char *)(param_11 + 0x56) == '\0') {
      (**(code **)(*DAT_803dd70c + 0x14))(psVar6,iVar21,1);
      *(code **)(iVar21 + 0x304) = FUN_802a58ac;
      *(undefined2 *)(iVar21 + 0x276) = 1;
    }
  }
  if (DAT_803df0d8 != '\0') {
    *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 4;
    DAT_803df0d8 = '\0';
  }
  if ((*(int *)(iVar21 + 0x7f0) != 0) &&
     (iVar8 = (**(code **)(**(int **)(*(int *)(iVar21 + 0x7f0) + 0x68) + 0x38))(), iVar8 == 2)) {
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xfffc;
  }
  if ((*(byte *)(iVar21 + 0x3f2) >> 6 & 1) != 0) {
    FUN_8003b408((int)psVar6,iVar21 + 0x364);
  }
  if (DAT_803dd2d4 == '\x02') {
    DAT_803dd2d4 = '\x01';
  }
  if (*(short *)(DAT_803df0cc + 0x44) == 0x2d) {
    FUN_8016ecc8(DAT_803df0cc);
  }
  FUN_802af694((double)FLOAT_803dc074,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  if (((DAT_803df0cc != 0) && ((*(byte *)(iVar21 + 0x3f4) >> 6 & 1) != 0)) &&
     (*(ushort *)(DAT_803df0cc + 0xb0) = *(ushort *)(DAT_803df0cc + 0xb0) & 0xfff8,
     *(char *)(iVar21 + 0x8b3) == '\0')) {
    *(ushort *)(DAT_803df0cc + 0xb0) = *(ushort *)(DAT_803df0cc + 0xb0) | 2;
  }
  *(uint *)(iVar21 + 0x360) = *(uint *)(iVar21 + 0x360) | 0x800000;
  FUN_8006f0b4((double)*(float *)(iVar21 + 0x280),(double)FLOAT_803e8b78,psVar6,param_11 + 0xf0,
               (uint)*(byte *)(iVar21 + 0x8a6),iVar21 + 0x3c4,iVar21 + 4);
  FUN_80286874();
  return;
}

