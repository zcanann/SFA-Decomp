// Function: FUN_8020d044
// Entry: 8020d044
// Size: 3136 bytes

/* WARNING: Removing unreachable block (ram,0x8020dc64) */
/* WARNING: Removing unreachable block (ram,0x8020dc5c) */
/* WARNING: Removing unreachable block (ram,0x8020dc54) */
/* WARNING: Removing unreachable block (ram,0x8020dc4c) */
/* WARNING: Removing unreachable block (ram,0x8020dc44) */
/* WARNING: Removing unreachable block (ram,0x8020dc3c) */
/* WARNING: Removing unreachable block (ram,0x8020dc34) */
/* WARNING: Removing unreachable block (ram,0x8020dc2c) */
/* WARNING: Removing unreachable block (ram,0x8020dc24) */
/* WARNING: Removing unreachable block (ram,0x8020d84c) */
/* WARNING: Removing unreachable block (ram,0x8020d094) */
/* WARNING: Removing unreachable block (ram,0x8020d08c) */
/* WARNING: Removing unreachable block (ram,0x8020d084) */
/* WARNING: Removing unreachable block (ram,0x8020d07c) */
/* WARNING: Removing unreachable block (ram,0x8020d074) */
/* WARNING: Removing unreachable block (ram,0x8020d06c) */
/* WARNING: Removing unreachable block (ram,0x8020d064) */
/* WARNING: Removing unreachable block (ram,0x8020d05c) */
/* WARNING: Removing unreachable block (ram,0x8020d054) */

void FUN_8020d044(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,int param_16)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  bool bVar4;
  short sVar5;
  undefined2 *puVar6;
  uint uVar7;
  undefined2 *puVar8;
  uint uVar9;
  ushort uVar13;
  undefined2 *puVar10;
  short sVar14;
  int iVar11;
  short *psVar12;
  char *pcVar15;
  byte bVar16;
  uint *puVar17;
  uint uVar18;
  int iVar19;
  int iVar20;
  undefined8 extraout_f1;
  undefined8 uVar21;
  double dVar22;
  double dVar23;
  double dVar24;
  double in_f23;
  double in_f24;
  double in_f25;
  double in_f26;
  double in_f27;
  double dVar25;
  double in_f28;
  double dVar26;
  double in_f29;
  double dVar27;
  double in_f30;
  double dVar28;
  double in_f31;
  double dVar29;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined uStack_108;
  char local_107 [3];
  undefined4 local_104;
  undefined auStack_100 [6];
  undefined2 local_fa;
  float local_f4;
  float local_f0;
  float local_ec;
  undefined8 local_e8;
  undefined4 local_e0;
  uint uStack_dc;
  longlong local_d8;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
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
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  puVar6 = (undefined2 *)FUN_80286820();
  iVar20 = *(int *)(puVar6 + 0x5c);
  bVar4 = false;
  *(short *)(iVar20 + 6) = *(short *)(iVar20 + 6) + -1;
  if (*(short *)(iVar20 + 6) == 1) {
    uVar21 = extraout_f1;
    uVar7 = FUN_80022264(0x708,3000);
    *(short *)(iVar20 + 6) = (short)uVar7;
    iVar19 = *(int *)(puVar6 + 0x26);
    uVar7 = FUN_8002e144();
    if ((uVar7 & 0xff) != 0) {
      puVar8 = FUN_8002becc(0x20,0x80f);
      *(undefined *)(puVar8 + 2) = *(undefined *)(iVar19 + 4);
      *(undefined *)(puVar8 + 3) = *(undefined *)(iVar19 + 6);
      *(undefined *)((int)puVar8 + 5) = *(undefined *)(iVar19 + 5);
      *(undefined *)((int)puVar8 + 7) = *(undefined *)(iVar19 + 7);
      *(undefined4 *)(puVar8 + 4) = *(undefined4 *)(puVar6 + 6);
      *(undefined4 *)(puVar8 + 6) = *(undefined4 *)(puVar6 + 8);
      *(undefined4 *)(puVar8 + 8) = *(undefined4 *)(puVar6 + 10);
      param_11 = (int)*(char *)(puVar6 + 0x56);
      param_12 = 0xffffffff;
      param_13 = 0;
      FUN_8002e088(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar8,5,
                   *(char *)(puVar6 + 0x56),0xffffffff,(uint *)0x0,param_14,param_15,param_16);
    }
  }
  if (*(short *)(iVar20 + 6) < 0) {
    *(undefined2 *)(iVar20 + 6) = 0;
  }
  FUN_8020cc64();
  if (DAT_803de98a != 0) {
    DAT_803de98a = DAT_803de98a + -1;
  }
  if (DAT_803de988 == '\0') {
    uVar21 = FUN_80020388(1);
    if ((*(byte *)(iVar20 + 8) & 4) == 0) {
      param_13 = 0;
      param_14 = 0;
      param_15 = 0xff;
      param_16 = *DAT_803dd6d0;
      (**(code **)(param_16 + 0x1c))(0x4e,1,0,0);
      uVar21 = (**(code **)(*DAT_803dd6d0 + 0x28))(puVar6,0);
      *(byte *)(iVar20 + 8) = *(byte *)(iVar20 + 8) | 4;
    }
    else if ((*(byte *)(iVar20 + 8) & 8) == 0) {
      local_104 = (&DAT_8032add0)[(byte)(&DAT_803dce30)[*(char *)(iVar20 + 0x10)]];
      (**(code **)(*DAT_803dd6d0 + 0x60))(&local_104,2);
      *(byte *)(iVar20 + 8) = *(byte *)(iVar20 + 8) | 8;
      iVar19 = FUN_8002e1ac(0x43077);
      *(undefined *)(*(int *)(iVar19 + 0xb8) + 0x27c) = (&DAT_803dce50)[*(char *)(iVar20 + 0x10)];
      uVar21 = FUN_8000d03c();
    }
    if ((*(byte *)(iVar20 + 8) & 1) == 0) {
      *(byte *)(iVar20 + 8) = *(byte *)(iVar20 + 8) | 1;
      FUN_80008cbc(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x21f,0,
                   param_13,param_14,param_15,param_16);
      FUN_8005d024(0);
      FUN_8005cf74(0);
    }
    uVar7 = FUN_80014e9c(0);
    local_fa = 100;
    local_f4 = FLOAT_803e72b4;
    local_f0 = FLOAT_803e72b8;
    local_ec = FLOAT_803e72bc;
    (**(code **)(*DAT_803dd708 + 8))(puVar6,0x6f2,auStack_100,2,0xffffffff,0);
    FUN_8020dc84(puVar6,local_107,&uStack_108);
    puVar6[2] = puVar6[2] + -10;
    puVar6[1] = 0x3448;
    *puVar6 = 0x4000;
    puVar8 = (undefined2 *)FUN_8002e1ac(0x42ff5);
    puVar8[2] = puVar6[2];
    puVar8[1] = puVar6[1];
    *puVar8 = *puVar6;
    puVar8 = (undefined2 *)FUN_8002e1ac(0x4300c);
    *(undefined *)(*(int *)(puVar8 + 0x5c) + 0x27d) = *(undefined *)(iVar20 + 9);
    bVar16 = *(byte *)(iVar20 + 0x10);
    uVar18 = 0;
    iVar19 = 0;
    puVar17 = &DAT_8032ae0c;
    pcVar15 = &DAT_803dce20;
    do {
      uVar9 = FUN_80020078(*puVar17);
      if (uVar9 != 0) {
        bVar3 = true;
        if ((*pcVar15 != '\0') && (uVar13 = FUN_800ea540(), 0xad < uVar13)) {
          bVar3 = false;
        }
        if (bVar3) {
          uVar18 = uVar18 | 1 << iVar19;
        }
      }
      puVar17 = puVar17 + 1;
      pcVar15 = pcVar15 + 1;
      iVar19 = iVar19 + 1;
    } while (iVar19 < 5);
    *(char *)(iVar20 + 0x11) = (char)uVar18;
    if ((DAT_803de984 == 0) && (*(char *)(iVar20 + 9) == '\0')) {
      while (!bVar4) {
        *(char *)(iVar20 + 0x10) = *(char *)(iVar20 + 0x10) + local_107[0];
        if (*(char *)(iVar20 + 0x10) < '\0') {
          *(undefined *)(iVar20 + 0x10) = 4;
        }
        else if ('\x04' < *(char *)(iVar20 + 0x10)) {
          *(undefined *)(iVar20 + 0x10) = 0;
        }
        bVar4 = true;
      }
      FUN_8012e114(0x2a7,(&DAT_803dce38)[*(char *)(iVar20 + 0x10)],0x19,0);
      if (((uint)bVar16 != (int)*(char *)(iVar20 + 0x10)) || (*(int *)(puVar6 + 0x7a) == 0)) {
        if (*(int *)(puVar6 + 0x7a) != 0) {
          local_104 = (&DAT_8032add0)[(byte)(&DAT_803dce30)[*(char *)(iVar20 + 0x10)]];
          (**(code **)(*DAT_803dd6d0 + 0x60))(&local_104,1);
          FUN_8000bb38(0,0x97);
        }
        FLOAT_803de9ac = FLOAT_803e7290;
        iVar19 = FUN_8002e1ac((&DAT_8032add0)[(byte)(&DAT_803dce30)[bVar16]]);
        *(undefined *)(*(int *)(iVar19 + 0xb8) + 0x27d) = 0;
        iVar19 = FUN_8002e1ac((&DAT_8032add0)[(byte)(&DAT_803dce30)[*(char *)(iVar20 + 0x10)]]);
        *(undefined *)(*(int *)(iVar19 + 0xb8) + 0x27d) = 1;
        *(undefined4 *)(puVar6 + 0x7a) = 1;
      }
    }
    FLOAT_803de9ac = FLOAT_803de9ac + FLOAT_803e72c0;
    dVar22 = (double)FLOAT_803de9ac;
    if ((double)FLOAT_803e72c4 <= dVar22) {
      FLOAT_803de9ac = FLOAT_803e7290;
    }
    for (uVar18 = 0; (uVar18 & 0xff) < 5; uVar18 = uVar18 + 1) {
      puVar10 = (undefined2 *)FUN_8002e1ac((&DAT_8032adf8)[uVar18 & 0xff]);
      iVar19 = *(int *)(puVar10 + 0x5c);
      puVar10[1] = puVar6[1];
      *puVar10 = *puVar6;
      if ((*(char *)(iVar20 + 9) == '\0') &&
         (((int)(uint)*(byte *)(iVar20 + 0x11) >> (uVar18 & 0x3f) & 1U) != 0)) {
        if ((uVar18 & 0xff) == (int)*(char *)(iVar20 + 0x10)) {
          local_e8 = (double)(longlong)(int)FLOAT_803de9ac;
          uStack_dc = (int)FLOAT_803de9ac & 0xff;
          uVar9 = uStack_dc + 2;
          local_e0 = 0x43300000;
          dVar28 = (double)(FLOAT_803de9ac -
                           (float)((double)CONCAT44(0x43300000,uStack_dc) - DOUBLE_803e72d0));
          iVar11 = iVar19 + uStack_dc * 0x18;
          dVar25 = (double)*(float *)(iVar11 + 0x10);
          fVar1 = *(float *)(iVar11 + 0x28);
          dVar24 = (double)*(float *)(iVar11 + 0x14);
          dVar23 = (double)*(float *)(iVar11 + 0x2c);
          dVar29 = (double)*(float *)(iVar11 + 0x18);
          fVar2 = *(float *)(iVar11 + 0x30);
          *(undefined *)(iVar19 + 0x27d) = 2;
          dVar27 = (double)(float)((double)fVar1 - dVar25);
          dVar26 = (double)(float)((double)fVar2 - dVar29);
          iVar19 = FUN_80021884();
          sVar14 = (short)iVar19;
          sVar5 = sVar14;
          if ((uVar9 & 0xff) < 0x16) {
            iVar19 = FUN_80021884();
            sVar5 = (short)iVar19;
          }
          sVar5 = sVar5 - sVar14;
          if (0x8000 < sVar5) {
            sVar5 = sVar5 + 1;
          }
          if (sVar5 < -0x8000) {
            sVar5 = sVar5 + -1;
          }
          uVar13 = FUN_8012e0e8();
          if ((uVar13 & 0xff) == 0) {
            puVar8[3] = puVar8[3] & 0xbfff;
          }
          else {
            puVar8[3] = puVar8[3] | 0x4000;
          }
          param_2 = DOUBLE_803e72a8;
          uStack_dc = (int)sVar5 ^ 0x80000000;
          local_e0 = 0x43300000;
          dVar22 = (double)(float)((double)CONCAT44(0x43300000,uStack_dc) - DOUBLE_803e72a8);
          local_e8 = (double)CONCAT44(0x43300000,(int)sVar14 ^ 0x80000000);
          iVar19 = (int)(dVar28 * dVar22 + (double)(float)(local_e8 - DOUBLE_803e72a8));
          local_d8 = (longlong)iVar19;
          *puVar8 = (short)iVar19;
          *(float *)(puVar8 + 6) = (float)(dVar28 * dVar27 + dVar25);
          *(float *)(puVar8 + 8) = (float)(dVar28 * (double)(float)(dVar23 - dVar24) + dVar24);
          *(float *)(puVar8 + 10) = (float)(dVar28 * dVar26 + dVar29);
        }
        else {
          *(undefined *)(iVar19 + 0x27d) = 1;
        }
      }
      else {
        *(undefined *)(iVar19 + 0x27d) = 0;
        if ((uVar18 & 0xff) == (int)*(char *)(iVar20 + 0x10)) {
          puVar8[3] = puVar8[3] | 0x4000;
        }
      }
    }
    iVar19 = FUN_8002e1ac((&DAT_8032add0)[(byte)(&DAT_803dce30)[*(char *)(iVar20 + 0x10)]]);
    iVar11 = FUN_800431a4();
    if ((iVar11 == 0) && (DAT_803de98a == 0)) {
      if (*(char *)(iVar20 + 9) == '\x01') {
        FUN_80130118();
        uVar18 = countLeadingZeros(((uint)(byte)((FLOAT_803de980 == FLOAT_803e7290) << 1) << 0x1c)
                                   >> 0x1d ^ 1);
        if (uVar18 >> 5 != 0) {
          FLOAT_803de980 = FLOAT_803e72b0;
        }
        if ((uVar7 & 0x200) == 0) {
          if ((uVar7 & 0x100) != 0) {
            (**(code **)(*DAT_803dd6cc + 8))(4,1);
            FUN_8000a3a0(3,1,0);
            FUN_8000d03c();
            FUN_8000bb38(0,0x98);
            uVar21 = FUN_8012e0b8('\0');
            DAT_803de988 = '\x05';
            DAT_803de990 = 0;
            FUN_80043938(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          }
        }
        else {
          FUN_8000d03c();
          FUN_8000bb38(0,0x99);
          FUN_8000a3a0(2,2,1000);
          (**(code **)(*DAT_803dd6d0 + 0x28))(puVar6,0x50);
          *(undefined *)(iVar20 + 9) = 0;
          DAT_803de98c = 0x1e;
          uVar21 = (**(code **)(*DAT_803dd6d0 + 0x60))(iVar20 + 9,0);
          FUN_80043604(DAT_803de9a8,1,0);
          FUN_80043938(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          DAT_803de98a = 10;
        }
      }
      else if (*(char *)(iVar20 + 9) == '\0') {
        if (DAT_803de98c == 0) {
          if (((DAT_803de984 == 0) &&
              (((uint)*(byte *)(iVar20 + 0x11) & 1 << (int)*(char *)(iVar20 + 0x10)) != 0)) &&
             ((uVar7 & 0x100) != 0)) {
            DAT_803de984 = 10;
            FUN_80043938(dVar22,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          }
        }
        else {
          DAT_803de98c = DAT_803de98c + -1;
        }
        if (DAT_803de984 != 0) {
          FUN_80130118();
          DAT_803de984 = DAT_803de984 + -1;
          if (DAT_803de984 < 2) {
            DAT_803de984 = 0;
            FUN_8000bb38(0,0x98);
            (**(code **)(*DAT_803dd6d0 + 0x28))(iVar19,0x50);
            *(undefined *)(iVar20 + 9) = 1;
            uVar21 = (**(code **)(*DAT_803dd6d0 + 0x60))(iVar20 + 9,0);
            iVar19 = FUN_8002e1ac(0x43077);
            *(undefined *)(*(int *)(iVar19 + 0xb8) + 0x27c) =
                 (&DAT_803dce50)[*(char *)(iVar20 + 0x10)];
            DAT_803de9a8 = FUN_80043070(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,
                                        param_8,(uint)(byte)(&DAT_803dce48)
                                                            [(byte)(&DAT_803dce30)
                                                                   [*(char *)(iVar20 + 0x10)]]);
            FUN_80043658(DAT_803de9a8,1);
            FUN_80026fb8();
            FLOAT_803de980 = FLOAT_803e7290;
            DAT_803dce58 = (int)*(char *)(iVar20 + 0x10);
          }
        }
      }
    }
    else {
      FUN_80130118();
    }
    sVar5 = puVar6[2];
    for (bVar16 = 0; bVar16 < 5; bVar16 = bVar16 + 1) {
      iVar19 = FUN_8002e1ac((&DAT_8032adf8)[bVar16]);
      *(short *)(iVar19 + 4) = sVar5;
    }
    dVar22 = (double)FLOAT_803e72c8;
    for (bVar16 = 0; bVar16 < 5; bVar16 = bVar16 + 1) {
      psVar12 = (short *)FUN_8002e1ac((&DAT_8032add0)[bVar16]);
      if ((&DAT_8032add0)[bVar16] == 0x4300d) {
        *psVar12 = ((short)(&DAT_8032ade4)[bVar16] + 0x4000) - sVar5;
      }
      else {
        *psVar12 = *psVar12 + 0x3c;
      }
      if (2 < *(uint *)(iVar20 + 0x14)) {
        FUN_8000da78((uint)psVar12,0x96);
      }
      dVar23 = (double)FUN_80293eac();
      dVar24 = (double)FUN_80293994();
      *(float *)(psVar12 + 6) =
           (float)((double)(float)(dVar22 * dVar24) * dVar23 + (double)*(float *)(puVar6 + 6));
      dVar23 = (double)FUN_80293994();
      dVar24 = (double)FUN_80293994();
      *(float *)(psVar12 + 8) =
           (float)((double)(float)(dVar22 * dVar24) * dVar23 + (double)*(float *)(puVar6 + 8));
      dVar23 = (double)FUN_80293eac();
      *(float *)(psVar12 + 10) = (float)(dVar22 * dVar23 + (double)*(float *)(puVar6 + 10));
    }
    *(int *)(iVar20 + 0x14) = *(int *)(iVar20 + 0x14) + 1;
  }
  else {
    DAT_803de988 = DAT_803de988 + -1;
    if (DAT_803de988 == '\0') {
      FUN_8005d024(1);
      FUN_8005d06c(1);
      uVar21 = FUN_8005cf74(1);
      FUN_80055464(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (uint)(byte)(&DAT_803dce40)[(byte)(&DAT_803dce30)[*(char *)(iVar20 + 0x10)]],'\0'
                   ,param_11,param_12,param_13,param_14,param_15,param_16);
    }
  }
  FUN_8028686c();
  return;
}

