// Function: FUN_802be17c
// Entry: 802be17c
// Size: 1388 bytes

/* WARNING: Removing unreachable block (ram,0x802be6bc) */
/* WARNING: Removing unreachable block (ram,0x802be6c4) */

void FUN_802be17c(short *param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short sVar4;
  short *psVar5;
  int iVar6;
  uint *puVar7;
  undefined4 uVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f30;
  undefined8 in_f31;
  short *local_a8;
  undefined auStack164 [4];
  undefined auStack160 [4];
  undefined auStack156 [4];
  undefined2 local_98;
  undefined2 local_96;
  undefined2 local_94;
  float local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80 [4];
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  puVar7 = *(uint **)(param_1 + 0x5c);
  iVar6 = *(int *)(param_1 + 0x2a);
  local_80[0] = DAT_802c2cc0;
  local_80[1] = DAT_802c2cc4;
  local_80[2] = DAT_802c2cc8;
  local_80[3] = DAT_802c2ccc;
  local_70 = DAT_802c2cd0;
  local_6c = DAT_802c2cd4;
  local_68 = DAT_802c2cd8;
  local_64 = DAT_802c2cdc;
  local_60 = DAT_802c2ce0;
  local_5c = DAT_802c2ce4;
  local_58 = DAT_802c2ce8;
  local_54 = DAT_802c2cec;
  local_50 = DAT_802c2cf0;
  local_4c = DAT_802c2cf4;
  local_48 = DAT_802c2cf8;
  local_44 = DAT_802c2cfc;
  if ((param_1[0x58] & 0x1000U) == 0) {
    if (*(char *)(iVar6 + 0xad) != '\0') {
      iVar3 = (int)*(char *)(iVar6 + 0xac);
      if (iVar3 < 0) {
        iVar3 = 0;
      }
      else if (0x23 < iVar3) {
        iVar3 = 0x23;
      }
      local_90 = FLOAT_803e8338;
      local_94 = 0;
      local_96 = 0;
      local_98 = 0;
      local_8c = *(undefined4 *)(iVar6 + 0x3c);
      local_88 = *(undefined4 *)(iVar6 + 0x40);
      local_84 = *(undefined4 *)(iVar6 + 0x44);
      (**(code **)(*DAT_803de4d0 + 4))
                (0,1,&local_98,0x401,0xffffffff,local_80 + (uint)(byte)(&DAT_803352ac)[iVar3] * 4);
      *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 1;
      FUN_80014aa0((double)FLOAT_803e8330);
    }
    if (*(int *)(iVar6 + 0x50) != 0) {
      FUN_80014aa0((double)FLOAT_803e8330);
    }
    *param_1 = *(short *)(puVar7 + 0x3f4);
    if ((*(short *)(puVar7 + 0x9d) != 3) &&
       (iVar6 = FUN_80036770(param_1,&local_a8,0,0,auStack164,auStack160,auStack156), iVar6 != 0)) {
      iVar3 = FUN_8002ac24(param_1);
      if (((iVar3 != 0) && (*(char *)((int)puVar7 + 0x14e6) == '\x02')) ||
         (((FUN_80221e94((double)FLOAT_803e8368,param_1,auStack164), iVar6 == 0x1a ||
           (psVar5 = (short *)FUN_8002b9ec(), local_a8 == psVar5)) || (local_a8[0x23] == 0x23))))
      goto LAB_802be6bc;
      FUN_800393f8(param_1,puVar7 + 0xef,0x28e,0x1000,0xffffffff,1);
      sVar4 = *param_1 - *local_a8;
      if (0x8000 < sVar4) {
        sVar4 = sVar4 + 1;
      }
      if (sVar4 < -0x8000) {
        sVar4 = sVar4 + -1;
      }
      if ((sVar4 < 0x4001) && (-0x4001 < sVar4)) {
        *(byte *)(puVar7 + 0x53b) = *(byte *)(puVar7 + 0x53b) & 0x7f | 0x80;
      }
      else {
        *(byte *)(puVar7 + 0x53b) = *(byte *)(puVar7 + 0x53b) & 0x7f;
      }
      puVar7[0x536] = (int)*(short *)(puVar7 + 0x9d);
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,puVar7,3);
    }
    if ((*puVar7 & 0x800000) != 0) {
      if (((*(char *)((int)puVar7 + 0x262) != '\0') ||
          (((int)*(char *)(puVar7 + 0x99) & 0xf0U) != 0)) &&
         (((float)puVar7[0x3da] <= FLOAT_803e8304 && (FLOAT_803e836c < (float)puVar7[0xa0])))) {
        uStack60 = FUN_800221a0(2,5);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        FUN_80014aa0((double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e82e0));
        puVar7[0x3da] = (uint)FLOAT_803e8370;
        FUN_8000bb18(param_1,0x404);
      }
      if ((*(char *)((int)puVar7 + 0x262) != '\0') ||
         ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 8) != 0)) {
        dVar9 = (double)FUN_802931a0((double)(*(float *)(param_1 + 0x12) *
                                              *(float *)(param_1 + 0x12) +
                                             *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)
                                             ));
        *(float *)(param_1 + 0x12) =
             FLOAT_803db418 * (*(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x46));
        *(float *)(param_1 + 0x16) =
             FLOAT_803db418 * (*(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x4a));
        uStack60 = (int)*(short *)(puVar7 + 0x3f7) ^ 0x80000000;
        local_40 = 0x43300000;
        dVar10 = (double)FUN_80293e80((double)((FLOAT_803e8374 *
                                               (float)((double)CONCAT44(0x43300000,uStack60) -
                                                      DOUBLE_803e82e0)) / FLOAT_803e8320));
        uStack52 = (int)*(short *)(puVar7 + 0x3f7) ^ 0x80000000;
        local_38 = 0x43300000;
        dVar11 = (double)FUN_80294204((double)((FLOAT_803e8374 *
                                               (float)((double)CONCAT44(0x43300000,uStack52) -
                                                      DOUBLE_803e82e0)) / FLOAT_803e8320));
        puVar7[0xa0] = (uint)(float)(-(double)*(float *)(param_1 + 0x16) * dVar11 -
                                    (double)(float)((double)*(float *)(param_1 + 0x12) * dVar10));
        puVar7[0xa0] = (uint)((float)puVar7[0xa0] * FLOAT_803e8314);
        fVar1 = (float)puVar7[0xa0];
        fVar2 = FLOAT_803e8378;
        if ((FLOAT_803e8378 <= fVar1) && (fVar2 = fVar1, (float)puVar7[0x3d7] < fVar1)) {
          fVar2 = (float)puVar7[0x3d7];
        }
        puVar7[0xa0] = (uint)fVar2;
        dVar11 = (double)(float)puVar7[0xa0];
        dVar10 = (double)FLOAT_803e8304;
        if ((dVar10 <= dVar11) && (dVar10 = dVar11, dVar9 < dVar11)) {
          dVar10 = dVar9;
        }
        puVar7[0xa0] = (uint)(float)dVar10;
        if ((*(byte *)(puVar7 + 0x3d2) >> 6 & 1) == 0) {
          puVar7[0xa5] = puVar7[0xa0];
        }
      }
      *puVar7 = *puVar7 & 0xff7fffff;
    }
    puVar7[0x3da] = (uint)((float)puVar7[0x3da] - FLOAT_803db414);
    if ((float)puVar7[0x3da] < FLOAT_803e8304) {
      puVar7[0x3da] = (uint)FLOAT_803e8304;
    }
    if (puVar7 != (uint *)0x0) {
      FUN_80026c54(puVar7[0x53e]);
    }
  }
LAB_802be6bc:
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  return;
}

