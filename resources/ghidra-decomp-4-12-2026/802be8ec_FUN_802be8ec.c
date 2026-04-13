// Function: FUN_802be8ec
// Entry: 802be8ec
// Size: 1388 bytes

/* WARNING: Removing unreachable block (ram,0x802bee34) */
/* WARNING: Removing unreachable block (ram,0x802bee2c) */
/* WARNING: Removing unreachable block (ram,0x802be904) */
/* WARNING: Removing unreachable block (ram,0x802be8fc) */

void FUN_802be8ec(short *param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short sVar4;
  byte bVar6;
  short *psVar5;
  int iVar7;
  uint *puVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  short *local_a8;
  float fStack_a4;
  undefined4 uStack_a0;
  undefined4 uStack_9c;
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
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  puVar8 = *(uint **)(param_1 + 0x5c);
  iVar7 = *(int *)(param_1 + 0x2a);
  local_80[0] = DAT_802c3440;
  local_80[1] = DAT_802c3444;
  local_80[2] = DAT_802c3448;
  local_80[3] = DAT_802c344c;
  local_70 = DAT_802c3450;
  local_6c = DAT_802c3454;
  local_68 = DAT_802c3458;
  local_64 = DAT_802c345c;
  local_60 = DAT_802c3460;
  local_5c = DAT_802c3464;
  local_58 = DAT_802c3468;
  local_54 = DAT_802c346c;
  local_50 = DAT_802c3470;
  local_4c = DAT_802c3474;
  local_48 = DAT_802c3478;
  local_44 = DAT_802c347c;
  if ((param_1[0x58] & 0x1000U) == 0) {
    if (*(char *)(iVar7 + 0xad) != '\0') {
      iVar3 = (int)*(char *)(iVar7 + 0xac);
      if (iVar3 < 0) {
        iVar3 = 0;
      }
      else if (0x23 < iVar3) {
        iVar3 = 0x23;
      }
      local_90 = FLOAT_803e8fd0;
      local_94 = 0;
      local_96 = 0;
      local_98 = 0;
      local_8c = *(undefined4 *)(iVar7 + 0x3c);
      local_88 = *(undefined4 *)(iVar7 + 0x40);
      local_84 = *(undefined4 *)(iVar7 + 0x44);
      (**(code **)(*DAT_803df150 + 4))
                (0,1,&local_98,0x401,0xffffffff,local_80 + (uint)(byte)(&DAT_80335f0c)[iVar3] * 4);
      *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 1;
      FUN_80014acc((double)FLOAT_803e8fc8);
    }
    if (*(int *)(iVar7 + 0x50) != 0) {
      FUN_80014acc((double)FLOAT_803e8fc8);
    }
    *param_1 = *(short *)(puVar8 + 0x3f4);
    if ((*(short *)(puVar8 + 0x9d) != 3) &&
       (iVar7 = FUN_80036868((int)param_1,&local_a8,(int *)0x0,(uint *)0x0,&fStack_a4,&uStack_a0,
                             &uStack_9c), iVar7 != 0)) {
      bVar6 = FUN_8002acfc((int)param_1);
      if ((bVar6 != 0) && (*(char *)((int)puVar8 + 0x14e6) == '\x02')) {
        return;
      }
      FUN_802224e4(param_1,&fStack_a4);
      if (iVar7 == 0x1a) {
        return;
      }
      psVar5 = (short *)FUN_8002bac4();
      if (local_a8 == psVar5) {
        return;
      }
      if (local_a8[0x23] == 0x23) {
        return;
      }
      FUN_800394f0(param_1,puVar8 + 0xef,0x28e,0x1000,0xffffffff,1);
      sVar4 = *param_1 - *local_a8;
      if (0x8000 < sVar4) {
        sVar4 = sVar4 + 1;
      }
      if (sVar4 < -0x8000) {
        sVar4 = sVar4 + -1;
      }
      if ((sVar4 < 0x4001) && (-0x4001 < sVar4)) {
        *(byte *)(puVar8 + 0x53b) = *(byte *)(puVar8 + 0x53b) & 0x7f | 0x80;
      }
      else {
        *(byte *)(puVar8 + 0x53b) = *(byte *)(puVar8 + 0x53b) & 0x7f;
      }
      puVar8[0x536] = (int)*(short *)(puVar8 + 0x9d);
      (**(code **)(*DAT_803dd70c + 0x14))(param_1,puVar8,3);
    }
    if ((*puVar8 & 0x800000) != 0) {
      if ((((*(char *)((int)puVar8 + 0x262) != '\0') ||
           (((int)*(char *)(puVar8 + 0x99) & 0xf0U) != 0)) &&
          ((float)puVar8[0x3da] <= FLOAT_803e8f9c)) && (FLOAT_803e9004 < (float)puVar8[0xa0])) {
        uStack_3c = FUN_80022264(2,5);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        FUN_80014acc((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e8f78));
        puVar8[0x3da] = (uint)FLOAT_803e9008;
        FUN_8000bb38((uint)param_1,0x404);
      }
      if ((*(char *)((int)puVar8 + 0x262) != '\0') ||
         ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 8) != 0)) {
        dVar9 = FUN_80293900((double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                                     *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)));
        *(float *)(param_1 + 0x12) =
             FLOAT_803dc078 * (*(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x46));
        *(float *)(param_1 + 0x16) =
             FLOAT_803dc078 * (*(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x4a));
        uStack_3c = (int)*(short *)(puVar8 + 0x3f7) ^ 0x80000000;
        local_40 = 0x43300000;
        dVar10 = (double)FUN_802945e0();
        uStack_34 = (int)*(short *)(puVar8 + 0x3f7) ^ 0x80000000;
        local_38 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        puVar8[0xa0] = (uint)(float)(-(double)*(float *)(param_1 + 0x16) * dVar11 -
                                    (double)(float)((double)*(float *)(param_1 + 0x12) * dVar10));
        puVar8[0xa0] = (uint)((float)puVar8[0xa0] * FLOAT_803e8fac);
        fVar1 = (float)puVar8[0xa0];
        fVar2 = FLOAT_803e9010;
        if ((FLOAT_803e9010 <= fVar1) && (fVar2 = fVar1, (float)puVar8[0x3d7] < fVar1)) {
          fVar2 = (float)puVar8[0x3d7];
        }
        puVar8[0xa0] = (uint)fVar2;
        dVar11 = (double)(float)puVar8[0xa0];
        dVar10 = (double)FLOAT_803e8f9c;
        if ((dVar10 <= dVar11) && (dVar10 = dVar11, dVar9 < dVar11)) {
          dVar10 = dVar9;
        }
        puVar8[0xa0] = (uint)(float)dVar10;
        if ((*(byte *)(puVar8 + 0x3d2) >> 6 & 1) == 0) {
          puVar8[0xa5] = puVar8[0xa0];
        }
      }
      *puVar8 = *puVar8 & 0xff7fffff;
    }
    puVar8[0x3da] = (uint)((float)puVar8[0x3da] - FLOAT_803dc074);
    if ((float)puVar8[0x3da] < FLOAT_803e8f9c) {
      puVar8[0x3da] = (uint)FLOAT_803e8f9c;
    }
    if (puVar8 != (uint *)0x0) {
      FUN_80026d18(puVar8[0x53e]);
    }
  }
  return;
}

