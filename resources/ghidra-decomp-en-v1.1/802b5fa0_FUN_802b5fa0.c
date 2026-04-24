// Function: FUN_802b5fa0
// Entry: 802b5fa0
// Size: 2244 bytes

/* WARNING: Removing unreachable block (ram,0x802b6840) */
/* WARNING: Removing unreachable block (ram,0x802b6838) */
/* WARNING: Removing unreachable block (ram,0x802b5fb8) */
/* WARNING: Removing unreachable block (ram,0x802b5fb0) */

void FUN_802b5fa0(short *param_1)

{
  char cVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  ushort *puVar5;
  int iVar6;
  short *psVar7;
  uint *puVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  
  puVar8 = *(uint **)(param_1 + 0x5c);
  dVar11 = (double)FLOAT_803dc074;
  puVar8[0xd8] = puVar8[0xd8] & 0xf7ffffff;
  if (((*(byte *)((int)puVar8 + 0x3f2) >> 5 & 1) != 0) && ((param_1[0x58] & 0x1000U) != 0)) {
    *(undefined *)((int)puVar8 + 0x25f) = 0;
  }
  (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_1,puVar8 + 1);
  (**(code **)(*DAT_803dd728 + 0x14))(param_1,puVar8 + 1);
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_1,puVar8 + 1);
  FUN_80026d18(DAT_803df0a0);
  if ((float)puVar8[0x208] < FLOAT_803e8b88) {
    (**(code **)(*DAT_803dd70c + 0xc))(param_1,puVar8,&DAT_803dbc28);
    if (*(char *)((int)puVar8 + 0x34d) == '\x01') {
      if (((DAT_803df0cc != 0) && ((*(byte *)(puVar8 + 0xfd) >> 6 & 1) != 0)) &&
         ((iVar4 = *(int *)(DAT_803df0cc + 0x54), *(int *)(iVar4 + 0x50) != 0 ||
          ((*(char *)(iVar4 + 0xad) != '\0' && (*(char *)(iVar4 + 0xac) != '\x0e')))))) {
        *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 1;
        puVar8[0x1f6] = (uint)FLOAT_803e8b3c;
        *(undefined *)((int)puVar8 + 0x8ce) = *(undefined *)((int)puVar8 + 0x8cd);
        if ((*(byte *)(puVar8[0xf7] + (uint)*(byte *)((int)puVar8 + 0x8a9) * 0xb0 + 0x88) & 1) != 0)
        {
          puVar8[0x208] = (uint)FLOAT_803e8d40;
        }
        iVar6 = puVar8[0xf7] + (uint)*(byte *)((int)puVar8 + 0x8a9) * 0xb0;
        if ((*(byte *)(iVar6 + 0x88) & 2) != 0) {
          *(undefined *)((int)puVar8 + 0x8ad) =
               *(undefined *)(iVar6 + *(char *)((int)puVar8 + 0x8cd) + 0xa8);
          *(undefined *)(puVar8 + 0x22b) =
               *(undefined *)
                (puVar8[0xf7] + (uint)*(byte *)((int)puVar8 + 0x8a9) * 0xb0 +
                 (int)*(char *)((int)puVar8 + 0x8cd) + 0xab);
          uStack_44 = (uint)*(byte *)((int)puVar8 + 0x8ad);
          local_48 = 0x43300000;
          puVar8[0x20a] = (uint)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e8bd0);
          *(char *)((int)puVar8 + 0x8ab) = *(char *)((int)puVar8 + 0x8ab) + '\x01';
          puVar8[0x130] = *(uint *)(iVar4 + 0x50);
        }
        iVar6 = *(int *)(iVar4 + 0x50);
        if (iVar6 == 0) {
          if (*(char *)(iVar4 + 0xad) != '\0') {
            FUN_80014acc((double)FLOAT_803e8b70);
            DAT_803df0d9 = 1;
          }
        }
        else {
          if ((*(byte *)(*(int *)(iVar6 + 0x50) + 0x76) & 4) != 0) {
            FUN_80014acc((double)FLOAT_803e8b70);
          }
          if ((*(byte *)(*(int *)(iVar6 + 0x50) + 0x76) & 8) != 0) {
            DAT_803df0d9 = 1;
          }
        }
        cVar1 = *(char *)((int)puVar8 + 0x8a9);
        if (cVar1 == '\x0f') {
          *(undefined *)((int)puVar8 + 0x8c1) = 1;
        }
        else if (cVar1 == '\x1b') {
          *(undefined *)((int)puVar8 + 0x8c1) = 2;
        }
        else if (cVar1 == '\x11') {
          *(undefined *)((int)puVar8 + 0x8c1) = 0;
        }
        else {
          *(undefined *)((int)puVar8 + 0x8c1) = 1;
        }
      }
      if (*(int *)(*(int *)(param_1 + 0x2a) + 0x50) != 0) {
        *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 1;
        puVar8[0x1f6] = (uint)FLOAT_803e8b3c;
        *(undefined *)((int)puVar8 + 0x8ce) = *(undefined *)((int)puVar8 + 0x8cd);
        if ((*(byte *)(puVar8[0xf7] + (uint)*(byte *)((int)puVar8 + 0x8a9) * 0xb0 + 0x88) & 1) != 0)
        {
          puVar8[0x208] = (uint)FLOAT_803e8d40;
        }
        iVar4 = puVar8[0xf7] + (uint)*(byte *)((int)puVar8 + 0x8a9) * 0xb0;
        if ((*(byte *)(iVar4 + 0x88) & 2) != 0) {
          *(undefined *)((int)puVar8 + 0x8ad) =
               *(undefined *)(iVar4 + *(char *)((int)puVar8 + 0x8cd) + 0xa8);
          *(undefined *)(puVar8 + 0x22b) =
               *(undefined *)
                (puVar8[0xf7] + (uint)*(byte *)((int)puVar8 + 0x8a9) * 0xb0 +
                 (int)*(char *)((int)puVar8 + 0x8cd) + 0xab);
          uStack_44 = (uint)*(byte *)((int)puVar8 + 0x8ad);
          local_48 = 0x43300000;
          puVar8[0x20a] = (uint)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e8bd0);
          *(char *)((int)puVar8 + 0x8ab) = *(char *)((int)puVar8 + 0x8ab) + '\x01';
          puVar8[0x130] = *(uint *)(*(int *)(param_1 + 0x2a) + 0x50);
        }
      }
    }
    if ((puVar8[0xd8] & 2) != 0) {
      psVar7 = (short *)puVar8[0x37];
      if (((psVar7 == (short *)0x0) || ((*(uint *)(*(int *)(psVar7 + 0x28) + 0x44) & 0x40) == 0)) ||
         ((*(uint *)(*(int *)(psVar7 + 0x28) + 0x44) & 0x8000) != 0)) {
        if ((*(int *)(param_1 + 0x18) != 0) && (psVar7 == (short *)0x0)) {
          FUN_80063000(param_1,(short *)0x0,1);
        }
      }
      else {
        FUN_80063000(param_1,psVar7,1);
      }
    }
    puVar8[0xd8] = puVar8[0xd8] | 2;
    if ((puVar8[0x1fc] != 0) &&
       (((param_1[0x58] & 0x1000U) != 0 ||
        (iVar4 = FUN_80080100((int *)&DAT_803dd32c,2,(int)*(short *)(puVar8 + 0x9d)), iVar4 != -1)))
       ) {
      (**(code **)(**(int **)(puVar8[0x1fc] + 0x68) + 0x34))
                (puVar8[0x1fc],local_50,&local_54,&local_58);
      (**(code **)(*DAT_803dd6d0 + 0x2c))((double)local_50[0],(double)local_54,(double)local_58);
      FUN_802aa46c(param_1,puVar8,(undefined2 *)puVar8[0x1fc],0,0,0,0,0);
    }
    if ((*(char *)((int)puVar8 + 0x25f) == '\x01') && ((puVar8[1] & 0x100000) == 0)) {
      if (((puVar8[0xd8] & 0x2000) == 0) && ((*(byte *)(puVar8 + 0x99) & 0x33) != 0)) {
        *(float *)(param_1 + 0x14) =
             (float)((double)(*(float *)(param_1 + 0xe) - *(float *)(param_1 + 0x48)) / dVar11);
        if (*(float *)(param_1 + 0x14) < FLOAT_803e8db4) {
          *(float *)(param_1 + 0x14) = FLOAT_803e8db4;
        }
        if (FLOAT_803e8b3c < *(float *)(param_1 + 0x14)) {
          *(float *)(param_1 + 0x14) = FLOAT_803e8b3c;
        }
      }
      if ((((*puVar8 & 0x800000) != 0) && (FLOAT_803e8b3c == (float)puVar8[0x224])) &&
         (FLOAT_803e8b3c == (float)puVar8[0x225])) {
        dVar9 = FUN_80293900((double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                                     *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)));
        if (*(int *)(param_1 + 0x18) == 0) {
          *(float *)(param_1 + 0x12) =
               (float)((double)(*(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x46)) / dVar11);
          *(float *)(param_1 + 0x16) =
               (float)((double)(*(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x4a)) / dVar11);
        }
        else {
          *(float *)(param_1 + 0x12) =
               (float)((double)(*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40)) / dVar11);
          *(float *)(param_1 + 0x16) =
               (float)((double)(*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44)) / dVar11);
        }
        if ((((*(byte *)(puVar8 + 0x99) & 2) != 0) && ((*(byte *)(puVar8 + 0x99) & 0x20) == 0)) ||
           ((*(char *)((int)puVar8 + 0x262) != '\0' ||
            ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 8) != 0)))) {
          if (((float)puVar8[0x104] <= FLOAT_803e8b3c) && (FLOAT_803e8df8 < (float)puVar8[0xa0])) {
            FUN_80014acc((double)FLOAT_803e8ba8);
            puVar8[0x104] = (uint)FLOAT_803e8bc8;
            FUN_8000bb38((uint)param_1,0x404);
          }
          uStack_44 = (int)*(short *)(puVar8 + 0x121) ^ 0x80000000;
          local_48 = 0x43300000;
          dVar11 = (double)FUN_802945e0();
          uStack_3c = (int)*(short *)(puVar8 + 0x121) ^ 0x80000000;
          local_40 = 0x43300000;
          dVar10 = (double)FUN_80294964();
          puVar8[0xa0] = (uint)(float)(-(double)*(float *)(param_1 + 0x16) * dVar10 -
                                      (double)(float)((double)*(float *)(param_1 + 0x12) * dVar11));
          puVar8[0xa0] = (uint)((float)puVar8[0xa0] * FLOAT_803e8c5c);
          fVar2 = (float)puVar8[0xa0];
          fVar3 = FLOAT_803e8da8 * (float)puVar8[0xa6];
          if ((fVar3 <= fVar2) && (fVar3 = fVar2, (float)puVar8[0x101] < fVar2)) {
            fVar3 = (float)puVar8[0x101];
          }
          puVar8[0xa0] = (uint)fVar3;
          dVar10 = (double)(float)puVar8[0xa0];
          dVar11 = (double)FLOAT_803e8b3c;
          if ((dVar11 <= dVar10) && (dVar11 = dVar10, dVar9 < dVar10)) {
            dVar11 = dVar9;
          }
          puVar8[0xa0] = (uint)(float)dVar11;
          if ((*(byte *)(puVar8 + 0xfc) >> 6 & 1) == 0) {
            puVar8[0xa5] = puVar8[0xa0];
          }
        }
        *puVar8 = *puVar8 & 0xff7fffff;
      }
    }
    if ((param_1[0x58] & 0x1000U) == 0) {
      *param_1 = *(short *)(puVar8 + 0x11e);
    }
    puVar5 = (ushort *)FUN_801e2398();
    if ((puVar5 != (ushort *)0x0) && (iVar4 = FUN_801e18cc((int)puVar5), iVar4 == 2)) {
      *(float *)(*(int *)(param_1 + 0x32) + 0x20) = *(float *)(param_1 + 6) - *(float *)(puVar5 + 6)
      ;
      *(float *)(*(int *)(param_1 + 0x32) + 0x24) = *(float *)(param_1 + 8) - *(float *)(puVar5 + 8)
      ;
      *(float *)(*(int *)(param_1 + 0x32) + 0x28) =
           *(float *)(param_1 + 10) - *(float *)(puVar5 + 10);
      FUN_80021b8c(puVar5,(float *)(*(int *)(param_1 + 0x32) + 0x20));
      *(float *)(*(int *)(param_1 + 0x32) + 0x20) =
           *(float *)(*(int *)(param_1 + 0x32) + 0x20) + *(float *)(puVar5 + 6);
      *(float *)(*(int *)(param_1 + 0x32) + 0x24) =
           *(float *)(*(int *)(param_1 + 0x32) + 0x24) + *(float *)(puVar5 + 8);
      *(float *)(*(int *)(param_1 + 0x32) + 0x28) =
           *(float *)(*(int *)(param_1 + 0x32) + 0x28) + *(float *)(puVar5 + 10);
      *(uint *)(*(int *)(param_1 + 0x32) + 0x30) =
           *(uint *)(*(int *)(param_1 + 0x32) + 0x30) | 0x2020;
      param_1[2] = puVar5[2];
      puVar8[0xd8] = puVar8[0xd8] | 0x8000000;
    }
    puVar8[0xd8] = puVar8[0xd8] & 0xffbfffff;
  }
  return;
}

