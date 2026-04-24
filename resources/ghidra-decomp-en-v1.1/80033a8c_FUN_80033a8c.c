// Function: FUN_80033a8c
// Entry: 80033a8c
// Size: 1520 bytes

/* WARNING: Removing unreachable block (ram,0x8003405c) */
/* WARNING: Removing unreachable block (ram,0x80034054) */
/* WARNING: Removing unreachable block (ram,0x8003404c) */
/* WARNING: Removing unreachable block (ram,0x80033aac) */
/* WARNING: Removing unreachable block (ram,0x80033aa4) */
/* WARNING: Removing unreachable block (ram,0x80033a9c) */

void FUN_80033a8c(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6)

{
  float fVar1;
  short *psVar2;
  uint uVar3;
  short *psVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  double dVar7;
  double extraout_f1;
  double dVar8;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar9;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar10;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84 [2];
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
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
  uVar10 = FUN_80286840();
  psVar2 = (short *)((ulonglong)uVar10 >> 0x20);
  psVar4 = (short *)uVar10;
  dVar8 = extraout_f1;
  FUN_80037e6c();
  puVar6 = *(undefined4 **)(psVar2 + 0x2a);
  puVar5 = *(undefined4 **)(psVar4 + 0x2a);
  *(ushort *)(puVar6 + 0x18) = *(ushort *)(puVar6 + 0x18) | 8;
  *(ushort *)(puVar5 + 0x18) = *(ushort *)(puVar5 + 0x18) | 8;
  *puVar6 = psVar4;
  *puVar5 = psVar2;
  if (*(int *)(psVar2 + 0x18) == 0) {
    local_84[0] = (float)dVar8;
    local_88 = (float)param_2;
    local_8c = (float)param_3;
  }
  else {
    FUN_8000dfc8(dVar8,param_2,param_3,local_84,&local_88,&local_8c,*(int *)(psVar2 + 0x18));
  }
  if (*(int *)(psVar4 + 0x18) == 0) {
    local_90 = (float)dVar8;
    local_94 = (float)param_2;
    local_98 = (float)param_3;
  }
  else {
    FUN_8000dfc8(dVar8,param_2,param_3,&local_90,&local_94,&local_98,*(int *)(psVar4 + 0x18));
  }
  if (((psVar2[0x22] == 1) && (*(char *)((int)puVar6 + 0x6a) != '\0')) &&
     ((*(ushort *)(puVar5 + 0x18) & 0x400) == 0)) {
    *(float *)(psVar2 + 6) = *(float *)(psVar2 + 6) - local_84[0];
    *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_88;
    *(float *)(psVar2 + 10) = *(float *)(psVar2 + 10) - local_8c;
    if (param_6 == 0) {
      FUN_8000e0c0((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                   (double)*(float *)(psVar2 + 10),(float *)(psVar2 + 0xc),(float *)(psVar2 + 0xe),
                   (float *)(psVar2 + 0x10),*(int *)(psVar2 + 0x18));
    }
    else {
      *(float *)(psVar2 + 0xc) = (float)((double)*(float *)(psVar2 + 0xc) - dVar8);
      *(float *)(psVar2 + 0xe) = (float)((double)*(float *)(psVar2 + 0xe) - param_2);
      *(float *)(psVar2 + 0x10) = (float)((double)*(float *)(psVar2 + 0x10) - param_3);
    }
  }
  else if (((psVar4[0x22] == 1) && (*(char *)((int)puVar5 + 0x6a) != '\0')) &&
          ((*(ushort *)(puVar6 + 0x18) & 0x400) == 0)) {
    *(float *)(psVar4 + 6) = *(float *)(psVar4 + 6) + local_90;
    *(float *)(psVar4 + 8) = *(float *)(psVar4 + 8) + local_94;
    *(float *)(psVar4 + 10) = *(float *)(psVar4 + 10) + local_98;
    if (param_6 == 0) {
      FUN_8000e0c0((double)*(float *)(psVar4 + 6),(double)*(float *)(psVar4 + 8),
                   (double)*(float *)(psVar4 + 10),(float *)(psVar4 + 0xc),(float *)(psVar4 + 0xe),
                   (float *)(psVar4 + 0x10),*(int *)(psVar4 + 0x18));
    }
    else {
      *(float *)(psVar4 + 0xc) = (float)((double)*(float *)(psVar4 + 0xc) + dVar8);
      *(float *)(psVar4 + 0xe) = (float)((double)*(float *)(psVar4 + 0xe) + param_2);
      *(float *)(psVar4 + 0x10) = (float)((double)*(float *)(psVar4 + 0x10) + param_3);
    }
  }
  else if (*(char *)((int)puVar5 + 0x6a) == '\0') {
    if (*(char *)((int)puVar6 + 0x6a) != '\0') {
      *(float *)(psVar2 + 6) = *(float *)(psVar2 + 6) - local_84[0];
      *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_88;
      *(float *)(psVar2 + 10) = *(float *)(psVar2 + 10) - local_8c;
      if (param_6 == 0) {
        FUN_8000e0c0((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                     (double)*(float *)(psVar2 + 10),(float *)(psVar2 + 0xc),(float *)(psVar2 + 0xe)
                     ,(float *)(psVar2 + 0x10),*(int *)(psVar2 + 0x18));
      }
      else {
        *(float *)(psVar2 + 0xc) = (float)((double)*(float *)(psVar2 + 0xc) - dVar8);
        *(float *)(psVar2 + 0xe) = (float)((double)*(float *)(psVar2 + 0xe) - param_2);
        *(float *)(psVar2 + 0x10) = (float)((double)*(float *)(psVar2 + 0x10) - param_3);
      }
    }
  }
  else if (*(char *)((int)puVar6 + 0x6a) == '\0') {
    if (*(char *)((int)puVar5 + 0x6a) != '\0') {
      *(float *)(psVar4 + 6) = *(float *)(psVar4 + 6) + local_90;
      *(float *)(psVar4 + 8) = *(float *)(psVar4 + 8) + local_94;
      *(float *)(psVar4 + 10) = *(float *)(psVar4 + 10) + local_98;
      if (param_6 == 0) {
        FUN_8000e0c0((double)*(float *)(psVar4 + 6),(double)*(float *)(psVar4 + 8),
                     (double)*(float *)(psVar4 + 10),(float *)(psVar4 + 0xc),(float *)(psVar4 + 0xe)
                     ,(float *)(psVar4 + 0x10),*(int *)(psVar4 + 0x18));
      }
      else {
        *(float *)(psVar4 + 0xc) = (float)((double)*(float *)(psVar4 + 0xc) + dVar8);
        *(float *)(psVar4 + 0xe) = (float)((double)*(float *)(psVar4 + 0xe) + param_2);
        *(float *)(psVar4 + 0x10) = (float)((double)*(float *)(psVar4 + 0x10) + param_3);
      }
    }
  }
  else {
    uVar3 = FUN_80021884();
    uStack_7c = (int)*psVar2 - (uVar3 & 0xffff);
    if (0x8000 < (int)uStack_7c) {
      uStack_7c = uStack_7c - 0xffff;
    }
    if ((int)uStack_7c < -0x8000) {
      uStack_7c = uStack_7c + 0xffff;
    }
    uVar3 = (int)*psVar4 - ((uVar3 & 0xffff) + 0x8000 & 0xffff);
    if (0x8000 < (int)uVar3) {
      uVar3 = uVar3 - 0xffff;
    }
    if ((int)uVar3 < -0x8000) {
      uVar3 = uVar3 + 0xffff;
    }
    uStack_7c = uStack_7c ^ 0x80000000;
    local_84[1] = 176.0;
    dVar8 = (double)FUN_80294964();
    uStack_74 = (uint)*(byte *)((int)puVar6 + 0x6a);
    local_78 = 0x43300000;
    uStack_6c = (uint)*(byte *)((int)puVar6 + 0x6b);
    local_70 = 0x43300000;
    dVar9 = (double)((float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803df5d0) *
                     (float)(dVar8 * dVar8) +
                    (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803df5d0) *
                    (FLOAT_803df598 - (float)(dVar8 * dVar8)));
    uStack_64 = uVar3 ^ 0x80000000;
    local_68 = 0x43300000;
    dVar8 = (double)FUN_80294964();
    uStack_5c = (uint)*(byte *)((int)puVar5 + 0x6a);
    local_60 = 0x43300000;
    uStack_54 = (uint)*(byte *)((int)puVar5 + 0x6b);
    local_58 = 0x43300000;
    dVar8 = (double)((float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803df5d0) *
                     (float)(dVar8 * dVar8) +
                    (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803df5d0) *
                    (FLOAT_803df598 - (float)(dVar8 * dVar8)));
    if ((double)(float)(dVar8 * (double)FLOAT_803dc0b0) <= dVar9) {
      if (dVar8 < (double)(float)(dVar9 * (double)FLOAT_803dc0b0)) {
        dVar8 = (double)FLOAT_803df590;
      }
    }
    else {
      dVar9 = (double)FLOAT_803df590;
    }
    dVar7 = (double)FLOAT_803df590;
    if (dVar7 < (double)(float)(dVar9 + dVar8)) {
      dVar7 = (double)(float)(dVar8 / (double)(float)(dVar9 + dVar8));
    }
    *(float *)(psVar2 + 6) = -(float)((double)local_84[0] * dVar7 - (double)*(float *)(psVar2 + 6));
    *(float *)(psVar2 + 8) = -(float)((double)local_88 * dVar7 - (double)*(float *)(psVar2 + 8));
    *(float *)(psVar2 + 10) = -(float)((double)local_8c * dVar7 - (double)*(float *)(psVar2 + 10));
    FUN_8000e0c0((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                 (double)*(float *)(psVar2 + 10),(float *)(psVar2 + 0xc),(float *)(psVar2 + 0xe),
                 (float *)(psVar2 + 0x10),*(int *)(psVar2 + 0x18));
    fVar1 = (float)((double)FLOAT_803df598 - dVar7);
    *(float *)(psVar4 + 6) = local_90 * fVar1 + *(float *)(psVar4 + 6);
    *(float *)(psVar4 + 8) = local_94 * fVar1 + *(float *)(psVar4 + 8);
    *(float *)(psVar4 + 10) = local_98 * fVar1 + *(float *)(psVar4 + 10);
    FUN_8000e0c0((double)*(float *)(psVar4 + 6),(double)*(float *)(psVar4 + 8),
                 (double)*(float *)(psVar4 + 10),(float *)(psVar4 + 0xc),(float *)(psVar4 + 0xe),
                 (float *)(psVar4 + 0x10),*(int *)(psVar4 + 0x18));
  }
  FUN_8028688c();
  return;
}

