// Function: FUN_80236d30
// Entry: 80236d30
// Size: 1152 bytes

/* WARNING: Removing unreachable block (ram,0x80237190) */
/* WARNING: Removing unreachable block (ram,0x80236d40) */

void FUN_80236d30(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  int iVar2;
  undefined2 *puVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  double dVar10;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar11;
  float local_68;
  float local_64;
  float local_60;
  undefined auStack_5c [8];
  undefined4 local_54;
  undefined4 local_40;
  uint uStack_3c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar11 = FUN_80286838();
  iVar2 = (int)((ulonglong)uVar11 >> 0x20);
  iVar5 = (int)uVar11;
  iVar9 = *(int *)(iVar2 + 0x4c);
  uVar8 = 0;
  uVar7 = 0;
  uVar6 = 0;
  puVar3 = FUN_8000facc();
  if (*(char *)(iVar5 + 0x25) == '\0') {
    *(float *)(iVar5 + 0x18) = FLOAT_803e800c * *(float *)(iVar9 + 0x20);
  }
  else {
    uStack_3c = (int)*(char *)(iVar5 + 0x26) ^ 0x80000000;
    local_40 = 0x43300000;
    fVar1 = *(float *)(iVar9 + 0x20) * FLOAT_803e8014;
    param_2 = (double)FLOAT_803e8018;
    param_3 = (double)FLOAT_803dc074;
    dVar10 = FUN_80021434((double)((((float)((double)CONCAT44(0x43300000,uStack_3c) -
                                            DOUBLE_803e8038) / FLOAT_803e8010) *
                                    (FLOAT_803e800c * *(float *)(iVar9 + 0x20) - fVar1) + fVar1) -
                                  *(float *)(iVar5 + 0x18)),param_2,param_3);
    *(float *)(iVar5 + 0x18) = (float)((double)*(float *)(iVar5 + 0x18) + dVar10);
  }
  dVar10 = (double)FUN_800217c8((float *)(puVar3 + 0x22),(float *)(iVar2 + 0x18));
  if (*(char *)(iVar5 + 0x25) == '\x01') {
    uStack_3c = (uint)*(byte *)(iVar9 + 0x26) << 3;
    local_40 = 0x43300000;
    if ((dVar10 <= (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e7ff0)) &&
       (uVar8 = (uint)*(byte *)(iVar9 + 0x1b), uVar8 == 0xf)) {
      uVar8 = FUN_80236b44(DOUBLE_803e7ff0,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      uVar8 = uVar8 & 0xff;
    }
  }
  *(float *)(iVar5 + 4) = *(float *)(iVar5 + 4) - FLOAT_803dc074;
  *(float *)(iVar5 + 8) = *(float *)(iVar5 + 8) - FLOAT_803dc074;
  if (*(float *)(iVar5 + 4) <= FLOAT_803e7ff8) {
    uVar4 = (uint)*(byte *)(iVar9 + 0x1c);
    if (uVar4 < 9) {
      uStack_3c = (uint)*(byte *)(iVar9 + 0x27) << 3;
      local_40 = 0x43300000;
      if (dVar10 <= (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e7ff0)) {
        uVar7 = uVar4;
      }
    }
    if (*(char *)(iVar5 + 0x25) == '\0') {
      uStack_3c = (uint)*(byte *)(iVar9 + 0x26) << 3;
      local_40 = 0x43300000;
      if (((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e7ff0) < dVar10) ||
         ((*(byte *)(iVar5 + 0x22) & 8) != 0)) {
        uVar7 = 0;
      }
      else {
        uVar7 = uVar4;
        if (uVar4 == 0) {
          uVar7 = 2;
        }
      }
    }
    if (*(char *)(iVar5 + 0x25) == '\x01') {
      *(float *)(iVar5 + 4) = *(float *)(iVar5 + 4) + FLOAT_803e801c;
    }
    else {
      *(float *)(iVar5 + 4) = *(float *)(iVar5 + 4) + FLOAT_803e8010;
    }
  }
  if (((*(ushort *)(iVar2 + 0xb0) & 0x800) != 0) || ((*(byte *)(iVar5 + 0x22) & 2) != 0)) {
    if (*(short *)(iVar2 + 0x46) == 0x758) {
      uStack_3c = (uint)*(byte *)(iVar9 + 0x28);
      local_40 = 0x43300000;
      FUN_80098608((double)*(float *)(iVar5 + 0x18),
                   (double)((float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e7ff0) /
                           FLOAT_803e8020));
    }
    else {
      if ((*(char *)(iVar5 + 0x25) == '\x01') && (*(float *)(iVar5 + 8) <= FLOAT_803e7ff8)) {
        if (*(byte *)(iVar9 + 0x1d) < 4) {
          uStack_3c = (uint)*(byte *)(iVar9 + 0x28) << 3;
          local_40 = 0x43300000;
          if (dVar10 <= (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e7ff0)) {
            uVar6 = (uint)*(byte *)(iVar9 + 0x1d);
          }
        }
        *(float *)(iVar5 + 8) = *(float *)(iVar5 + 8) + FLOAT_803e8024;
      }
      local_68 = FLOAT_803e7ff8;
      if (*(short *)(iVar2 + 0x46) == 0x853) {
        if (*(char *)(iVar5 + 0x25) == '\0') {
          local_64 = FLOAT_803e8028;
        }
        else {
          local_64 = FLOAT_803e802c;
        }
      }
      else if (*(char *)(iVar5 + 0x25) == '\0') {
        local_64 = FLOAT_803e8028;
      }
      else {
        local_64 = FLOAT_803e7ff8;
      }
      local_60 = FLOAT_803e7ff8;
      FUN_80098da4(iVar2,uVar8,uVar7,uVar6,&local_68);
    }
  }
  if (((*(char *)(iVar5 + 0x25) == '\x01') && ((*(byte *)(iVar9 + 0x2a) & 2) != 0)) &&
     (*(float *)(iVar5 + 0xc) = *(float *)(iVar5 + 0xc) - FLOAT_803dc074,
     *(float *)(iVar5 + 0xc) <= FLOAT_803e7ff8)) {
    if ((*(ushort *)(iVar2 + 0xb0) & 0x800) != 0) {
      local_54 = *(undefined4 *)(iVar5 + 0x18);
      (**(code **)(*DAT_803dd708 + 8))(iVar2,0x7cb,auStack_5c,2,0xffffffff,0);
    }
    *(float *)(iVar5 + 0xc) = *(float *)(iVar5 + 0xc) + FLOAT_803e8030;
  }
  FUN_80286884();
  return;
}

