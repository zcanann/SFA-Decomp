// Function: FUN_80164068
// Entry: 80164068
// Size: 976 bytes

/* WARNING: Removing unreachable block (ram,0x80164418) */
/* WARNING: Removing unreachable block (ram,0x80164078) */

void FUN_80164068(short *param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  undefined4 *local_68 [2];
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  longlong local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined8 local_20;
  
  local_68[0] = (undefined4 *)0x0;
  dVar7 = (double)FLOAT_803e3c10;
  iVar1 = FUN_80065fcc((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                       (double)*(float *)(param_1 + 10),param_1,local_68,0,0);
  iVar4 = 0;
  iVar5 = 0;
  puVar3 = local_68[0];
  if (0 < iVar1) {
    do {
      dVar6 = (double)(*(float *)(param_1 + 8) - *(float *)*puVar3);
      if (dVar6 < (double)FLOAT_803e3c00) {
        dVar6 = (double)(float)((double)FLOAT_803e3c14 * dVar6 + (double)FLOAT_803e3bf4);
      }
      if (dVar6 < dVar7) {
        iVar5 = iVar4;
        dVar7 = dVar6;
      }
      puVar3 = puVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  if (*(float *)(param_1 + 0x12) <= FLOAT_803e3c18) {
    if (*(float *)(param_1 + 0x12) < FLOAT_803e3c14) {
      *(float *)(param_1 + 0x12) = FLOAT_803e3c14;
    }
  }
  else {
    *(float *)(param_1 + 0x12) = FLOAT_803e3c18;
  }
  if (*(float *)(param_1 + 0x14) <= FLOAT_803e3c18) {
    if (*(float *)(param_1 + 0x14) < FLOAT_803e3c14) {
      *(float *)(param_1 + 0x14) = FLOAT_803e3c14;
    }
  }
  else {
    *(float *)(param_1 + 0x14) = FLOAT_803e3c18;
  }
  if (*(float *)(param_1 + 0x16) <= FLOAT_803e3c18) {
    if (*(float *)(param_1 + 0x16) < FLOAT_803e3c14) {
      *(float *)(param_1 + 0x16) = FLOAT_803e3c14;
    }
  }
  else {
    *(float *)(param_1 + 0x16) = FLOAT_803e3c18;
  }
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803dc074 + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803dc074 + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * FLOAT_803dc074 + *(float *)(param_1 + 10);
  dVar7 = DOUBLE_803e3c08;
  uStack_5c = (int)*(short *)(param_2 + 0x27c) ^ 0x80000000;
  local_60 = 0x43300000;
  uStack_54 = (int)param_1[2] ^ 0x80000000;
  local_58 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e3c08) * FLOAT_803dc074 +
               (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e3c08));
  local_50 = (longlong)iVar1;
  param_1[2] = (short)iVar1;
  uStack_44 = (int)*(short *)(param_2 + 0x27e) ^ 0x80000000;
  local_48 = 0x43300000;
  uStack_3c = (int)param_1[1] ^ 0x80000000;
  local_40 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_44) - dVar7) * FLOAT_803dc074 +
               (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar7));
  local_38 = (longlong)iVar1;
  param_1[1] = (short)iVar1;
  uStack_2c = (int)*(short *)(param_2 + 0x280) ^ 0x80000000;
  local_30 = 0x43300000;
  uStack_24 = (int)*param_1 ^ 0x80000000;
  local_28 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_2c) - dVar7) * FLOAT_803dc074 +
               (float)((double)CONCAT44(0x43300000,uStack_24) - dVar7));
  local_20 = (double)(longlong)iVar1;
  *param_1 = (short)iVar1;
  if (local_68[0] != (undefined4 *)0x0) {
    if (*(float *)(param_1 + 8) <= FLOAT_803e3bf8 + *(float *)local_68[0][iVar5]) {
      *(float *)(param_1 + 8) = FLOAT_803e3bf8 + *(float *)local_68[0][iVar5];
      if (param_1[0x23] == 0x3fb) {
        uVar2 = FUN_80022264(0x8c,0xb4);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        uStack_24 = (uint)*(ushort *)(param_2 + 0x268);
        *(float *)(param_1 + 0x14) =
             -(FLOAT_803e3c1c * *(float *)(param_1 + 0x14) *
              ((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e3c28) /
              (float)(local_20 - DOUBLE_803e3c08)));
      }
      else {
        uVar2 = FUN_80022264(0x14,0x28);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        uStack_24 = (uint)*(ushort *)(param_2 + 0x268);
        *(float *)(param_1 + 0x14) =
             -(FLOAT_803e3c1c * *(float *)(param_1 + 0x14) *
              ((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e3c28) /
              (float)(local_20 - DOUBLE_803e3c08)));
      }
      local_28 = 0x43300000;
      iVar5 = (int)(FLOAT_803e3c20 * *(float *)(param_1 + 0x14));
      local_20 = (double)(longlong)iVar5;
      if (0x7f < iVar5) {
        iVar5 = 0x7f;
      }
      if (0x10 < iVar5) {
        FUN_8000bb38((uint)param_1,0x27e);
        uVar2 = FUN_80022264(0,5);
        if ((uVar2 == 0) && ((*(byte *)(param_2 + 0x27a) & 8) != 0)) {
          FUN_8000bb38((uint)param_1,0x27f);
        }
      }
    }
    else {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803e3bfc;
    }
  }
  return;
}

