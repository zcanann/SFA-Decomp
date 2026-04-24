// Function: FUN_801b7c14
// Entry: 801b7c14
// Size: 1272 bytes

void FUN_801b7c14(short *param_1)

{
  byte bVar1;
  float fVar2;
  int *piVar3;
  int iVar4;
  uint uVar5;
  short sVar6;
  float *pfVar7;
  int iVar8;
  int iVar9;
  float local_88;
  float local_84;
  float local_80;
  short local_7c [6];
  float local_70;
  float local_6c;
  float local_68;
  float afStack_64 [17];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  iVar8 = *(int *)(param_1 + 0x26);
  iVar9 = *(int *)(param_1 + 0x5c);
  bVar1 = *(byte *)(iVar9 + 0x1d);
  if ((bVar1 & 1) == 0) {
    piVar3 = *(int **)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4);
    pfVar7 = (float *)piVar3[10];
    if ((pfVar7 != (float *)0x0) && ((bVar1 & 4) != 0)) {
      if (FLOAT_803e5710 <= *pfVar7) {
        *(byte *)(iVar9 + 0x1d) = bVar1 & 0xfb;
      }
    }
    *(ushort *)(iVar9 + 0x18) = *(short *)(iVar9 + 0x18) - (ushort)DAT_803dc070;
    if (*(short *)(iVar9 + 0x18) < 1) {
      FUN_80027a90((double)FLOAT_803e571c,piVar3,0,-1,0,0x10);
      *(undefined2 *)(iVar9 + 0x1a) = *(undefined2 *)(iVar8 + 0x1c);
      if (*(short *)(iVar9 + 0x1a) < 0xf) {
        *(undefined2 *)(iVar9 + 0x1a) = 0xf;
      }
      *(byte *)(iVar9 + 0x1d) = *(byte *)(iVar9 + 0x1d) | 1;
      FUN_8000bb38((uint)param_1,0x1f7);
      *(undefined *)(iVar9 + 0x1c) = 0x14;
    }
  }
  else {
    if ((bVar1 & 4) == 0) {
      *(byte *)(iVar9 + 0x1d) = bVar1 | 4;
      uStack_1c = FUN_80022264(0x14,0x28);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar9 + 0x10) = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5730);
      uStack_14 = FUN_80022264(6,10);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(iVar9 + 0x14) =
           (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e5730) / FLOAT_803e5714;
    }
    *(ushort *)(iVar9 + 0x1a) = *(short *)(iVar9 + 0x1a) - (ushort)DAT_803dc070;
    *(byte *)(iVar9 + 0x1c) = *(char *)(iVar9 + 0x1c) - DAT_803dc070;
    if (*(char *)(iVar9 + 0x1c) < '\x01') {
      FUN_8000bb38((uint)param_1,0x9f);
    }
    if (*(short *)(iVar9 + 0x1a) < 1) {
      FUN_80027a90((double)FLOAT_803e5718,
                   *(int **)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4),0,-1,0,
                   0x10);
      *(undefined2 *)(iVar9 + 0x18) = *(undefined2 *)(iVar8 + 0x1a);
      if (*(short *)(iVar9 + 0x18) < 0xf) {
        *(undefined2 *)(iVar9 + 0x18) = 0xf;
      }
      *(byte *)(iVar9 + 0x1d) = *(byte *)(iVar9 + 0x1d) & 0xfe;
      FUN_8000bb38((uint)param_1,0x1f6);
    }
  }
  iVar8 = FUN_800395a4((int)param_1,0);
  sVar6 = -*(short *)(iVar8 + 10) + 0x100;
  if (0x800 < sVar6) {
    sVar6 = -*(short *)(iVar8 + 10) + -0x700;
  }
  *(short *)(iVar8 + 10) = -sVar6;
  iVar8 = FUN_800395a4((int)param_1,1);
  sVar6 = -*(short *)(iVar8 + 10) + 0xa0;
  if (0x800 < sVar6) {
    sVar6 = -*(short *)(iVar8 + 10) + -0x760;
  }
  *(short *)(iVar8 + 10) = -sVar6;
  iVar8 = FUN_8002bac4();
  local_70 = -*(float *)(param_1 + 6);
  local_6c = -*(float *)(param_1 + 8);
  local_68 = -*(float *)(param_1 + 10);
  local_7c[0] = -*param_1;
  local_7c[1] = 0;
  local_7c[2] = 0;
  FUN_80021c64(afStack_64,(int)local_7c);
  FUN_80022790((double)*(float *)(iVar8 + 0xc),(double)*(float *)(iVar8 + 0x10),
               (double)*(float *)(iVar8 + 0x14),afStack_64,&local_80,&local_84,&local_88);
  if ((*(byte *)(iVar9 + 0x1d) & 2) != 0) {
    local_84 = *(float *)(param_1 + 8) - *(float *)(iVar8 + 0x10);
    if (local_84 < FLOAT_803e5720) {
      local_84 = -local_84;
    }
    if (local_84 < FLOAT_803e5724) {
      local_88 = local_88 * local_88;
      if (local_88 <= *(float *)(iVar9 + 8)) {
        iVar4 = *(int *)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4);
        uStack_14 = (int)*(short *)(*(int *)(iVar4 + (*(ushort *)(iVar4 + 0x18) >> 1 & 1) * 4 + 4) +
                                   (uint)*(byte *)(iVar9 + 0x1e) * 0x10) ^ 0x80000000;
        local_18 = 0x43300000;
        if (local_80 <=
            *(float *)(param_1 + 4) *
            (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e5730)) {
          FUN_80036548(iVar8,(int)param_1,'\v',4,0);
        }
      }
    }
  }
  if ((*(byte *)(iVar9 + 0x1d) & 4) != 0) {
    *(float *)(iVar9 + 0x10) = *(float *)(iVar9 + 0x14) * FLOAT_803dc074 + *(float *)(iVar9 + 0x10);
    if (*(float *)(iVar9 + 0x10) <= FLOAT_803e5728) {
      if (*(float *)(iVar9 + 0x10) < FLOAT_803e5714) {
        uStack_14 = FUN_80022264(6,10);
        fVar2 = FLOAT_803e5714;
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        *(float *)(iVar9 + 0x14) =
             (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e5730) / FLOAT_803e5714;
        *(float *)(iVar9 + 0x10) = fVar2;
      }
    }
    else {
      uStack_14 = FUN_80022264(6,10);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(iVar9 + 0x14) =
           -(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e5730) / FLOAT_803e5714;
      *(float *)(iVar9 + 0x10) = FLOAT_803e5728;
    }
  }
  uVar5 = FUN_80020078(0x1f0);
  if (uVar5 == 0) {
    *(byte *)(iVar9 + 0x1d) = *(byte *)(iVar9 + 0x1d) & 0xfd;
  }
  else {
    *(byte *)(iVar9 + 0x1d) = *(byte *)(iVar9 + 0x1d) | 2;
  }
  return;
}

