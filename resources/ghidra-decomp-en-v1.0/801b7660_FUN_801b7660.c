// Function: FUN_801b7660
// Entry: 801b7660
// Size: 1272 bytes

void FUN_801b7660(short *param_1)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  short sVar4;
  float *pfVar5;
  int iVar6;
  int iVar7;
  float local_88;
  float local_84;
  float local_80;
  short local_7c;
  undefined2 local_7a;
  undefined2 local_78;
  float local_70;
  float local_6c;
  float local_68;
  undefined auStack100 [68];
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  iVar6 = *(int *)(param_1 + 0x26);
  iVar7 = *(int *)(param_1 + 0x5c);
  bVar1 = *(byte *)(iVar7 + 0x1d);
  if ((bVar1 & 1) == 0) {
    iVar3 = *(int *)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4);
    pfVar5 = *(float **)(iVar3 + 0x28);
    if (((pfVar5 != (float *)0x0) && ((bVar1 & 4) != 0)) && (FLOAT_803e4a78 <= *pfVar5)) {
      *(byte *)(iVar7 + 0x1d) = bVar1 & 0xfb;
    }
    *(ushort *)(iVar7 + 0x18) = *(short *)(iVar7 + 0x18) - (ushort)DAT_803db410;
    if (*(short *)(iVar7 + 0x18) < 1) {
      FUN_800279cc((double)FLOAT_803e4a84,iVar3,0,0xffffffff,0,0x10);
      *(undefined2 *)(iVar7 + 0x1a) = *(undefined2 *)(iVar6 + 0x1c);
      if (*(short *)(iVar7 + 0x1a) < 0xf) {
        *(undefined2 *)(iVar7 + 0x1a) = 0xf;
      }
      *(byte *)(iVar7 + 0x1d) = *(byte *)(iVar7 + 0x1d) | 1;
      FUN_8000bb18(param_1,0x1f7);
      *(undefined *)(iVar7 + 0x1c) = 0x14;
    }
  }
  else {
    if ((bVar1 & 4) == 0) {
      *(byte *)(iVar7 + 0x1d) = bVar1 | 4;
      uStack28 = FUN_800221a0(0x14,0x28);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar7 + 0x10) = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e4a98);
      uStack20 = FUN_800221a0(6,10);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(iVar7 + 0x14) =
           (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e4a98) / FLOAT_803e4a7c;
    }
    *(ushort *)(iVar7 + 0x1a) = *(short *)(iVar7 + 0x1a) - (ushort)DAT_803db410;
    *(byte *)(iVar7 + 0x1c) = *(char *)(iVar7 + 0x1c) - DAT_803db410;
    if (*(char *)(iVar7 + 0x1c) < '\x01') {
      FUN_8000bb18(param_1,0x9f);
    }
    if (*(short *)(iVar7 + 0x1a) < 1) {
      FUN_800279cc((double)FLOAT_803e4a80,
                   *(undefined4 *)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4),0,
                   0xffffffff,0,0x10);
      *(undefined2 *)(iVar7 + 0x18) = *(undefined2 *)(iVar6 + 0x1a);
      if (*(short *)(iVar7 + 0x18) < 0xf) {
        *(undefined2 *)(iVar7 + 0x18) = 0xf;
      }
      *(byte *)(iVar7 + 0x1d) = *(byte *)(iVar7 + 0x1d) & 0xfe;
      FUN_8000bb18(param_1,0x1f6);
    }
  }
  iVar6 = FUN_800394ac(param_1,0,0);
  sVar4 = -*(short *)(iVar6 + 10) + 0x100;
  if (0x800 < sVar4) {
    sVar4 = -*(short *)(iVar6 + 10) + -0x700;
  }
  *(short *)(iVar6 + 10) = -sVar4;
  iVar6 = FUN_800394ac(param_1,1,0);
  sVar4 = -*(short *)(iVar6 + 10) + 0xa0;
  if (0x800 < sVar4) {
    sVar4 = -*(short *)(iVar6 + 10) + -0x760;
  }
  *(short *)(iVar6 + 10) = -sVar4;
  iVar6 = FUN_8002b9ec();
  local_70 = -*(float *)(param_1 + 6);
  local_6c = -*(float *)(param_1 + 8);
  local_68 = -*(float *)(param_1 + 10);
  local_7c = -*param_1;
  local_7a = 0;
  local_78 = 0;
  FUN_80021ba0(auStack100,&local_7c);
  FUN_800226cc((double)*(float *)(iVar6 + 0xc),(double)*(float *)(iVar6 + 0x10),
               (double)*(float *)(iVar6 + 0x14),auStack100,&local_80,&local_84,&local_88);
  if ((*(byte *)(iVar7 + 0x1d) & 2) != 0) {
    local_84 = *(float *)(param_1 + 8) - *(float *)(iVar6 + 0x10);
    if (local_84 < FLOAT_803e4a88) {
      local_84 = -local_84;
    }
    if (local_84 < FLOAT_803e4a8c) {
      local_88 = local_88 * local_88;
      if (local_88 <= *(float *)(iVar7 + 8)) {
        iVar3 = *(int *)(*(int *)(param_1 + 0x3e) + *(char *)((int)param_1 + 0xad) * 4);
        uStack20 = (int)*(short *)(*(int *)(iVar3 + (*(ushort *)(iVar3 + 0x18) >> 1 & 1) * 4 + 4) +
                                  (uint)*(byte *)(iVar7 + 0x1e) * 0x10) ^ 0x80000000;
        local_18 = 0x43300000;
        if (local_80 <=
            *(float *)(param_1 + 4) *
            (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e4a98)) {
          FUN_80036450(iVar6,param_1,0xb,4,0);
        }
      }
    }
  }
  if ((*(byte *)(iVar7 + 0x1d) & 4) != 0) {
    *(float *)(iVar7 + 0x10) = *(float *)(iVar7 + 0x14) * FLOAT_803db414 + *(float *)(iVar7 + 0x10);
    if (*(float *)(iVar7 + 0x10) <= FLOAT_803e4a90) {
      if (*(float *)(iVar7 + 0x10) < FLOAT_803e4a7c) {
        uStack20 = FUN_800221a0(6,10);
        fVar2 = FLOAT_803e4a7c;
        uStack20 = uStack20 ^ 0x80000000;
        local_18 = 0x43300000;
        *(float *)(iVar7 + 0x14) =
             (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e4a98) / FLOAT_803e4a7c;
        *(float *)(iVar7 + 0x10) = fVar2;
      }
    }
    else {
      uStack20 = FUN_800221a0(6,10);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(iVar7 + 0x14) =
           -(float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e4a98) / FLOAT_803e4a7c;
      *(float *)(iVar7 + 0x10) = FLOAT_803e4a90;
    }
  }
  iVar6 = FUN_8001ffb4(0x1f0);
  if (iVar6 == 0) {
    *(byte *)(iVar7 + 0x1d) = *(byte *)(iVar7 + 0x1d) & 0xfd;
  }
  else {
    *(byte *)(iVar7 + 0x1d) = *(byte *)(iVar7 + 0x1d) | 2;
  }
  return;
}

