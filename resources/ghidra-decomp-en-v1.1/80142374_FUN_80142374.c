// Function: FUN_80142374
// Entry: 80142374
// Size: 1336 bytes

/* WARNING: Removing unreachable block (ram,0x801423c4) */

void FUN_80142374(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 *param_10,undefined4 param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  ushort uVar2;
  float fVar3;
  int iVar4;
  undefined4 uVar5;
  bool bVar7;
  char cVar8;
  uint uVar6;
  int iVar9;
  double dVar10;
  undefined4 local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  local_28[0] = DAT_803e305c;
  iVar9 = param_10[9];
  bVar1 = *(byte *)((int)param_10 + 10);
  if (bVar1 == 2) {
    iVar9 = FUN_8013b6f0((double)FLOAT_803e30a8,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,iVar9,param_12,param_13,param_14,param_15,param_16
                        );
    if (iVar9 == 0) {
      param_10[0x15] = param_10[0x15] | 0x10;
      *(undefined *)((int)param_10 + 10) = 3;
      param_10[0x1c0] = FLOAT_803e306c;
      FUN_8000dcdc(param_9,0x13d);
      FUN_8013a778((double)FLOAT_803e31a0,param_9,0xe,0x4000000);
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      iVar4 = iVar9 + 0x18;
      iVar9 = 2;
      uVar5 = FUN_800db36c(iVar4,0xffffffff,2);
      param_10[0x1c3] = uVar5;
      if ((param_10[0x1c3] != 0) &&
         (dVar10 = FUN_80021730((float *)(param_10[9] + 0x18),(float *)(param_10[0x1c3] + 8)),
         (double)FLOAT_803e31a4 < dVar10)) {
        param_10[0x1c3] = 0;
      }
      *(undefined *)((int)param_10 + 10) = 1;
    }
    iVar9 = FUN_8013b6f0((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,iVar9,param_12,param_13,param_14,param_15,param_16
                        );
    if (iVar9 == 0) {
      if (param_10[0x1c3] == 0) {
        param_10[0x15] = param_10[0x15] | 0x10;
        *(undefined *)((int)param_10 + 10) = 3;
        param_10[0x1c0] = FLOAT_803e306c;
        uStack_1c = FUN_80022264(0x28,0x50);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        param_10[0x1c4] = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e30f0);
        FUN_8000dcdc(param_9,0x13d);
        FUN_8013a778((double)FLOAT_803e31a0,param_9,0xe,0x4000000);
      }
      else {
        *(undefined *)((int)param_10 + 10) = 2;
        if (param_10[10] != param_10[0x1c3] + 8) {
          param_10[10] = param_10[0x1c3] + 8;
          param_10[0x15] = param_10[0x15] & 0xfffffbff;
          *(undefined2 *)((int)param_10 + 0xd2) = 0;
        }
      }
    }
    else if (iVar9 == 2) {
      *(undefined *)(param_10 + 2) = 1;
      *(undefined *)((int)param_10 + 10) = 0;
      fVar3 = FLOAT_803e306c;
      param_10[0x1c7] = FLOAT_803e306c;
      param_10[0x1c8] = fVar3;
      param_10[0x15] = param_10[0x15] & 0xffffffef;
      param_10[0x15] = param_10[0x15] & 0xfffeffff;
      param_10[0x15] = param_10[0x15] & 0xfffdffff;
      param_10[0x15] = param_10[0x15] & 0xfffbffff;
      *(undefined *)((int)param_10 + 0xd) = 0xff;
    }
  }
  else if (bVar1 == 4) {
    param_10[0x1c4] = (float)param_10[0x1c4] - FLOAT_803dc074;
    if ((float)param_10[0x1c4] <= FLOAT_803e306c) {
      uStack_1c = FUN_80022264(0x28,0x50);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      param_10[0x1c4] = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e30f0);
      param_10[0x1c4] = (float)param_10[0x1c4] * FLOAT_803e30b4;
      iVar4 = *(int *)(param_9 + 0xb8);
      if (((*(byte *)(iVar4 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
          (bVar7 = FUN_8000b598(param_9,0x10), !bVar7)))) {
        FUN_800394f0(param_9,iVar4 + 0x3a8,0x360,0x500,0xffffffff,0);
      }
    }
    dVar10 = (double)(**(code **)(**(int **)(iVar9 + 0x68) + 0x20))(iVar9,param_9);
    *(float *)(param_9 + 0xc) =
         -(float)((double)(float)param_10[0xb] * dVar10 - (double)(float)param_10[0x1c1]);
    *(float *)(param_9 + 0x14) =
         -(float)((double)(float)param_10[0xc] * dVar10 - (double)(float)param_10[0x1c2]);
    cVar8 = (**(code **)(**(int **)(iVar9 + 0x68) + 0x24))(iVar9);
    if (cVar8 != '\0') {
      FUN_8000dbb0();
      *(char *)*param_10 = *(char *)*param_10 + -4;
      *(undefined *)(param_10 + 2) = 1;
      *(undefined *)((int)param_10 + 10) = 0;
      fVar3 = FLOAT_803e306c;
      param_10[0x1c7] = FLOAT_803e306c;
      param_10[0x1c8] = fVar3;
      param_10[0x15] = param_10[0x15] & 0xffffffef;
      param_10[0x15] = param_10[0x15] & 0xfffeffff;
      param_10[0x15] = param_10[0x15] & 0xfffdffff;
      param_10[0x15] = param_10[0x15] & 0xfffbffff;
      *(undefined *)((int)param_10 + 0xd) = 0xff;
      uVar6 = FUN_80022264(0,1);
      uVar2 = *(ushort *)((int)local_28 + uVar6 * 2);
      iVar9 = *(int *)(param_9 + 0xb8);
      if ((((*(byte *)(iVar9 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)))) &&
         (bVar7 = FUN_8000b598(param_9,0x10), !bVar7)) {
        FUN_800394f0(param_9,iVar9 + 0x3a8,uVar2,0x500,0xffffffff,0);
      }
    }
  }
  else if (bVar1 < 4) {
    param_10[0x1c0] = (float)param_10[0x1c0] + FLOAT_803dc074;
    param_10[0x1c4] = (float)param_10[0x1c4] - FLOAT_803dc074;
    if (FLOAT_803e3188 <= (float)param_10[0x1c0]) {
      *(undefined *)((int)param_10 + 10) = 4;
      param_10[0x1c1] = *(undefined4 *)(param_9 + 0x18);
      param_10[0x1c2] = *(undefined4 *)(param_9 + 0x20);
      iVar9 = param_10[0x1c3];
      if (iVar9 != 0) {
        param_10[0xb] = *(float *)(iVar9 + 8) - *(float *)(param_10[9] + 0x18);
        param_10[0xc] = *(float *)(iVar9 + 0x10) - *(float *)(param_10[9] + 0x20);
        dVar10 = FUN_80293900((double)((float)param_10[0xb] * (float)param_10[0xb] +
                                      (float)param_10[0xc] * (float)param_10[0xc]));
        if ((double)FLOAT_803e306c != dVar10) {
          param_10[0xb] = (float)((double)(float)param_10[0xb] / dVar10);
          param_10[0xc] = (float)((double)(float)param_10[0xc] / dVar10);
        }
      }
    }
  }
  return;
}

