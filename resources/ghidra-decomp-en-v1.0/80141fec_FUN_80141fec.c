// Function: FUN_80141fec
// Entry: 80141fec
// Size: 1336 bytes

/* WARNING: Removing unreachable block (ram,0x8014203c) */

void FUN_80141fec(int param_1,char **param_2)

{
  byte bVar1;
  undefined2 uVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  char *pcVar7;
  double dVar8;
  undefined4 local_28;
  undefined4 local_20;
  uint uStack28;
  
  local_28 = DAT_803e23cc;
  pcVar7 = param_2[9];
  bVar1 = *(byte *)((int)param_2 + 10);
  if (bVar1 == 2) {
    iVar4 = FUN_8013b368((double)FLOAT_803e2418);
    if (iVar4 == 0) {
      param_2[0x15] = (char *)((uint)param_2[0x15] | 0x10);
      *(undefined *)((int)param_2 + 10) = 3;
      param_2[0x1c0] = (char *)FLOAT_803e23dc;
      FUN_8000dcbc(param_1,0x13d);
      FUN_8013a3f0((double)FLOAT_803e2510,param_1,0xe,0x4000000);
    }
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      pcVar7 = (char *)FUN_800db0e0(pcVar7 + 0x18,0xffffffff,2);
      param_2[0x1c3] = pcVar7;
      if ((param_2[0x1c3] != (char *)0x0) &&
         (dVar8 = (double)FUN_8002166c(param_2[9] + 0x18,param_2[0x1c3] + 8),
         (double)FLOAT_803e2514 < dVar8)) {
        param_2[0x1c3] = (char *)0x0;
      }
      *(undefined *)((int)param_2 + 10) = 1;
    }
    iVar4 = FUN_8013b368((double)FLOAT_803e2488,param_1,param_2);
    if (iVar4 == 0) {
      if (param_2[0x1c3] == (char *)0x0) {
        param_2[0x15] = (char *)((uint)param_2[0x15] | 0x10);
        *(undefined *)((int)param_2 + 10) = 3;
        param_2[0x1c0] = (char *)FLOAT_803e23dc;
        uStack28 = FUN_800221a0(0x28,0x50);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        param_2[0x1c4] = (char *)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e2460);
        FUN_8000dcbc(param_1,0x13d);
        FUN_8013a3f0((double)FLOAT_803e2510,param_1,0xe,0x4000000);
      }
      else {
        *(undefined *)((int)param_2 + 10) = 2;
        if (param_2[10] != param_2[0x1c3] + 8) {
          param_2[10] = param_2[0x1c3] + 8;
          param_2[0x15] = (char *)((uint)param_2[0x15] & 0xfffffbff);
          *(undefined2 *)((int)param_2 + 0xd2) = 0;
        }
      }
    }
    else if (iVar4 == 2) {
      *(undefined *)(param_2 + 2) = 1;
      *(undefined *)((int)param_2 + 10) = 0;
      fVar3 = FLOAT_803e23dc;
      param_2[0x1c7] = (char *)FLOAT_803e23dc;
      param_2[0x1c8] = (char *)fVar3;
      param_2[0x15] = (char *)((uint)param_2[0x15] & 0xffffffef);
      param_2[0x15] = (char *)((uint)param_2[0x15] & 0xfffeffff);
      param_2[0x15] = (char *)((uint)param_2[0x15] & 0xfffdffff);
      param_2[0x15] = (char *)((uint)param_2[0x15] & 0xfffbffff);
      *(undefined *)((int)param_2 + 0xd) = 0xff;
    }
  }
  else if (bVar1 == 4) {
    param_2[0x1c4] = (char *)((float)param_2[0x1c4] - FLOAT_803db414);
    if ((float)param_2[0x1c4] <= FLOAT_803e23dc) {
      uStack28 = FUN_800221a0(0x28,0x50);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      param_2[0x1c4] = (char *)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e2460);
      param_2[0x1c4] = (char *)((float)param_2[0x1c4] * FLOAT_803e2424);
      iVar4 = *(int *)(param_1 + 0xb8);
      if (((*(byte *)(iVar4 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
          (iVar5 = FUN_8000b578(param_1,0x10), iVar5 == 0)))) {
        FUN_800393f8(param_1,iVar4 + 0x3a8,0x360,0x500,0xffffffff,0);
      }
    }
    dVar8 = (double)(**(code **)(**(int **)(pcVar7 + 0x68) + 0x20))(pcVar7,param_1);
    *(float *)(param_1 + 0xc) =
         -(float)((double)(float)param_2[0xb] * dVar8 - (double)(float)param_2[0x1c1]);
    *(float *)(param_1 + 0x14) =
         -(float)((double)(float)param_2[0xc] * dVar8 - (double)(float)param_2[0x1c2]);
    cVar6 = (**(code **)(**(int **)(pcVar7 + 0x68) + 0x24))(pcVar7);
    if (cVar6 != '\0') {
      FUN_8000db90(param_1,0x13d);
      **param_2 = **param_2 + -4;
      *(undefined *)(param_2 + 2) = 1;
      *(undefined *)((int)param_2 + 10) = 0;
      fVar3 = FLOAT_803e23dc;
      param_2[0x1c7] = (char *)FLOAT_803e23dc;
      param_2[0x1c8] = (char *)fVar3;
      param_2[0x15] = (char *)((uint)param_2[0x15] & 0xffffffef);
      param_2[0x15] = (char *)((uint)param_2[0x15] & 0xfffeffff);
      param_2[0x15] = (char *)((uint)param_2[0x15] & 0xfffdffff);
      param_2[0x15] = (char *)((uint)param_2[0x15] & 0xfffbffff);
      *(undefined *)((int)param_2 + 0xd) = 0xff;
      iVar4 = FUN_800221a0(0,1);
      uVar2 = *(undefined2 *)((int)&local_28 + iVar4 * 2);
      iVar4 = *(int *)(param_1 + 0xb8);
      if ((((*(byte *)(iVar4 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
         (iVar5 = FUN_8000b578(param_1,0x10), iVar5 == 0)) {
        FUN_800393f8(param_1,iVar4 + 0x3a8,uVar2,0x500,0xffffffff,0);
      }
    }
  }
  else if (bVar1 < 4) {
    param_2[0x1c0] = (char *)((float)param_2[0x1c0] + FLOAT_803db414);
    param_2[0x1c4] = (char *)((float)param_2[0x1c4] - FLOAT_803db414);
    if (FLOAT_803e24f8 <= (float)param_2[0x1c0]) {
      *(undefined *)((int)param_2 + 10) = 4;
      param_2[0x1c1] = *(char **)(param_1 + 0x18);
      param_2[0x1c2] = *(char **)(param_1 + 0x20);
      pcVar7 = param_2[0x1c3];
      if (pcVar7 != (char *)0x0) {
        param_2[0xb] = (char *)(*(float *)(pcVar7 + 8) - *(float *)(param_2[9] + 0x18));
        param_2[0xc] = (char *)(*(float *)(pcVar7 + 0x10) - *(float *)(param_2[9] + 0x20));
        dVar8 = (double)FUN_802931a0((double)((float)param_2[0xb] * (float)param_2[0xb] +
                                             (float)param_2[0xc] * (float)param_2[0xc]));
        if ((double)FLOAT_803e23dc != dVar8) {
          param_2[0xb] = (char *)(float)((double)(float)param_2[0xb] / dVar8);
          param_2[0xc] = (char *)(float)((double)(float)param_2[0xc] / dVar8);
        }
      }
    }
  }
  return;
}

