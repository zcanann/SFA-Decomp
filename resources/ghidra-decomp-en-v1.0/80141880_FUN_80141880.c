// Function: FUN_80141880
// Entry: 80141880
// Size: 1900 bytes

void FUN_80141880(int param_1,char **param_2)

{
  undefined2 uVar1;
  bool bVar2;
  float fVar3;
  char *pcVar4;
  uint uVar5;
  short sVar9;
  char cVar10;
  char *pcVar6;
  int iVar7;
  int iVar8;
  int iVar11;
  int iVar12;
  double dVar13;
  double dVar14;
  undefined4 local_28;
  undefined4 local_20;
  uint uStack28;
  
  local_28 = DAT_803e23d0;
  switch(*(undefined *)((int)param_2 + 10)) {
  case 0:
    pcVar6 = (char *)FUN_800dafdc(param_2[10],0xffffffff,2);
    pcVar4 = (char *)(**(code **)(*DAT_803dca9c + 0x1c))(*(undefined4 *)(pcVar6 + 0x1c));
    param_2[0x1c2] = pcVar4;
    param_2[0x1c0] = pcVar6;
    pcVar6 = (char *)(**(code **)(*DAT_803dca9c + 0x1c))(*(undefined4 *)(pcVar6 + 0x20));
    param_2[0x1c1] = pcVar6;
    if (param_2[0x1c1][3] != '\0') {
      param_2[0x1c1] = (char *)((uint)param_2[0x1c1] ^ (uint)param_2[0x1c2]);
      param_2[0x1c2] = (char *)((uint)param_2[0x1c2] ^ (uint)param_2[0x1c1]);
      param_2[0x1c1] = (char *)((uint)param_2[0x1c1] ^ (uint)param_2[0x1c2]);
    }
    if (param_2[10] != param_2[0x1c2] + 8) {
      param_2[10] = param_2[0x1c2] + 8;
      param_2[0x15] = (char *)((uint)param_2[0x15] & 0xfffffbff);
      *(undefined2 *)((int)param_2 + 0xd2) = 0;
    }
    *(undefined *)((int)param_2 + 10) = 1;
  case 1:
    FUN_80148bc8(s_DIGTUNNEL_FINDING_8031daa0);
    FUN_8013b368((double)FLOAT_803e2488,param_1,param_2);
    uVar5 = FUN_800dbcfc(param_1 + 0x18,0);
    if ((byte)param_2[0x1c2][3] == uVar5) {
      *(undefined *)((int)param_2 + 9) = 1;
      *(undefined *)((int)param_2 + 10) = 2;
    }
    break;
  case 2:
    FUN_80148bc8(s_DIGTUNNEL_GOINGTOSTART_8031dab4);
    pcVar6 = param_2[0x1c0];
    FUN_8013d5a4((double)FLOAT_803e2488,param_1,param_2,pcVar6 + 8,1);
    iVar7 = FUN_80139a8c(param_1,pcVar6 + 8);
    if (iVar7 == 0) {
      param_2[0x15] = (char *)((uint)param_2[0x15] | 0x2010);
      *(undefined *)((int)param_2 + 10) = 3;
    }
    else {
      iVar7 = FUN_800dbcfc(param_1 + 0x18,0);
      if (iVar7 == 0) {
        param_2[0x15] = (char *)((uint)param_2[0x15] | 0x2010);
      }
    }
    break;
  case 3:
    FUN_8013a3f0((double)FLOAT_803e2510,param_1,0xe,0x4000000);
    param_2[0xb] = (char *)(*(float *)(param_2[0x1c1] + 8) - *(float *)(param_2[0x1c0] + 8));
    param_2[0xc] = (char *)(*(float *)(param_2[0x1c1] + 0x10) - *(float *)(param_2[0x1c0] + 0x10));
    FUN_8000dcbc(param_1,0x13d);
    uStack28 = FUN_800221a0(0x14,0xb4);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    param_2[0x1c3] = (char *)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e2460);
    *(undefined *)((int)param_2 + 10) = 4;
  case 4:
    FUN_80148bc8(s_DIGTUNNEL_DIGGING_8031dacc);
    param_2[0x1c3] = (char *)((float)param_2[0x1c3] - FLOAT_803db414);
    if ((float)param_2[0x1c3] <= FLOAT_803e23dc) {
      uStack28 = FUN_800221a0(0x14,0xb4);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      param_2[0x1c3] = (char *)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e2460);
      param_2[0x1c3] = (char *)((float)param_2[0x1c3] * FLOAT_803e2424);
      iVar7 = *(int *)(param_1 + 0xb8);
      if (((*(byte *)(iVar7 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
          (iVar8 = FUN_8000b578(param_1,0x10), iVar8 == 0)))) {
        FUN_800393f8(param_1,iVar7 + 0x3a8,0x360,0x500,0xffffffff,0);
      }
    }
    dVar13 = (double)(**(code **)(**(int **)(param_2[9] + 0x68) + 0x20))(param_2[9],param_1);
    *(float *)(param_1 + 0xc) =
         (float)((double)(float)param_2[0xb] * dVar13 + (double)*(float *)(param_2[0x1c0] + 8));
    *(float *)(param_1 + 0x14) =
         (float)((double)(float)param_2[0xc] * dVar13 + (double)*(float *)(param_2[0x1c0] + 0x10));
    dVar14 = (double)*(float *)(*(int *)(param_1 + 0xb8) + 0x2c);
    dVar13 = (double)*(float *)(*(int *)(param_1 + 0xb8) + 0x30);
    if (FLOAT_803e23ec < (float)(dVar14 * dVar14) + (float)(dVar13 * dVar13)) {
      sVar9 = FUN_800217c0(-dVar14,-dVar13);
      FUN_80139930(param_1,(int)sVar9);
    }
    cVar10 = (**(code **)(**(int **)(param_2[9] + 0x68) + 0x24))();
    if (cVar10 != '\0') {
      iVar8 = 0;
      iVar7 = 0;
      iVar12 = 4;
      do {
        iVar11 = *(int *)(param_2[0x1c1] + iVar7 + 0x1c);
        if ((-1 < iVar11) && (iVar11 != *(int *)(param_2[0x1c0] + 0x14))) {
          param_2[0x1c0] = param_2[0x1c1];
          pcVar6 = (char *)(**(code **)(*DAT_803dca9c + 0x1c))
                                     (*(undefined4 *)(param_2[0x1c1] + iVar8 * 4 + 0x1c));
          param_2[0x1c1] = pcVar6;
          break;
        }
        iVar7 = iVar7 + 4;
        iVar8 = iVar8 + 1;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
      **param_2 = **param_2 + -4;
      FUN_8000db90(param_1,0x13d);
      *(undefined *)((int)param_2 + 10) = 5;
      iVar7 = FUN_800221a0(0,1);
      uVar1 = *(undefined2 *)((int)&local_28 + iVar7 * 2);
      iVar7 = *(int *)(param_1 + 0xb8);
      if ((((*(byte *)(iVar7 + 0x58) >> 6 & 1) == 0) &&
          ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
         (iVar8 = FUN_8000b578(param_1,0x10), iVar8 == 0)) {
        FUN_800393f8(param_1,iVar7 + 0x3a8,uVar1,0x500,0xffffffff,0);
      }
    }
    break;
  case 5:
    FUN_80021690(param_1 + 0x18,param_2[0x1c1] + 8);
    FUN_80148bc8(s_DIGTUNNEL_TOEND1__f_8031dae0);
    pcVar6 = param_2[0x1c1];
    FUN_8013d5a4((double)FLOAT_803e2488,param_1,param_2,pcVar6 + 8,1);
    iVar7 = FUN_80139a8c(param_1,pcVar6 + 8);
    if (iVar7 == 0) {
      iVar8 = 0;
      iVar7 = 0;
      iVar12 = 4;
      do {
        iVar11 = *(int *)(param_2[0x1c1] + iVar7 + 0x1c);
        if ((-1 < iVar11) && (iVar11 != *(int *)(param_2[0x1c0] + 0x14))) {
          param_2[0x1c0] = param_2[0x1c1];
          pcVar6 = (char *)(**(code **)(*DAT_803dca9c + 0x1c))
                                     (*(undefined4 *)(param_2[0x1c1] + iVar8 * 4 + 0x1c));
          param_2[0x1c1] = pcVar6;
          break;
        }
        iVar7 = iVar7 + 4;
        iVar8 = iVar8 + 1;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
      *(undefined *)((int)param_2 + 10) = 6;
    }
    break;
  case 6:
    FUN_80148bc8(s_DIGTUNNEL_TOEND2_8031daf8);
    pcVar6 = param_2[0x1c1];
    FUN_8013d5a4((double)FLOAT_803e2488,param_1,param_2,pcVar6 + 8,1);
    iVar7 = FUN_80139a8c(param_1,pcVar6 + 8);
    if (iVar7 == 0) {
      if (FLOAT_803e23dc == (float)param_2[0xab]) {
        bVar2 = false;
      }
      else if (FLOAT_803e2410 == (float)param_2[0xac]) {
        bVar2 = true;
      }
      else if ((float)param_2[0xad] - (float)param_2[0xac] <= FLOAT_803e2414) {
        bVar2 = false;
      }
      else {
        bVar2 = true;
      }
      if (bVar2) {
        FUN_8013a3f0((double)FLOAT_803e243c,param_1,8,0);
        param_2[0x1e7] = (char *)FLOAT_803e2440;
        param_2[0x20e] = (char *)FLOAT_803e23dc;
        FUN_80148bc8(s_in_water_8031d46c);
      }
      else {
        FUN_8013a3f0((double)FLOAT_803e2444,param_1,0,0);
        FUN_80148bc8(s_out_of_water_8031d478);
      }
      param_2[0x15] = (char *)((uint)param_2[0x15] & 0xffffdfef);
      *(undefined *)((int)param_2 + 10) = 7;
    }
    break;
  case 7:
    FUN_80148bc8(s_DIGTUNNEL_WAIT_8031db0c);
    iVar7 = FUN_800dbcfc(param_2[1] + 0x18,0);
    iVar8 = FUN_800dbcfc(param_1 + 0x18,0);
    if (iVar8 == iVar7) {
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
  return;
}

