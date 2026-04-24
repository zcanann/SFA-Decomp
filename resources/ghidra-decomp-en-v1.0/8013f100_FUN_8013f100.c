// Function: FUN_8013f100
// Entry: 8013f100
// Size: 2276 bytes

/* WARNING: Removing unreachable block (ram,0x8013f9c0) */

void FUN_8013f100(short *param_1,int *param_2)

{
  bool bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  switch(*(undefined *)((int)param_2 + 10)) {
  case 0:
    param_2[0x1c0] = param_2[9];
    param_2[0x1c1] = (int)FLOAT_803e24ec;
    *(undefined *)((int)param_2 + 10) = 1;
    uVar4 = FUN_800221a0(0x96,300);
    param_2[0x1e9] = (int)(float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e2460)
    ;
  case 1:
    iVar5 = FUN_80179650(param_2[0x1c0]);
    if (iVar5 == 0) {
      iVar5 = FUN_8013b368((double)FLOAT_803e2408,param_1,param_2);
      if (iVar5 == 0) {
        if ((float)param_2[0x1c1] <= FLOAT_803e23dc) {
          FUN_8013a3f0((double)FLOAT_803e243c,param_1,0x10,0x4000000);
          param_2[0x1c2] = (int)((float)param_2[0x1c2] - FLOAT_803db414);
          if ((float)param_2[0x1c2] <= FLOAT_803e23dc) {
            param_2[0x1c1] = (int)FLOAT_803e24ec;
          }
        }
        else {
          if (FLOAT_803e23dc == (float)param_2[0xab]) {
            bVar1 = false;
          }
          else if (FLOAT_803e2410 == (float)param_2[0xac]) {
            bVar1 = true;
          }
          else if ((float)param_2[0xad] - (float)param_2[0xac] <= FLOAT_803e2414) {
            bVar1 = false;
          }
          else {
            bVar1 = true;
          }
          if (bVar1) {
            FUN_8013a3f0((double)FLOAT_803e243c,param_1,8,0);
            param_2[0x1e7] = (int)FLOAT_803e2440;
            param_2[0x20e] = (int)FLOAT_803e23dc;
            FUN_80148bc8(s_in_water_8031d46c);
          }
          else {
            FUN_8013a3f0((double)FLOAT_803e2444,param_1,0,0);
            FUN_80148bc8(s_out_of_water_8031d478);
          }
          param_2[0x1c1] = (int)((float)param_2[0x1c1] - FLOAT_803db414);
          if ((float)param_2[0x1c1] <= FLOAT_803e23dc) {
            if (FLOAT_803e23dc == (float)param_2[0xab]) {
              bVar1 = false;
            }
            else if (FLOAT_803e2410 == (float)param_2[0xac]) {
              bVar1 = true;
            }
            else if ((float)param_2[0xad] - (float)param_2[0xac] <= FLOAT_803e2414) {
              bVar1 = false;
            }
            else {
              bVar1 = true;
            }
            if (bVar1) {
              param_2[0x1c1] = (int)FLOAT_803e24ec;
            }
            else {
              param_2[0x1c2] = (int)FLOAT_803e24f8;
            }
          }
        }
      }
      else if (iVar5 == 1) {
        param_2[0x1e9] = (int)((float)param_2[0x1e9] - FLOAT_803db414);
        if ((float)param_2[0x1e9] <= FLOAT_803e23dc) {
          uVar4 = FUN_800221a0(0x96,300);
          param_2[0x1e9] =
               (int)(float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e2460);
          iVar5 = *(int *)(param_1 + 0x5c);
          if (((*(byte *)(iVar5 + 0x58) >> 6 & 1) == 0) &&
             (((0x2f < param_1[0x50] || (param_1[0x50] < 0x29)) &&
              (iVar3 = FUN_8000b578(param_1,0x10), iVar3 == 0)))) {
            FUN_800393f8(param_1,iVar5 + 0x3a8,0x361,0x500,0xffffffff,0);
          }
        }
      }
      else {
        if (FLOAT_803e23dc == (float)param_2[0xab]) {
          bVar1 = false;
        }
        else if (FLOAT_803e2410 == (float)param_2[0xac]) {
          bVar1 = true;
        }
        else if ((float)param_2[0xad] - (float)param_2[0xac] <= FLOAT_803e2414) {
          bVar1 = false;
        }
        else {
          bVar1 = true;
        }
        if (bVar1) {
          FUN_8013a3f0((double)FLOAT_803e243c,param_1,8,0);
          param_2[0x1e7] = (int)FLOAT_803e2440;
          param_2[0x20e] = (int)FLOAT_803e23dc;
          FUN_80148bc8(s_in_water_8031d46c);
        }
        else {
          FUN_8013a3f0((double)FLOAT_803e2444,param_1,0,0);
          FUN_80148bc8(s_out_of_water_8031d478);
        }
      }
    }
    else {
      iVar5 = FUN_8013b368((double)FLOAT_803e24f0,param_1,param_2);
      if (iVar5 == 0) {
        if (FLOAT_803e23dc == (float)param_2[0xab]) {
          bVar1 = false;
        }
        else if (FLOAT_803e2410 == (float)param_2[0xac]) {
          bVar1 = true;
        }
        else if ((float)param_2[0xad] - (float)param_2[0xac] <= FLOAT_803e2414) {
          bVar1 = false;
        }
        else {
          bVar1 = true;
        }
        if (bVar1) {
          FUN_8013a3f0((double)FLOAT_803e24f4,param_1,0x1c,0x4000000);
        }
        else {
          FUN_8013a3f0((double)FLOAT_803e24f4,param_1,0x11,0x4000000);
        }
        param_2[0x15] = param_2[0x15] | 0x10;
        *(undefined *)((int)param_2 + 10) = 3;
        FUN_80179678(param_2[0x1c0],param_1);
      }
      else if (iVar5 == 2) {
        iVar5 = *(int *)(param_1 + 0x5c);
        if ((((*(byte *)(iVar5 + 0x58) >> 6 & 1) == 0) &&
            ((0x2f < param_1[0x50] || (param_1[0x50] < 0x29)))) &&
           (iVar3 = FUN_8000b578(param_1,0x10), iVar3 == 0)) {
          FUN_800393f8(param_1,iVar5 + 0x3a8,0x35d,0x500,0xffffffff,0);
        }
        *(undefined *)(param_2 + 2) = 1;
        *(undefined *)((int)param_2 + 10) = 0;
        fVar2 = FLOAT_803e23dc;
        param_2[0x1c7] = (int)FLOAT_803e23dc;
        param_2[0x1c8] = (int)fVar2;
        param_2[0x15] = param_2[0x15] & 0xffffffef;
        param_2[0x15] = param_2[0x15] & 0xfffeffff;
        param_2[0x15] = param_2[0x15] & 0xfffdffff;
        param_2[0x15] = param_2[0x15] & 0xfffbffff;
        *(undefined *)((int)param_2 + 0xd) = 0xff;
      }
    }
    break;
  case 2:
    if ((param_2[0x15] & 0x8000000U) != 0) {
      param_2[0x20a] = (int)FLOAT_803e2408;
      iVar5 = *param_2;
      if (*(byte *)(iVar5 + 2) < 0xef) {
        *(byte *)(iVar5 + 2) = *(byte *)(iVar5 + 2) + 1;
      }
      else {
        *(undefined *)(iVar5 + 2) = 0;
      }
      param_2[0x15] = param_2[0x15] & 0xffffffef;
      *(undefined *)((int)param_2 + 10) = 7;
      if (param_2[10] != param_2[9] + 0x18) {
        param_2[10] = param_2[9] + 0x18;
        param_2[0x15] = param_2[0x15] & 0xfffffbff;
        *(undefined2 *)((int)param_2 + 0xd2) = 0;
      }
    }
    break;
  case 3:
    if (FLOAT_803e24a8 <= *(float *)(param_1 + 0x4c)) {
      *(undefined *)((int)param_2 + 10) = 4;
    }
    break;
  case 4:
    if (FLOAT_803e24d0 <= *(float *)(param_1 + 0x4c)) {
      if (param_2[10] != param_2[1] + 0x18) {
        param_2[10] = param_2[1] + 0x18;
        param_2[0x15] = param_2[0x15] & 0xfffffbff;
        *(undefined2 *)((int)param_2 + 0xd2) = 0;
      }
      *(undefined *)((int)param_2 + 10) = 5;
    }
    break;
  case 5:
    iVar5 = FUN_8013b368((double)FLOAT_803e24c8,param_1,param_2);
    if (iVar5 == 0) {
      if (FLOAT_803e23dc == (float)param_2[0xab]) {
        bVar1 = false;
      }
      else if (FLOAT_803e2410 == (float)param_2[0xac]) {
        bVar1 = true;
      }
      else if ((float)param_2[0xad] - (float)param_2[0xac] <= FLOAT_803e2414) {
        bVar1 = false;
      }
      else {
        bVar1 = true;
      }
      if (bVar1) {
        FUN_8013a3f0((double)FLOAT_803e24f4,param_1,0x1d,0x4000000);
      }
      else {
        FUN_8013a3f0((double)FLOAT_803e24f4,param_1,0x13,0x4000000);
      }
      *(undefined *)((int)param_2 + 10) = 6;
    }
    break;
  case 6:
    if (FLOAT_803e24fc <= *(float *)(param_1 + 0x4c)) {
      *(float *)(param_2[0x1c0] + 0x10) = *(float *)(param_2[0x1c0] + 0x10) + FLOAT_803e2488;
      dVar7 = (double)FUN_80294204((double)((FLOAT_803e2454 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*param_1 ^ 0x80000000) -
                                                   DOUBLE_803e2460)) / FLOAT_803e2458));
      dVar7 = -dVar7;
      dVar8 = (double)FUN_80293e80((double)((FLOAT_803e2454 *
                                            (float)((double)CONCAT44(0x43300000,
                                                                     (int)*param_1 ^ 0x80000000) -
                                                   DOUBLE_803e2460)) / FLOAT_803e2458));
      FUN_801796bc(-dVar8,(double)FLOAT_803e23e8,dVar7,param_2[0x1c0],param_1);
      *(undefined *)((int)param_2 + 10) = 2;
    }
    break;
  case 7:
    iVar5 = FUN_8013b368((double)FLOAT_803e2408);
    if (iVar5 != 1) {
      if (FLOAT_803e23dc == (float)param_2[0xab]) {
        bVar1 = false;
      }
      else if (FLOAT_803e2410 == (float)param_2[0xac]) {
        bVar1 = true;
      }
      else if ((float)param_2[0xad] - (float)param_2[0xac] <= FLOAT_803e2414) {
        bVar1 = false;
      }
      else {
        bVar1 = true;
      }
      if (bVar1) {
        FUN_8013a3f0((double)FLOAT_803e243c,param_1,8,0);
        param_2[0x1e7] = (int)FLOAT_803e2440;
        param_2[0x20e] = (int)FLOAT_803e23dc;
        FUN_80148bc8(s_in_water_8031d46c);
      }
      else {
        FUN_8013a3f0((double)FLOAT_803e2444,param_1,0,0);
        FUN_80148bc8(s_out_of_water_8031d478);
      }
      goto LAB_8013f9c0;
    }
    iVar5 = FUN_801793a4(param_2[9]);
    if (iVar5 != 0) {
      param_2[0x1c1] = (int)FLOAT_803e24ec;
      *(undefined *)((int)param_2 + 10) = 1;
    }
  }
  if (((param_2[0x15] & 0x10000U) == 0) ||
     (iVar5 = FUN_8005a10c((double)FLOAT_803e2500,param_1 + 6), iVar5 != 0)) {
    FUN_8017962c(param_2[0x1c0]);
  }
  else {
    FUN_8002cbc4(param_2[9]);
  }
LAB_8013f9c0:
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

