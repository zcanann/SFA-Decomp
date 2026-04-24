// Function: FUN_801c053c
// Entry: 801c053c
// Size: 1136 bytes

/* WARNING: Removing unreachable block (ram,0x801c0984) */

void FUN_801c053c(int param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  byte *pbVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  pbVar5 = *(byte **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (*(short *)(iVar4 + 0x20) == -1) {
    *(float *)(pbVar5 + 0xc) = *(float *)(pbVar5 + 0xc) - FLOAT_803db414;
    if (*(float *)(pbVar5 + 0xc) <= FLOAT_803e4da0) {
      uVar2 = FUN_800221a0(0xf0,0x1e0);
      *(float *)(pbVar5 + 0xc) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e4dc8);
      *pbVar5 = *pbVar5 | 1;
      *(undefined4 *)(pbVar5 + 4) = *(undefined4 *)(&DAT_80325d68 + (uint)pbVar5[1] * 4);
      *(undefined4 *)(pbVar5 + 8) = *(undefined4 *)(pbVar5 + 4);
      pbVar5[1] = pbVar5[1] + 1;
      if (9 < pbVar5[1]) {
        pbVar5[1] = 0;
      }
    }
  }
  else {
    iVar1 = FUN_8001ffb4();
    if (iVar1 != 0) {
      FUN_800200e8((int)*(short *)(iVar4 + 0x20),0);
      *pbVar5 = *pbVar5 | 1;
      *(undefined4 *)(pbVar5 + 4) = *(undefined4 *)(&DAT_80325d68 + (uint)pbVar5[1] * 4);
      *(undefined4 *)(pbVar5 + 8) = *(undefined4 *)(pbVar5 + 4);
      pbVar5[1] = pbVar5[1] + 1;
      if (9 < pbVar5[1]) {
        pbVar5[1] = 0;
      }
    }
  }
  if (FLOAT_803e4da0 < *(float *)(pbVar5 + 4)) {
    if ((*pbVar5 & 1) != 0) {
      *pbVar5 = *pbVar5 & 0xfe;
      FUN_80035df4(param_1,9,1,0);
      FUN_80035974(param_1,0xf);
      FUN_80035f20(param_1);
      if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
        iVar1 = 0;
        do {
          if (*(short *)(iVar4 + 0x1a) == 0) {
            (**(code **)(*DAT_803dca88 + 8))(param_1,0x4cc,0,2,0xffffffff,0);
          }
          else {
            (**(code **)(*DAT_803dca88 + 8))(param_1,0x4c9,0,2,0xffffffff,0);
          }
          iVar1 = iVar1 + 1;
        } while (iVar1 < 0x32);
      }
      iVar1 = FUN_8002b9ec();
      if ((iVar1 != 0) && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) {
        dVar7 = (double)FUN_80021704(param_1 + 0x18,iVar1 + 0x18);
        if (dVar7 <= (double)FLOAT_803e4da4) {
          dVar7 = (double)(FLOAT_803e4da8 - (float)(dVar7 / (double)FLOAT_803e4da4));
          FUN_8000e650((double)(float)((double)FLOAT_803e4dac * dVar7),(double)FLOAT_803e4dac,
                       (double)FLOAT_803e4db0);
          FUN_80014aa0((double)(float)((double)FLOAT_803e4db4 * dVar7));
        }
      }
      if (*(int *)(pbVar5 + 0x10) == 0) {
        uVar3 = FUN_8001f4c8(param_1,1);
        *(undefined4 *)(pbVar5 + 0x10) = uVar3;
        if (*(int *)(pbVar5 + 0x10) != 0) {
          FUN_8001db2c(*(int *)(pbVar5 + 0x10),2);
          FUN_8001db14(*(undefined4 *)(pbVar5 + 0x10),1);
          if (*(short *)(iVar4 + 0x1a) == 0) {
            FUN_8001daf0(*(undefined4 *)(pbVar5 + 0x10),0x7f,0xff,0,0);
          }
          else {
            FUN_8001daf0(*(undefined4 *)(pbVar5 + 0x10),0xff,0x7f,0,0);
          }
          FUN_8001dc38((double)FLOAT_803e4db8,(double)FLOAT_803e4dbc,*(undefined4 *)(pbVar5 + 0x10))
          ;
          FUN_8001db6c((double)FLOAT_803e4da0,*(undefined4 *)(pbVar5 + 0x10),1);
          FUN_8001db6c((double)(*(float *)(pbVar5 + 4) / FLOAT_803e4dc0),
                       *(undefined4 *)(pbVar5 + 0x10),0);
        }
      }
      FUN_8000bb18(param_1,0x188);
    }
    *(float *)(pbVar5 + 4) = *(float *)(pbVar5 + 4) - FLOAT_803db414;
    if (FLOAT_803e4da0 < *(float *)(pbVar5 + 4)) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x4ca,0,2,0xffffffff,0);
      if (*(short *)(iVar4 + 0x1a) == 0) {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x4cd,0,2,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x4cb,0,2,0xffffffff,0);
      }
    }
    else {
      *(float *)(pbVar5 + 4) = FLOAT_803e4da0;
      if (*(int *)(pbVar5 + 0x10) != 0) {
        FUN_8001f384();
        *(undefined4 *)(pbVar5 + 0x10) = 0;
      }
      FUN_80035df4(param_1,0,0,0);
      FUN_80035974(param_1,0);
      FUN_80035f00(param_1);
    }
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return;
}

