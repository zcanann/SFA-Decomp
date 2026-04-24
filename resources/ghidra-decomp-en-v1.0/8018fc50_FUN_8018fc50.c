// Function: FUN_8018fc50
// Entry: 8018fc50
// Size: 392 bytes

/* WARNING: Removing unreachable block (ram,0x8018fdb4) */

void FUN_8018fc50(int param_1)

{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  undefined4 uVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  pfVar7 = *(float **)(param_1 + 0xb8);
  iVar5 = FUN_8002b9ec();
  if ((iVar5 != 0) &&
     (((*(short *)((int)pfVar7 + 0xe) == -1 || (iVar6 = FUN_8001ffb4(), iVar6 != 0)) &&
      (*(short *)((int)pfVar7 + 0x12) == 0)))) {
    iVar6 = FUN_8001ffb4((int)*(short *)(pfVar7 + 4));
    if (iVar6 != 0) {
      *(undefined2 *)((int)pfVar7 + 0x12) = 1;
    }
    sVar1 = *(short *)(pfVar7 + 3);
    if ((-1 < sVar1) || ((-1 >= sVar1 && (*(int *)(param_1 + 0xf4) < 1)))) {
      fVar2 = *(float *)(param_1 + 0x18) - *(float *)(iVar5 + 0x18);
      fVar3 = *(float *)(param_1 + 0x1c) - *(float *)(iVar5 + 0x1c);
      fVar4 = *(float *)(param_1 + 0x20) - *(float *)(iVar5 + 0x20);
      if (sVar1 == 0) {
        *(undefined2 *)((int)pfVar7 + 0x12) = 1;
      }
      dVar9 = (double)FUN_802931a0((double)(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3));
      dVar10 = (double)*pfVar7;
      if ((dVar9 <= dVar10) || ((double)FLOAT_803e3e6c == dVar10)) {
        if ((3 < *(byte *)(pfVar7 + 2)) &&
           ((dVar10 < (double)pfVar7[1] && ((double)FLOAT_803e3e6c != dVar10)))) {
          FUN_8018f148(param_1,0x23);
        }
        FUN_8018f2d8(param_1);
      }
      *(int *)(param_1 + 0xf4) = -(int)*(short *)(pfVar7 + 3);
      pfVar7[1] = (float)dVar9;
    }
    else if ((sVar1 < 0) && (0 < *(int *)(param_1 + 0xf4))) {
      *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803db410;
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  return;
}

