// Function: FUN_8010dff0
// Entry: 8010dff0
// Size: 1316 bytes

void FUN_8010dff0(int param_1,undefined4 param_2,float *param_3)

{
  float fVar1;
  short sVar2;
  float fVar3;
  uint uVar4;
  uint uVar5;
  short sVar6;
  float *pfVar7;
  int iVar8;
  int iVar9;
  float fVar10;
  undefined auStack152 [4];
  undefined auStack148 [4];
  undefined auStack144 [4];
  undefined auStack140 [124];
  
  fVar10 = 0.0;
  if (DAT_803dd584 == (float *)0x0) {
    DAT_803dd584 = (float *)FUN_80023cc8(0x4c,0xf,0);
  }
  if (param_3 == (float *)0x0) {
    iVar8 = FUN_80080234();
    fVar3 = FLOAT_803e19e8;
    if (iVar8 == 0) {
      *DAT_803dd584 = FLOAT_803e19e8;
      DAT_803dd584[1] = fVar3;
      DAT_803dd584[2] = fVar3;
    }
    fVar3 = FLOAT_803e19e8;
    pfVar7 = *(float **)(iVar8 + 0x74);
    if (pfVar7 == (float *)0x0) {
      *DAT_803dd584 = FLOAT_803e19e8;
      DAT_803dd584[1] = fVar3;
      DAT_803dd584[2] = fVar3;
    }
    *DAT_803dd584 = *pfVar7;
    DAT_803dd584[1] = pfVar7[1];
    DAT_803dd584[2] = pfVar7[2];
  }
  else {
    *DAT_803dd584 = *param_3;
    DAT_803dd584[1] = param_3[1];
    DAT_803dd584[2] = param_3[2];
    fVar10 = (float)(uint)*(byte *)(param_3 + 3);
  }
  if (fVar10 == 5.605194e-45) {
    fVar10 = (float)FUN_800221a0(0,3);
  }
  *(undefined2 *)(DAT_803dd584 + 8) = 0;
  DAT_803dd584[7] = fVar10;
  DAT_803dd584[5] = FLOAT_803e19e8;
  fVar3 = FLOAT_803e19ec;
  DAT_803dd584[0xc] = FLOAT_803e19ec;
  DAT_803dd584[0xe] = FLOAT_803e19dc;
  DAT_803dd584[0xf] = FLOAT_803e19f0;
  fVar1 = FLOAT_803e19f4;
  DAT_803dd584[0x11] = FLOAT_803e19f4;
  DAT_803dd584[0x12] = fVar1;
  DAT_803dd584[0x10] = fVar3;
  fVar3 = (float)FUN_800221a0(0x2000,0x2c00);
  DAT_803dd584[6] = fVar3;
  switch(fVar10) {
  case 0.0:
    DAT_803dd584[4] = FLOAT_803e19f8;
    break;
  case 1.401298e-45:
    DAT_803dd584[4] = FLOAT_803e19fc;
    break;
  case 2.802597e-45:
    DAT_803dd584[4] = FLOAT_803e1a00;
    break;
  case 4.203895e-45:
    DAT_803dd584[4] = FLOAT_803db9c0;
    fVar3 = (float)FUN_800221a0(0xf00,0x1f00);
    DAT_803dd584[6] = fVar3;
    DAT_803dd584[0xe] = FLOAT_803e19e8;
    break;
  default:
    DAT_803dd584[4] = FLOAT_803e19f8;
    break;
  case 7.006492e-45:
    DAT_803dd584[4] = FLOAT_803e1a04;
    break;
  case 8.407791e-45:
    DAT_803dd584[0xc] = FLOAT_803db9a8;
    DAT_803dd584[0xe] = FLOAT_803db9ac;
    DAT_803dd584[0x11] = FLOAT_803dd580;
    DAT_803dd584[0xf] = FLOAT_803db9b0;
    DAT_803dd584[6] = DAT_803db9bc;
    DAT_803dd584[0x12] = FLOAT_803db9b4;
    DAT_803dd584[4] = FLOAT_803db9b8;
    *(undefined2 *)((int)DAT_803dd584 + 0x22) = 0xb6;
    DAT_803dd584[0x10] = FLOAT_803e19e8;
    break;
  case 9.809089e-45:
    DAT_803dd584[4] = FLOAT_803e19f8;
    DAT_803dd584[0xc] = FLOAT_803e1a08;
    DAT_803dd584[0x11] = FLOAT_803e1a0c;
    DAT_803dd584[0x12] = FLOAT_803e1a10;
    DAT_803dd584[0xf] = FLOAT_803e1a14;
    fVar3 = (float)FUN_800221a0(0x1800,0x1c00);
    DAT_803dd584[6] = fVar3;
    break;
  case 1.121039e-44:
    DAT_803dd584[4] = FLOAT_803e1a18;
    DAT_803dd584[0xe] = FLOAT_803e1a1c;
  }
  uVar4 = FUN_800217c0((double)(*(float *)(param_1 + 0x18) - *DAT_803dd584),
                       (double)(*(float *)(param_1 + 0x20) - DAT_803dd584[2]));
  uVar5 = FUN_800217c0((double)(*(float *)(*(int *)(param_1 + 0xa4) + 0x18) - *DAT_803dd584),
                       (double)(*(float *)(*(int *)(param_1 + 0xa4) + 0x20) - DAT_803dd584[2]));
  uVar5 = uVar5 & 0xffff;
  fVar3 = DAT_803dd584[6];
  iVar8 = (uVar5 + (int)fVar3) - (uVar4 & 0xffff);
  if (0x8000 < iVar8) {
    iVar8 = iVar8 + -0xffff;
  }
  if (iVar8 < -0x8000) {
    iVar8 = iVar8 + 0xffff;
  }
  iVar9 = (uVar5 - (int)fVar3) - (uVar4 & 0xffff);
  if (0x8000 < iVar9) {
    iVar9 = iVar9 + -0xffff;
  }
  if (iVar9 < -0x8000) {
    iVar9 = iVar9 + 0xffff;
  }
  if (iVar8 < 0) {
    iVar8 = -iVar8;
  }
  if (iVar9 < 0) {
    iVar9 = -iVar9;
  }
  if (iVar9 < iVar8) {
    DAT_803dd584[6] = (float)-(int)fVar3;
    *(undefined2 *)((int)DAT_803dd584 + 0x22) = 0xff80;
  }
  if (((fVar10 != 8.407791e-45) && (fVar10 != 9.809089e-45)) && (iVar8 = FUN_80080234(), iVar8 != 0)
     ) {
    sVar2 = (short)uVar5 - **(short **)(param_1 + 0xa4);
    if (0x8000 < sVar2) {
      sVar2 = sVar2 + 1;
    }
    if (sVar2 < -0x8000) {
      sVar2 = sVar2 + -1;
    }
    sVar6 = FUN_800385e8(*(short **)(param_1 + 0xa4),iVar8,0);
    iVar8 = (int)sVar2 - ((int)sVar6 & 0xffffU);
    if (0x8000 < iVar8) {
      iVar8 = iVar8 + -0xffff;
    }
    if (iVar8 < -0x8000) {
      iVar8 = iVar8 + 0xffff;
    }
    if (((0x1000 < iVar8) && (0 < (int)DAT_803dd584[6])) ||
       ((iVar8 < -0x1000 && ((int)DAT_803dd584[6] < 0)))) {
      DAT_803dd584[6] = (float)-(int)DAT_803dd584[6];
    }
  }
  FUN_8010db7c(*(undefined4 *)(param_1 + 0xa4),auStack152,auStack148,auStack144);
  FUN_80103524((double)FLOAT_803e1a20,param_1 + 0x18,auStack152,DAT_803dd584 + 9,auStack140,3,1,1);
  return;
}

