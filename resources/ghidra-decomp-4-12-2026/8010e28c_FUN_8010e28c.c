// Function: FUN_8010e28c
// Entry: 8010e28c
// Size: 1316 bytes

void FUN_8010e28c(int param_1,undefined4 param_2,undefined4 *param_3)

{
  float fVar1;
  short sVar2;
  float fVar3;
  uint uVar4;
  uint uVar5;
  float *pfVar6;
  int iVar7;
  int iVar8;
  float fVar9;
  float fStack_98;
  float fStack_94;
  float fStack_90;
  undefined auStack_8c [124];
  
  fVar9 = 0.0;
  if (DAT_803de1fc == (float *)0x0) {
    DAT_803de1fc = (float *)FUN_80023d8c(0x4c,0xf);
  }
  if (param_3 == (undefined4 *)0x0) {
    iVar7 = FUN_800804c0();
    fVar3 = FLOAT_803e2668;
    if (iVar7 == 0) {
      *DAT_803de1fc = FLOAT_803e2668;
      DAT_803de1fc[1] = fVar3;
      DAT_803de1fc[2] = fVar3;
    }
    fVar3 = FLOAT_803e2668;
    pfVar6 = *(float **)(iVar7 + 0x74);
    if (pfVar6 == (float *)0x0) {
      *DAT_803de1fc = FLOAT_803e2668;
      DAT_803de1fc[1] = fVar3;
      DAT_803de1fc[2] = fVar3;
    }
    *DAT_803de1fc = *pfVar6;
    DAT_803de1fc[1] = pfVar6[1];
    DAT_803de1fc[2] = pfVar6[2];
  }
  else {
    *DAT_803de1fc = (float)*param_3;
    DAT_803de1fc[1] = (float)param_3[1];
    DAT_803de1fc[2] = (float)param_3[2];
    fVar9 = (float)(uint)*(byte *)(param_3 + 3);
  }
  if (fVar9 == 5.60519e-45) {
    fVar9 = (float)FUN_80022264(0,3);
  }
  *(undefined2 *)(DAT_803de1fc + 8) = 0;
  DAT_803de1fc[7] = fVar9;
  DAT_803de1fc[5] = FLOAT_803e2668;
  fVar3 = FLOAT_803e266c;
  DAT_803de1fc[0xc] = FLOAT_803e266c;
  DAT_803de1fc[0xe] = FLOAT_803e265c;
  DAT_803de1fc[0xf] = FLOAT_803e2670;
  fVar1 = FLOAT_803e2674;
  DAT_803de1fc[0x11] = FLOAT_803e2674;
  DAT_803de1fc[0x12] = fVar1;
  DAT_803de1fc[0x10] = fVar3;
  fVar3 = (float)FUN_80022264(0x2000,0x2c00);
  DAT_803de1fc[6] = fVar3;
  switch(fVar9) {
  case 0.0:
    DAT_803de1fc[4] = FLOAT_803e2678;
    break;
  case 1.4013e-45:
    DAT_803de1fc[4] = FLOAT_803e267c;
    break;
  case 2.8026e-45:
    DAT_803de1fc[4] = FLOAT_803e2680;
    break;
  case 4.2039e-45:
    DAT_803de1fc[4] = FLOAT_803dc620;
    fVar3 = (float)FUN_80022264(0xf00,0x1f00);
    DAT_803de1fc[6] = fVar3;
    DAT_803de1fc[0xe] = FLOAT_803e2668;
    break;
  default:
    DAT_803de1fc[4] = FLOAT_803e2678;
    break;
  case 7.00649e-45:
    DAT_803de1fc[4] = FLOAT_803e2684;
    break;
  case 8.40779e-45:
    DAT_803de1fc[0xc] = FLOAT_803dc608;
    DAT_803de1fc[0xe] = FLOAT_803dc60c;
    DAT_803de1fc[0x11] = FLOAT_803de1f8;
    DAT_803de1fc[0xf] = FLOAT_803dc610;
    DAT_803de1fc[6] = DAT_803dc61c;
    DAT_803de1fc[0x12] = FLOAT_803dc614;
    DAT_803de1fc[4] = FLOAT_803dc618;
    *(undefined2 *)((int)DAT_803de1fc + 0x22) = 0xb6;
    DAT_803de1fc[0x10] = FLOAT_803e2668;
    break;
  case 9.80909e-45:
    DAT_803de1fc[4] = FLOAT_803e2678;
    DAT_803de1fc[0xc] = FLOAT_803e2688;
    DAT_803de1fc[0x11] = FLOAT_803e268c;
    DAT_803de1fc[0x12] = FLOAT_803e2690;
    DAT_803de1fc[0xf] = FLOAT_803e2694;
    fVar3 = (float)FUN_80022264(0x1800,0x1c00);
    DAT_803de1fc[6] = fVar3;
    break;
  case 1.12104e-44:
    DAT_803de1fc[4] = FLOAT_803e2698;
    DAT_803de1fc[0xe] = FLOAT_803e269c;
  }
  uVar4 = FUN_80021884();
  uVar5 = FUN_80021884();
  fVar3 = DAT_803de1fc[6];
  iVar7 = ((uVar5 & 0xffff) + (int)fVar3) - (uVar4 & 0xffff);
  if (0x8000 < iVar7) {
    iVar7 = iVar7 + -0xffff;
  }
  if (iVar7 < -0x8000) {
    iVar7 = iVar7 + 0xffff;
  }
  iVar8 = ((uVar5 & 0xffff) - (int)fVar3) - (uVar4 & 0xffff);
  if (0x8000 < iVar8) {
    iVar8 = iVar8 + -0xffff;
  }
  if (iVar8 < -0x8000) {
    iVar8 = iVar8 + 0xffff;
  }
  if (iVar7 < 0) {
    iVar7 = -iVar7;
  }
  if (iVar8 < 0) {
    iVar8 = -iVar8;
  }
  if (iVar8 < iVar7) {
    DAT_803de1fc[6] = (float)-(int)fVar3;
    *(undefined2 *)((int)DAT_803de1fc + 0x22) = 0xff80;
  }
  if (((fVar9 != 8.40779e-45) && (fVar9 != 9.80909e-45)) && (iVar7 = FUN_800804c0(), iVar7 != 0)) {
    sVar2 = (short)uVar5 - **(ushort **)(param_1 + 0xa4);
    if (0x8000 < sVar2) {
      sVar2 = sVar2 + 1;
    }
    if (sVar2 < -0x8000) {
      sVar2 = sVar2 + -1;
    }
    uVar4 = FUN_800386e0(*(ushort **)(param_1 + 0xa4),iVar7,(float *)0x0);
    iVar7 = (int)sVar2 - (uVar4 & 0xffff);
    if (0x8000 < iVar7) {
      iVar7 = iVar7 + -0xffff;
    }
    if (iVar7 < -0x8000) {
      iVar7 = iVar7 + 0xffff;
    }
    if (((0x1000 < iVar7) && (0 < (int)DAT_803de1fc[6])) ||
       ((iVar7 < -0x1000 && ((int)DAT_803de1fc[6] < 0)))) {
      DAT_803de1fc[6] = (float)-(int)DAT_803de1fc[6];
    }
  }
  FUN_8010de18(*(undefined4 *)(param_1 + 0xa4),&fStack_98,&fStack_94,&fStack_90);
  FUN_801037c0((double)FLOAT_803e26a0,(float *)(param_1 + 0x18),&fStack_98,DAT_803de1fc + 9,
               (int)auStack_8c,3,'\x01','\x01');
  return;
}

