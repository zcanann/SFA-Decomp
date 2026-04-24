// Function: FUN_80186bc8
// Entry: 80186bc8
// Size: 1256 bytes

/* WARNING: Removing unreachable block (ram,0x80187088) */

void FUN_80186bc8(int param_1)

{
  byte bVar1;
  undefined4 uVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined4 in_r10;
  int *piVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  double local_38;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  piVar7 = *(int **)(param_1 + 0xb8);
  iVar4 = FUN_8002b9ec();
  *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x84) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0x88) = *(undefined4 *)(param_1 + 0x14);
  if (FLOAT_803e3aa0 < (float)piVar7[0x10]) {
    piVar7[0x10] = (int)((float)piVar7[0x10] - FLOAT_803e3aa0);
    bVar1 = *(byte *)(piVar7 + 0x1b);
    if (bVar1 < 4) {
      FUN_801868d0(param_1);
    }
    else if (bVar1 == 7) {
      *(undefined *)(piVar7 + 0x1b) = 0;
    }
    else {
      *(byte *)(piVar7 + 0x1b) = bVar1 + 1;
    }
    FUN_801869dc(param_1);
  }
  dVar9 = (double)FUN_80010ee0((double)(float)piVar7[0x10],piVar7 + 1,0);
  *(float *)(param_1 + 0xc) = (float)((double)(float)piVar7[0x15] + dVar9);
  dVar9 = (double)FUN_80010ee0((double)(float)piVar7[0x10],piVar7 + 5,0);
  *(float *)(param_1 + 0x10) = (float)((double)(float)piVar7[0x16] + dVar9);
  dVar9 = (double)FUN_80010ee0((double)(float)piVar7[0x10],piVar7 + 9,0);
  *(float *)(param_1 + 0x14) = (float)((double)(float)piVar7[0x17] + dVar9);
  if (*(byte *)(piVar7 + 0x1c) >> 6 == 1) {
    iVar5 = FUN_8002b9ec();
    dVar9 = (double)FUN_80021704(param_1 + 0x18,iVar5 + 0x18);
    piVar7[0x11] = (int)(float)((double)FLOAT_803e3ac4 * dVar9 + (double)FLOAT_803e3ac0);
  }
  piVar7[0x10] = (int)((float)piVar7[0x11] * FLOAT_803db414 + (float)piVar7[0x10]);
  if ((((*(char *)((int)piVar7 + 0x6a) == '\x01') || (*(char *)((int)piVar7 + 0x6a) == '\x04')) &&
      (*(byte *)(piVar7 + 0x1c) >> 6 == 1)) && (*(char *)((int)piVar7 + 0x6e) == '\0')) {
    *(undefined *)((int)piVar7 + 0x6e) = 1;
    iVar5 = FUN_8001f4c8(param_1,1);
    if (iVar5 == 0) {
      iVar5 = 0;
    }
    else {
      FUN_8001db2c(iVar5,2);
      FUN_8001daf0(iVar5,100,0xff,100,0);
      FUN_8001db14(iVar5,1);
      FUN_8001dc38((double)FLOAT_803e3a98,(double)FLOAT_803e3a9c,iVar5);
      FUN_8001dd40(iVar5,1);
    }
    *piVar7 = iVar5;
    if (*(byte *)(piVar7 + 0x1c) >> 6 != 1) {
      DAT_803ddad8 = 1;
    }
  }
  fVar11 = *(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x80);
  fVar12 = *(float *)(param_1 + 0x10) - *(float *)(param_1 + 0x84);
  fVar13 = *(float *)(param_1 + 0x14) - *(float *)(param_1 + 0x88);
  dVar9 = (double)FUN_802931a0((double)(fVar13 * fVar13 + fVar11 * fVar11 + fVar12 * fVar12));
  fVar3 = FLOAT_803e3aa0 /
          (float)((double)CONCAT44(0x43300000,
                                   (int)(dVar9 / (double)FLOAT_803e3ac8) + 1U ^ 0x80000000) -
                 DOUBLE_803e3ab0);
  if (*(byte *)(piVar7 + 0x1c) >> 6 == 1) {
    FUN_8000da58(param_1,0x43b);
    if (FLOAT_803dbdd8 <
        (float)((double)CONCAT44(0x43300000,piVar7[0x18] ^ 0x80000000) - DOUBLE_803e3ab0)) {
      if ((*(char *)((int)piVar7 + 0x6a) == '\x01') || (*(char *)((int)piVar7 + 0x6a) == '\x04')) {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x19f,0,1,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x1a0,0,1,0xffffffff,0);
      }
      else {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x1bd,0,1,0xffffffff,0);
      }
    }
    uVar6 = (uint)DAT_803db410;
    iVar5 = piVar7[0x18];
    piVar7[0x18] = iVar5 - uVar6;
    if ((int)(iVar5 - uVar6) < 0) {
      FUN_8001fee8(0x698);
      FUN_8002cbc4(param_1);
    }
    else {
      uVar2 = *(undefined4 *)(iVar4 + 0x20);
      fVar11 = FLOAT_803e3aa8 + *(float *)(iVar4 + 0x1c);
      iVar5 = *(int *)(param_1 + 0xb8);
      *(undefined4 *)(iVar5 + 0x54) = *(undefined4 *)(iVar4 + 0x18);
      *(float *)(iVar5 + 0x58) = fVar11;
      *(undefined4 *)(iVar5 + 0x5c) = uVar2;
      if ((*piVar7 != 0) && (piVar7[0x18] < 0xb4)) {
        dVar9 = (double)FUN_80293e80((double)((FLOAT_803e3acc *
                                              (float)((double)CONCAT44(0x43300000,
                                                                       piVar7[0x18] << 0xb ^
                                                                       0x80000000) - DOUBLE_803e3ab0
                                                     )) / FLOAT_803e3ad0));
        local_38 = (double)CONCAT44(0x43300000,piVar7[0x18] ^ 0x80000000);
        dVar10 = (double)(float)((double)(float)(local_38 - DOUBLE_803e3ab0) * dVar9);
        FUN_8000da58(dVar9,DOUBLE_803e3ab0,0,0x460);
        FUN_8001dc38(dVar10,(double)(float)((double)FLOAT_803e3ad4 + dVar10),*piVar7);
      }
    }
  }
  else {
    (**(code **)(*DAT_803dca88 + 8))
              (param_1,0x19f,0,1,0xffffffff,0,*DAT_803dca88,in_r10,fVar11 * fVar3,fVar12 * fVar3,
               fVar13 * fVar3);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x1a0,0,1,0xffffffff,0);
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  return;
}

