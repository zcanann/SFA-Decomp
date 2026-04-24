// Function: FUN_8021dfb8
// Entry: 8021dfb8
// Size: 1176 bytes

void FUN_8021dfb8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_8028683c();
  uVar3 = (uint)((ulonglong)uVar12 >> 0x20);
  iVar8 = (int)uVar12;
  iVar10 = *(int *)(uVar3 + 0xb8);
  iVar9 = -1;
  if (*(char *)(iVar8 + 0x27a) != '\0') {
    *(byte *)(iVar10 + 0xc49) = *(byte *)(iVar10 + 0xc49) & 0xbf | 0x40;
    uVar4 = FUN_80022264(500,1000);
    *(float *)(iVar10 + 0xc30) =
         (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e7790);
    *(undefined *)(iVar10 + 0xc4b) = 0;
    if (*(short *)(uVar3 + 0xa0) != 2) {
      iVar9 = 2;
      *(float *)(iVar8 + 0x2a0) = FLOAT_803e7744;
    }
    FUN_8003935c((undefined4 *)(iVar10 + 0xb48));
  }
  uVar4 = FUN_80020078(0x9c9);
  uVar5 = FUN_80020078(0x9c7);
  uVar6 = FUN_80020078(0x9cb);
  uVar7 = FUN_80020078(0x9cd);
  uVar5 = uVar5 + uVar4 + uVar6 + uVar7;
  uVar4 = FUN_80020078(0x62b);
  if (uVar4 != 0) {
    FUN_800201ac(0x62f,1);
    FUN_80035f84(uVar3);
    FUN_80035f28(uVar3,1);
    *(byte *)(*(int *)(uVar3 + 0x50) + 0x71) = *(byte *)(*(int *)(uVar3 + 0x50) + 0x71) & 0xfe;
    *(undefined *)(iVar10 + 0xc4b) = 0xff;
    *(ushort *)(iVar10 + 0xc40) = *(ushort *)(iVar10 + 0xc40) | 0x40;
    *(ushort *)(iVar10 + 0xc40) = *(ushort *)(iVar10 + 0xc40) | 0x20;
    *(byte *)(iVar10 + 0xc49) = *(byte *)(iVar10 + 0xc49) & 0xbf;
    (**(code **)(*DAT_803dd71c + 0xa8))(iVar10 + 0xa10,uVar3,0x3463a);
    iVar8 = *(int *)(uVar3 + 0xb8);
    *(byte *)(iVar8 + 0xc49) = *(byte *)(iVar8 + 0xc49) & 0xfe | 1;
    (**(code **)(*DAT_803dd6e8 + 0x58))(DAT_803dcf88,0x5ce);
    (**(code **)(*DAT_803dd6e8 + 0x5c))((int)*(short *)(iVar8 + 0xc18));
    FUN_8003935c((undefined4 *)(iVar10 + 0xb48));
    goto LAB_8021e438;
  }
  if (uVar5 == 4) {
    FUN_800201ac(0x62a,1);
    goto LAB_8021e438;
  }
  FUN_80039210(uVar3,(int *)(iVar10 + 0xb48));
  dVar11 = (double)*(float *)(iVar10 + 0xc30);
  *(float *)(iVar10 + 0xc30) =
       (float)(dVar11 - (double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) -
                                       DOUBLE_803e7768));
  if ((*(short *)(uVar3 + 0xa0) != 9) && (*(short *)(uVar3 + 0xa0) != 0x11)) {
    dVar11 = (double)FLOAT_803e7774;
    FUN_80022150((double)FLOAT_803e7770,dVar11,(float *)(iVar10 + 0xc34));
    if (uVar5 == 0) {
      if (*(float *)(iVar10 + 0xc30) < FLOAT_803e7740) {
        dVar11 = (double)FLOAT_803e7778;
        *(float *)(iVar8 + 0x2a0) =
             (float)(dVar11 * (double)(float)(4503601774854144.0 - DOUBLE_803e7790) +
                    (double)FLOAT_803e7748);
        iVar9 = 9;
        uVar4 = FUN_80022264(700,1000);
        *(float *)(iVar10 + 0xc30) =
             (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e7790);
      }
    }
    else {
      uVar4 = FUN_8008038c((4 - uVar5) * 10);
      if (uVar4 != 0) {
        dVar11 = (double)FLOAT_803e7780;
        *(float *)(iVar8 + 0x2a0) =
             (float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) -
                                             DOUBLE_803e7790) + (double)FLOAT_803e777c);
        iVar9 = 9;
        uVar4 = FUN_80022264(700,1000);
        *(float *)(iVar10 + 0xc30) =
             (float)((double)CONCAT44(0x43300000,uVar4 + uVar5 * -300 ^ 0x80000000) -
                    DOUBLE_803e7790);
      }
    }
  }
  if ((*(char *)(iVar8 + 0x346) != '\0') && (*(short *)(uVar3 + 0xa0) != 2)) {
    iVar9 = 2;
    *(float *)(iVar8 + 0x2a0) = FLOAT_803e7744;
  }
  if (iVar9 != -1) {
    FUN_8002f66c(uVar3,0x78);
    FUN_8003042c((double)FLOAT_803e7740,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,uVar3
                 ,iVar9,0,in_r6,in_r7,in_r8,in_r9,in_r10);
  }
  iVar8 = FUN_8002bac4();
  if (iVar8 == 0) {
LAB_8021e424:
    *(byte *)(iVar10 + 0x9fd) = *(byte *)(iVar10 + 0x9fd) & 0xfe;
  }
  else {
    fVar1 = *(float *)(iVar8 + 0x10) - *(float *)(uVar3 + 0x10);
    fVar2 = fVar1;
    if (fVar1 < FLOAT_803e7740) {
      fVar2 = -fVar1;
    }
    if (FLOAT_803e7784 <= fVar2) {
      if (fVar1 < FLOAT_803e7740) {
        fVar1 = -fVar1;
      }
      if (fVar1 <= FLOAT_803e7788) goto LAB_8021e424;
    }
    *(byte *)(iVar10 + 0x9fd) = *(byte *)(iVar10 + 0x9fd) | 1;
    uVar4 = FUN_80022264(0,100);
    if ((uVar4 == 0) && (*(short *)(uVar3 + 0xa0) != 9)) {
      fVar1 = *(float *)(iVar8 + 0x10) - *(float *)(uVar3 + 0x10);
      if (fVar1 < FLOAT_803e7740) {
        fVar1 = -fVar1;
      }
      if (fVar1 < FLOAT_803e7784) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(9,uVar3,0xffffffff);
      }
    }
  }
LAB_8021e438:
  FUN_80286888();
  return;
}

