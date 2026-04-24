// Function: FUN_80121724
// Entry: 80121724
// Size: 2060 bytes

/* WARNING: Removing unreachable block (ram,0x80121f10) */
/* WARNING: Removing unreachable block (ram,0x80121734) */
/* WARNING: Type propagation algorithm not settling */

void FUN_80121724(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined4 in_r10;
  char cVar8;
  uint uVar9;
  double dVar10;
  undefined8 uVar11;
  double dVar12;
  double in_f31;
  double in_ps31_1;
  float local_a8 [4];
  int local_98 [2];
  undefined8 local_90;
  undefined8 local_88;
  longlong local_80;
  longlong local_78;
  longlong local_70;
  longlong local_68;
  longlong local_60;
  longlong local_58;
  longlong local_50;
  longlong local_48;
  longlong local_40;
  longlong local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  FUN_80286834();
  cVar8 = '\0';
  local_98[0] = 0;
  iVar2 = FUN_8002bac4();
  iVar3 = FUN_8002ba84();
  FUN_8025da88(0,0,0x280,0x1e0);
  dVar10 = (double)FLOAT_803e2abc;
  if ((((dVar10 <= (double)DAT_803a9f4c) || (dVar10 <= (double)DAT_803a9f68)) ||
      (dVar10 <= (double)DAT_803a9f60)) || (DAT_803de418 != 0)) {
    dVar10 = (double)FLOAT_803e2b40;
  }
  dVar12 = (double)FLOAT_803de4c4;
  if (dVar10 <= dVar12) {
    if ((dVar10 < dVar12) &&
       (FLOAT_803de4c4 = -(float)((double)FLOAT_803e2c20 * (double)FLOAT_803dc074 - dVar12),
       FLOAT_803de4c4 < FLOAT_803e2abc)) {
      FLOAT_803de4c4 = FLOAT_803e2abc;
    }
  }
  else {
    FLOAT_803de4c4 = (float)((double)FLOAT_803e2c20 * (double)FLOAT_803dc074 + dVar12);
    if (FLOAT_803e2b40 < FLOAT_803de4c4) {
      FLOAT_803de4c4 = FLOAT_803e2b40;
    }
  }
  uVar7 = (uint)FLOAT_803de4bc;
  local_90 = (double)(longlong)(int)uVar7;
  if ((uVar7 & 0xff) != 0) {
    dVar12 = (double)*(float *)(iVar2 + 0x14);
    iVar4 = FUN_8005b128();
    if ((((DAT_803a9f4c <= FLOAT_803e2c1c) || (FLOAT_803e2c28 <= DAT_803a9f4c)) ||
        (local_90 = (double)(longlong)(int)DAT_803a9f4c, ((int)DAT_803a9f4c & 8U) == 0)) &&
       ((((DAT_803a9f68 <= FLOAT_803e2c1c || (FLOAT_803e2c28 <= DAT_803a9f68)) ||
         (local_90 = (double)(longlong)(int)DAT_803a9f68, ((int)DAT_803a9f68 & 8U) == 0)) &&
        ((iVar4 != 0 || (iVar4 = FUN_80297a08(iVar2), iVar4 == 0)))))) {
      dVar10 = DOUBLE_803e2af8;
      for (uVar9 = 0; uVar5 = uVar9 & 0xff, (int)uVar5 < DAT_803a9fe0 >> 2; uVar9 = uVar9 + 1) {
        if ((int)uVar5 < (int)DAT_803a9fc4 >> 2) {
          iVar4 = 0x16;
        }
        else if ((int)DAT_803a9fc4 >> 2 < (int)uVar5) {
          iVar4 = 0x12;
        }
        else {
          iVar4 = (DAT_803a9fc4 & 3) + 0x12;
        }
        local_90 = (double)CONCAT44(0x43300000,uVar5 * 0x21 + 0x1e ^ 0x80000000);
        dVar12 = (double)FLOAT_803e2c2c;
        FUN_80077318((double)(float)(local_90 - dVar10),dVar12,(&DAT_803a9610)[iVar4],uVar7,0x100);
      }
    }
  }
  if ((((uVar7 & 0xff) != 0) && (uVar9 = FUN_80296328(iVar2), uVar9 != 0)) &&
     (uVar9 = FUN_80020078(0xeb1), uVar9 != 0)) {
    FUN_80121f30(uVar7,0x100,0);
  }
  iVar2 = 0;
  uVar9 = FUN_800e8024('\x01',0);
  uVar5 = FUN_80020078(0x123);
  if ((uVar5 == 0) && (uVar5 = FUN_80020078(0x83b), uVar5 == 0)) {
    uVar5 = FUN_80020078(0x2e8);
    if ((uVar5 != 0) || (uVar5 = FUN_80020078(0x83c), uVar5 != 0)) {
      iVar2 = 100;
    }
  }
  else {
    iVar2 = 99;
  }
  if (iVar2 != 0) {
    if (uVar9 != 0) {
      sVar1 = 0x104;
    }
    else {
      sVar1 = 0x122;
    }
    local_90 = (double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000);
    dVar12 = (double)FLOAT_803e2c2c;
    FUN_80077318((double)(float)(local_90 - DOUBLE_803e2af8),dVar12,(&DAT_803a9610)[iVar2],uVar7,
                 0x100);
  }
  if (uVar9 != 0) {
    if (iVar2 == 0) {
      sVar1 = 0x122;
    }
    else {
      sVar1 = 0x140;
    }
    local_90 = (double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000);
    dVar12 = (double)FLOAT_803e2c2c;
    FUN_80077318((double)(float)(local_90 - DOUBLE_803e2af8),dVar12,DAT_803a9798,uVar7,0x100);
  }
  if (((uVar7 & 0xff) != 0) && (iVar3 != 0)) {
    cVar8 = '\x16';
    if ((DAT_803a9f70 <= FLOAT_803e2c1c) ||
       ((FLOAT_803e2c28 <= DAT_803a9f70 ||
        (local_90 = (double)(longlong)(int)DAT_803a9f70, ((int)DAT_803a9f70 & 8U) == 0)))) {
      dVar12 = (double)FLOAT_803e2c30;
      FUN_80077318((double)FLOAT_803e2c1c,dVar12,DAT_803a9764,uVar7,0x100);
    }
    for (uVar9 = 0; (uVar9 & 0xff) < 0x14; uVar9 = uVar9 + 4) {
      uVar5 = uVar9 & 0xff;
      if (((DAT_803a9fe8 & 0xfc) == uVar5) && ((DAT_803a9fe8 & 2) != 0)) {
        iVar2 = (int)(uVar5 * 0xf) >> 2;
        local_90 = (double)CONCAT44(0x43300000,iVar2 + 0x40U ^ 0x80000000);
        FUN_80076998((double)(float)(local_90 - DOUBLE_803e2af8),(double)FLOAT_803e2c34,DAT_803a976c
                     ,uVar7,0x100,6,0x12,0);
        local_88 = (double)CONCAT44(0x43300000,iVar2 + 0x46U ^ 0x80000000);
        dVar12 = (double)FLOAT_803e2c34;
        FUN_80076144((double)(float)(local_88 - DOUBLE_803e2af8),dVar12,DAT_803a9768,uVar7,0x100,7,
                     0x12,6,0);
      }
      else {
        if ((int)uVar5 < (int)DAT_803a9fe8) {
          iVar2 = 0x57;
        }
        else {
          iVar2 = 0x56;
        }
        local_88 = (double)CONCAT44(0x43300000,((int)(uVar5 * 0xf) >> 2) + 0x40U ^ 0x80000000);
        dVar12 = (double)FLOAT_803e2c34;
        FUN_80077318((double)(float)(local_88 - DOUBLE_803e2af8),dVar12,(&DAT_803a9610)[iVar2],uVar7
                     ,0x100);
      }
    }
  }
  iVar2 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if ((iVar2 < 0x49) && (0x46 < iVar2)) {
    local_88 = (double)CONCAT44(0x43300000,(int)cVar8 + 0x5fU ^ 0x80000000);
    dVar12 = (double)(float)(local_88 - DOUBLE_803e2af8);
    FUN_80077318((double)FLOAT_803e2c1c,dVar12,DAT_803a97a4,uVar7,0x100);
  }
  uVar11 = FUN_8025da88(0,0,0x280,0x1e0);
  if (DAT_803de3da == '\0') {
    uVar7 = FUN_80020078(0x91b);
    if (uVar7 == 0) {
      uVar7 = FUN_80020078(0x91a);
      if (uVar7 == 0) {
        uVar7 = FUN_80020078(0x919);
        if (uVar7 == 0) {
          sVar1 = 10;
        }
        else {
          sVar1 = 0x32;
        }
      }
      else {
        sVar1 = 100;
      }
    }
    else {
      sVar1 = 200;
    }
    local_88 = (double)(longlong)(int)DAT_803a9f24;
    local_90 = (double)(longlong)(int)DAT_803a9f58;
    uVar11 = FUN_801228d8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1e,
                          (int)(short)DAT_803a9fd0,sVar1,(int)DAT_803a9f24,(int)DAT_803a9f58,
                          local_98,0,in_r10);
    local_80 = (longlong)(int)DAT_803a9f28;
    local_78 = (longlong)(int)DAT_803a9f5c;
    uVar11 = FUN_801228d8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x19,
                          (int)(short)DAT_803a9fd4,7,(int)DAT_803a9f28,(int)DAT_803a9f5c,local_98,0,
                          in_r10);
    local_70 = (longlong)(int)DAT_803a9f1c;
    local_68 = (longlong)(int)DAT_803a9f50;
    uVar11 = FUN_801228d8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1a,
                          (int)(short)DAT_803a9fc8,0xf,(int)DAT_803a9f1c,(int)DAT_803a9f50,local_98,
                          0,in_r10);
    local_60 = (longlong)(int)DAT_803a9f40;
    local_58 = (longlong)(int)DAT_803a9f74;
    uVar11 = FUN_801228d8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x18,
                          (int)(short)DAT_803a9fec,0x1f,(int)DAT_803a9f40,(int)DAT_803a9f74,local_98
                          ,0,in_r10);
    local_50 = (longlong)(int)DAT_803a9f44;
    local_48 = (longlong)(int)DAT_803a9f78;
    uVar11 = FUN_801228d8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1b,
                          (int)(short)DAT_803a9ff0,7,(int)DAT_803a9f44,(int)DAT_803a9f78,local_98,0,
                          in_r10);
    local_40 = (longlong)(int)DAT_803a9f48;
    local_38 = (longlong)(int)DAT_803a9f7c;
    FUN_801228d8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1c,
                 (int)(short)DAT_803a9ff4,0xff,(int)DAT_803a9f48,(int)DAT_803a9f7c,local_98,0,in_r10
                );
  }
  else {
    local_a8[3] = 0.0;
    local_a8[2] = 0.0;
    local_a8[1] = 0.0;
    local_a8[0] = FLOAT_803e2c18;
    uVar6 = FUN_8002bac4();
    iVar2 = FUN_80036f50(9,uVar6,local_a8);
    if ((iVar2 != 0) && (DAT_803de400 == '\0')) {
      uVar11 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x54))
                         (iVar2,local_a8 + 3,local_a8 + 2,local_a8 + 1);
      local_98[0] = 0x118;
      FUN_801228d8(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,0x1e,
                   (int)(short)(SUB42(local_a8[2],0) - SUB42(local_a8[3],0)),SUB42(local_a8[1],0),
                   0xff,0,local_98,1,in_r10);
    }
  }
  FUN_80286880();
  return;
}

