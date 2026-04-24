// Function: FUN_80121440
// Entry: 80121440
// Size: 2060 bytes

/* WARNING: Removing unreachable block (ram,0x80121c2c) */

void FUN_80121440(void)

{
  uint uVar1;
  uint uVar2;
  float fVar3;
  short sVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  undefined2 uVar9;
  int iVar10;
  char cVar11;
  uint uVar12;
  undefined4 uVar13;
  undefined8 in_f31;
  double dVar14;
  float local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98 [2];
  double local_90;
  double local_88;
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
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FUN_802860d0();
  cVar11 = '\0';
  local_98[0] = 0;
  iVar5 = FUN_8002b9ec();
  iVar6 = FUN_8002b9ac();
  FUN_8025d324(0,0,0x280,0x1e0);
  fVar3 = FLOAT_803e1ec0;
  if ((((DAT_803a92ec < FLOAT_803e1e3c) && (DAT_803a9308 < FLOAT_803e1e3c)) &&
      (DAT_803a9300 < FLOAT_803e1e3c)) && (DAT_803dd798 == 0)) {
    fVar3 = FLOAT_803e1e3c;
  }
  if (fVar3 <= FLOAT_803dd844) {
    if ((fVar3 < FLOAT_803dd844) &&
       (FLOAT_803dd844 = -(FLOAT_803e1fa0 * FLOAT_803db414 - FLOAT_803dd844),
       FLOAT_803dd844 < FLOAT_803e1e3c)) {
      FLOAT_803dd844 = FLOAT_803e1e3c;
    }
  }
  else {
    FLOAT_803dd844 = FLOAT_803e1fa0 * FLOAT_803db414 + FLOAT_803dd844;
    if (FLOAT_803e1ec0 < FLOAT_803dd844) {
      FLOAT_803dd844 = FLOAT_803e1ec0;
    }
  }
  uVar1 = (uint)FLOAT_803dd83c;
  local_90 = (double)(longlong)(int)uVar1;
  if (((uVar1 & 0xff) != 0) &&
     ((((iVar7 = FUN_8005afac((double)*(float *)(iVar5 + 0xc),(double)*(float *)(iVar5 + 0x14)),
        DAT_803a92ec <= FLOAT_803e1f9c || (FLOAT_803e1fa8 <= DAT_803a92ec)) ||
       (local_90 = (double)(longlong)(int)DAT_803a92ec, ((int)DAT_803a92ec & 8U) == 0)) &&
      ((((DAT_803a9308 <= FLOAT_803e1f9c || (FLOAT_803e1fa8 <= DAT_803a9308)) ||
        (local_90 = (double)(longlong)(int)DAT_803a9308, ((int)DAT_803a9308 & 8U) == 0)) &&
       ((iVar7 != 0 || (iVar7 = FUN_802972a8(iVar5), iVar7 == 0)))))))) {
    dVar14 = DOUBLE_803e1e78;
    for (uVar12 = 0; uVar2 = uVar12 & 0xff, (int)uVar2 < DAT_803a9380 >> 2; uVar12 = uVar12 + 1) {
      if ((int)uVar2 < (int)DAT_803a9364 >> 2) {
        iVar7 = 0x16;
      }
      else if ((int)DAT_803a9364 >> 2 < (int)uVar2) {
        iVar7 = 0x12;
      }
      else {
        iVar7 = (DAT_803a9364 & 3) + 0x12;
      }
      local_90 = (double)CONCAT44(0x43300000,uVar2 * 0x21 + 0x1e ^ 0x80000000);
      FUN_8007719c((double)(float)(local_90 - dVar14),(double)FLOAT_803e1fac,(&DAT_803a89b0)[iVar7],
                   uVar1,0x100);
    }
  }
  if ((((uVar1 & 0xff) != 0) && (iVar5 = FUN_80295bc8(iVar5), iVar5 != 0)) &&
     (iVar5 = FUN_8001ffb4(0xeb1), iVar5 != 0)) {
    FUN_80121c4c(uVar1,0x100,0);
  }
  iVar10 = 0;
  iVar5 = FUN_800e7da0(1,0);
  iVar7 = FUN_8001ffb4(0x123);
  if ((iVar7 == 0) && (iVar7 = FUN_8001ffb4(0x83b), iVar7 == 0)) {
    iVar7 = FUN_8001ffb4(0x2e8);
    if ((iVar7 != 0) || (iVar7 = FUN_8001ffb4(0x83c), iVar7 != 0)) {
      iVar10 = 100;
    }
  }
  else {
    iVar10 = 99;
  }
  if (iVar10 != 0) {
    if (iVar5 != 0) {
      sVar4 = 0x104;
    }
    else {
      sVar4 = 0x122;
    }
    local_90 = (double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000);
    FUN_8007719c((double)(float)(local_90 - DOUBLE_803e1e78),(double)FLOAT_803e1fac,
                 (&DAT_803a89b0)[iVar10],uVar1,0x100);
  }
  if (iVar5 != 0) {
    if (iVar10 == 0) {
      sVar4 = 0x122;
    }
    else {
      sVar4 = 0x140;
    }
    local_90 = (double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000);
    FUN_8007719c((double)(float)(local_90 - DOUBLE_803e1e78),(double)FLOAT_803e1fac,DAT_803a8b38,
                 uVar1,0x100);
  }
  if (((uVar1 & 0xff) != 0) && (iVar6 != 0)) {
    cVar11 = '\x16';
    if ((DAT_803a9310 <= FLOAT_803e1f9c) ||
       ((FLOAT_803e1fa8 <= DAT_803a9310 ||
        (local_90 = (double)(longlong)(int)DAT_803a9310, ((int)DAT_803a9310 & 8U) == 0)))) {
      FUN_8007719c((double)FLOAT_803e1f9c,(double)FLOAT_803e1fb0,DAT_803a8b04,uVar1,0x100);
    }
    for (uVar12 = 0; (uVar12 & 0xff) < 0x14; uVar12 = uVar12 + 4) {
      uVar2 = uVar12 & 0xff;
      if (((DAT_803a9388 & 0xfc) == uVar2) && ((DAT_803a9388 & 2) != 0)) {
        iVar5 = (int)(uVar2 * 0xf) >> 2;
        local_90 = (double)CONCAT44(0x43300000,iVar5 + 0x40U ^ 0x80000000);
        FUN_8007681c((double)(float)(local_90 - DOUBLE_803e1e78),(double)FLOAT_803e1fb4,DAT_803a8b0c
                     ,uVar1,0x100,6,0x12,0);
        local_88 = (double)CONCAT44(0x43300000,iVar5 + 0x46U ^ 0x80000000);
        FUN_80075fc8((double)(float)(local_88 - DOUBLE_803e1e78),(double)FLOAT_803e1fb4,DAT_803a8b08
                     ,uVar1,0x100,7,0x12,6,0);
      }
      else {
        if ((int)uVar2 < (int)DAT_803a9388) {
          iVar5 = 0x57;
        }
        else {
          iVar5 = 0x56;
        }
        local_88 = (double)CONCAT44(0x43300000,((int)(uVar2 * 0xf) >> 2) + 0x40U ^ 0x80000000);
        FUN_8007719c((double)(float)(local_88 - DOUBLE_803e1e78),(double)FLOAT_803e1fb4,
                     (&DAT_803a89b0)[iVar5],uVar1,0x100);
      }
    }
  }
  iVar5 = (**(code **)(*DAT_803dca50 + 0x10))();
  if ((iVar5 < 0x49) && (0x46 < iVar5)) {
    local_88 = (double)CONCAT44(0x43300000,(int)cVar11 + 0x5fU ^ 0x80000000);
    FUN_8007719c((double)FLOAT_803e1f9c,(double)(float)(local_88 - DOUBLE_803e1e78),DAT_803a8b44,
                 uVar1,0x100);
  }
  FUN_8025d324(0,0,0x280,0x1e0);
  if (DAT_803dd75a == '\0') {
    iVar5 = FUN_8001ffb4(0x91b);
    if (iVar5 == 0) {
      iVar5 = FUN_8001ffb4(0x91a);
      if (iVar5 == 0) {
        iVar5 = FUN_8001ffb4(0x919);
        if (iVar5 == 0) {
          uVar9 = 10;
        }
        else {
          uVar9 = 0x32;
        }
      }
      else {
        uVar9 = 100;
      }
    }
    else {
      uVar9 = 200;
    }
    local_88 = (double)(longlong)(int)DAT_803a92c4;
    local_90 = (double)(longlong)(int)DAT_803a92f8;
    FUN_801225f4(0x1e,(int)(short)DAT_803a9370,uVar9,(int)DAT_803a92c4,(int)DAT_803a92f8,local_98,0)
    ;
    local_80 = (longlong)(int)DAT_803a92c8;
    local_78 = (longlong)(int)DAT_803a92fc;
    FUN_801225f4(0x19,(int)(short)DAT_803a9374,7,(int)DAT_803a92c8,(int)DAT_803a92fc,local_98,0);
    local_70 = (longlong)(int)DAT_803a92bc;
    local_68 = (longlong)(int)DAT_803a92f0;
    FUN_801225f4(0x1a,(int)(short)DAT_803a9368,0xf,(int)DAT_803a92bc,(int)DAT_803a92f0,local_98,0);
    local_60 = (longlong)(int)DAT_803a92e0;
    local_58 = (longlong)(int)DAT_803a9314;
    FUN_801225f4(0x18,(int)(short)DAT_803a938c,0x1f,(int)DAT_803a92e0,(int)DAT_803a9314,local_98,0);
    local_50 = (longlong)(int)DAT_803a92e4;
    local_48 = (longlong)(int)DAT_803a9318;
    FUN_801225f4(0x1b,(int)(short)DAT_803a9390,7,(int)DAT_803a92e4,(int)DAT_803a9318,local_98,0);
    local_40 = (longlong)(int)DAT_803a92e8;
    local_38 = (longlong)(int)DAT_803a931c;
    FUN_801225f4(0x1c,(int)(short)DAT_803a9394,0xff,(int)DAT_803a92e8,(int)DAT_803a931c,local_98,0);
  }
  else {
    local_9c = 0;
    local_a0 = 0;
    local_a4 = 0;
    local_a8 = FLOAT_803e1f98;
    uVar8 = FUN_8002b9ec();
    iVar5 = FUN_80036e58(9,uVar8,&local_a8);
    if ((iVar5 != 0) && (DAT_803dd780 == '\0')) {
      (**(code **)(**(int **)(iVar5 + 0x68) + 0x54))(iVar5,&local_9c,&local_a0,&local_a4);
      local_98[0] = 0x118;
      FUN_801225f4(0x1e,(int)(short)((short)local_a0 - (short)local_9c),(int)(short)local_a4,0xff,0,
                   local_98,1);
    }
  }
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  FUN_8028611c();
  return;
}

