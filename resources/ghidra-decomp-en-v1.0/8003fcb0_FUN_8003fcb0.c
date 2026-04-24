// Function: FUN_8003fcb0
// Entry: 8003fcb0
// Size: 1808 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_8003fcb0(undefined4 param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  uint3 uVar2;
  uint3 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  undefined4 *puVar9;
  undefined4 uVar10;
  uint uVar11;
  undefined *puVar12;
  int unaff_r28;
  double dVar13;
  undefined8 uVar14;
  undefined4 local_108;
  undefined4 local_104;
  undefined4 local_100;
  int local_fc;
  int local_f8 [4];
  uint local_e8;
  undefined auStack228 [64];
  undefined auStack164 [64];
  undefined auStack100 [100];
  
  uVar14 = FUN_802860d4();
  iVar5 = (int)((ulonglong)uVar14 >> 0x20);
  iVar6 = FUN_8002b588();
  uVar7 = FUN_8000f54c();
  if (DAT_803dcc24 == 0) {
    FUN_8002b47c(iVar5,auStack164,0);
  }
  else {
    FUN_80246e80(DAT_803dcc24,auStack164);
    DAT_803dcc24 = 0;
  }
  if ((*(ushort *)(iVar6 + 0x18) & 8) == 0) {
    bVar1 = false;
    *(undefined *)(iVar6 + 0x60) = 0;
    FUN_80028544(iVar6);
    if (((*(short *)(param_3 + 0xec) == 0) || ((*(ushort *)(param_3 + 2) & 2) != 0)) ||
       (*(char *)(param_3 + 0xf3) == '\0')) {
      FUN_80028558(iVar6);
      uVar10 = FUN_8002856c(iVar6,0);
      FUN_80246e80(auStack164,uVar10);
    }
    else {
      bVar1 = *(int *)(param_3 + 0xa4) == 0;
      if (bVar1) {
        FUN_80028b54(iVar6,param_3,iVar5,auStack164);
      }
      else {
        FUN_80246e54(auStack228);
        FUN_80028b54(iVar6,param_3,iVar5,auStack228);
        FUN_800272a8(iVar6,auStack164,&DAT_80342e10);
      }
      bVar1 = !bVar1;
      if ((*(code **)(iVar5 + 0x108) != (code *)0x0) && ((int)uVar14 == iVar5)) {
        (**(code **)(iVar5 + 0x108))(iVar5,iVar6,auStack164);
      }
    }
    if (*(char *)(param_3 + 0xf9) != '\0') {
      FUN_80027404(iVar6);
    }
    if (bVar1) {
      if (*(char *)(iVar6 + 0x60) == '\0') {
        uVar10 = *(undefined4 *)(param_3 + 0x28);
      }
      else {
        uVar10 = *(undefined4 *)(iVar6 + (*(ushort *)(iVar6 + 0x18) >> 1 & 1) * 4 + 0x1c);
      }
      FUN_80029ba4(&DAT_80342e10,param_3 + 0x88,uVar10,*(undefined4 *)(iVar6 + 0x40),
                   *(undefined4 *)(iVar6 + (*(ushort *)(iVar6 + 0x18) >> 1 & 1) * 4 + 0x1c));
      FUN_80029834(&DAT_80342e10,param_3 + 0xac,*(undefined4 *)(param_3 + 0x2c),
                   *(undefined4 *)(iVar6 + 0x44),*(byte *)(param_3 + 0x24) & 8);
    }
    if (*(char *)(param_3 + 0xf7) == '\0') {
      iVar4 = *(int *)(iVar5 + 0x54);
      if (iVar4 != 0) {
        *(char *)(iVar4 + 0xaf) = *(char *)(iVar4 + 0xaf) + -1;
        if (*(char *)(*(int *)(iVar5 + 0x54) + 0xaf) < '\0') {
          *(undefined *)(*(int *)(iVar5 + 0x54) + 0xaf) = 0;
        }
      }
    }
    else {
      FUN_80027b40(iVar6,param_3,iVar5,0,(int)uVar14);
    }
    *(ushort *)(iVar6 + 0x18) = *(ushort *)(iVar6 + 0x18) | 8;
  }
  FUN_8003c178(param_3,iVar6);
  iVar4 = (uint)*(ushort *)(param_3 + 0xd8) << 3;
  FUN_80013a64(local_f8,*(undefined4 *)(param_3 + 0xd4),iVar4,iVar4);
  iVar4 = iVar5;
  if (*(int *)(param_3 + 0xa4) != 0) {
    FUN_80246eb4(uVar7,auStack164,auStack100);
    FUN_8025d0a8(auStack100,DAT_802caed9);
  }
  do {
    iVar8 = iVar4;
    iVar4 = *(int *)(iVar8 + 0xc4);
  } while (iVar4 != 0);
  uVar11 = (uint)*(byte *)(*(int *)(*(int *)(iVar8 + 100) + 0xc) + 0x65);
  if (uVar11 == 0xff) {
    local_100 = DAT_803db468;
    FUN_8025bcc4(3,&local_100);
    FUN_8025c584(0,1,0,5);
  }
  else {
    if (uVar11 < 8) {
      local_fc = (1 << uVar11) << 0x18;
    }
    else {
      local_fc = (1 << uVar11 - 8 & 0xffU) << 0x10;
    }
    local_fc = CONCAT31(local_fc._0_3_,0xff);
    local_104 = local_fc;
    FUN_8025bcc4(3,&local_104);
    FUN_8025c584(2,1,0,7);
  }
  FUN_802581e0(0);
  FUN_8025c2a0(1);
  FUN_8025b6f0(0);
  FUN_8025c0c4(0,0xff,0xff,4);
  FUN_8025b71c(0);
  FUN_8025ba40(0,0xf,0xf,0xf,6);
  FUN_8025bac0(0,7,7,7,3);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,0,1,0);
  local_108 = DAT_803db468;
  dVar13 = (double)FLOAT_803dea04;
  FUN_8025c2d4(dVar13,dVar13,dVar13,dVar13,0,&local_108);
  FUN_800702b8(1);
  FUN_8025bff0(7,0,0,7,0);
  FUN_80259ea4(4,0,0,0,0,0,2);
  FUN_80259e58(1);
  if ((*(byte *)(*(int *)(iVar5 + 0x50) + 0x5f) & 4) == 0) {
    FUN_80070310(0,3,0);
    FUN_80258b24(0);
  }
  else {
    FUN_80070310(1,3,1);
    FUN_80258b24(1);
  }
  FUN_80257e74(9,*(undefined4 *)(iVar6 + (*(ushort *)(iVar6 + 0x18) >> 1 & 1) * 4 + 0x1c),6);
  bVar1 = false;
  uVar11 = local_e8;
  while (local_e8 = uVar11, !bVar1) {
    puVar12 = (undefined *)(local_f8[0] + ((int)local_e8 >> 3));
    uVar11 = local_e8 + 4;
    uVar3 = CONCAT12(puVar12[2],CONCAT11(puVar12[1],*puVar12)) >> (local_e8 & 7);
    uVar2 = uVar3 & 0xf;
    if (uVar2 == 3) {
      local_e8 = uVar11;
      FUN_802573f8();
      if (1 < *(byte *)(param_3 + 0xf3)) {
        FUN_80256978(0,1);
      }
      puVar12 = (undefined *)(local_f8[0] + ((int)local_e8 >> 3));
      if ((CONCAT12(puVar12[2],CONCAT11(puVar12[1],*puVar12)) >> (local_e8 & 7) & 1) == 0) {
        uVar10 = 2;
      }
      else {
        uVar10 = 3;
      }
      local_e8 = local_e8 + 1;
      FUN_80256978(9,uVar10);
      if ((*(byte *)(unaff_r28 + 0x40) & 1) != 0) {
        local_e8 = local_e8 + 1;
      }
      if ((*(byte *)(unaff_r28 + 0x40) & 2) != 0) {
        local_e8 = local_e8 + 1;
      }
      FUN_80256978(0xb,1);
      uVar11 = local_e8 + 1;
    }
    else if (uVar2 < 3) {
      if (uVar2 == 1) {
        puVar12 = (undefined *)(local_f8[0] + ((int)uVar11 >> 3));
        local_e8 = local_e8 + 10;
        unaff_r28 = FUN_80028424(param_3,CONCAT12(puVar12[2],CONCAT11(puVar12[1],*puVar12)) >>
                                         (uVar11 & 7) & 0x3f);
        uVar11 = local_e8;
      }
      else if ((uVar3 & 0xf) != 0) {
        puVar12 = (undefined *)(local_f8[0] + ((int)uVar11 >> 3));
        local_e8 = local_e8 + 0xc;
        puVar9 = (undefined4 *)
                 FUN_80028374(param_3,(uint3)*(byte *)(param_3 + 0xf5) +
                                      (CONCAT12(puVar12[2],CONCAT11(puVar12[1],*puVar12)) >>
                                       (uVar11 & 7) & 0xff));
        FUN_8025ced8(*puVar9,*(undefined2 *)(puVar9 + 1));
        uVar11 = local_e8;
      }
    }
    else if (uVar2 == 5) {
      bVar1 = true;
    }
    else if (uVar2 < 5) {
      local_e8 = uVar11;
      FUN_8003e060(param_3,iVar6,local_f8,uVar7);
      uVar11 = local_e8;
    }
  }
  FUN_80286120();
  return;
}

