// Function: FUN_8003fda8
// Entry: 8003fda8
// Size: 1808 bytes

void FUN_8003fda8(undefined4 param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  uint3 uVar2;
  uint3 uVar3;
  ushort *puVar4;
  ushort *puVar5;
  int *piVar6;
  float *pfVar7;
  float *pfVar8;
  ushort *puVar9;
  undefined4 *puVar10;
  int iVar11;
  uint uVar12;
  undefined *puVar13;
  int unaff_r28;
  double dVar14;
  undefined8 uVar15;
  uint3 local_108;
  undefined4 local_104;
  undefined4 local_100;
  undefined4 local_fc;
  int local_f8 [4];
  uint local_e8;
  float afStack_e4 [16];
  float afStack_a4 [16];
  float afStack_64 [25];
  
  uVar15 = FUN_80286838();
  puVar5 = (ushort *)((ulonglong)uVar15 >> 0x20);
  piVar6 = (int *)FUN_8002b660((int)puVar5);
  pfVar7 = (float *)FUN_8000f56c();
  if (DAT_803dd8a4 == (float *)0x0) {
    FUN_8002b554(puVar5,afStack_a4,'\0');
  }
  else {
    FUN_802475e4(DAT_803dd8a4,afStack_a4);
    DAT_803dd8a4 = (float *)0x0;
  }
  if ((*(ushort *)(piVar6 + 6) & 8) == 0) {
    bVar1 = false;
    *(undefined *)(piVar6 + 0x18) = 0;
    FUN_80028608((int)piVar6);
    if (((*(short *)(param_3 + 0xec) == 0) || ((*(ushort *)(param_3 + 2) & 2) != 0)) ||
       (*(char *)(param_3 + 0xf3) == '\0')) {
      FUN_8002861c((int)piVar6);
      pfVar8 = (float *)FUN_80028630(piVar6,0);
      FUN_802475e4(afStack_a4,pfVar8);
    }
    else {
      bVar1 = *(int *)(param_3 + 0xa4) == 0;
      if (bVar1) {
        FUN_80028c18(piVar6,param_3,(int)puVar5,afStack_a4);
      }
      else {
        FUN_802475b8(afStack_e4);
        FUN_80028c18(piVar6,param_3,(int)puVar5,afStack_e4);
        FUN_8002736c(piVar6,afStack_a4,(float *)&DAT_80343a70);
      }
      bVar1 = !bVar1;
      if ((*(code **)(puVar5 + 0x84) != (code *)0x0) && ((ushort *)uVar15 == puVar5)) {
        (**(code **)(puVar5 + 0x84))(puVar5,piVar6,afStack_a4);
      }
    }
    if (*(char *)(param_3 + 0xf9) != '\0') {
      FUN_800274c8();
    }
    if (bVar1) {
      if (*(char *)(piVar6 + 0x18) == '\0') {
        iVar11 = *(int *)(param_3 + 0x28);
      }
      else {
        iVar11 = piVar6[(*(ushort *)(piVar6 + 6) >> 1 & 1) + 7];
      }
      FUN_80029c7c(&DAT_80343a70,param_3 + 0x88,iVar11,(int *)piVar6[0x10],
                   piVar6[(*(ushort *)(piVar6 + 6) >> 1 & 1) + 7]);
      FUN_8002990c(&DAT_80343a70,param_3 + 0xac,*(int *)(param_3 + 0x2c),(uint *)piVar6[0x11],
                   *(byte *)(param_3 + 0x24) & 8);
    }
    if (*(char *)(param_3 + 0xf7) == '\0') {
      iVar11 = *(int *)(puVar5 + 0x2a);
      if (iVar11 != 0) {
        *(char *)(iVar11 + 0xaf) = *(char *)(iVar11 + 0xaf) + -1;
        if (*(char *)(*(int *)(puVar5 + 0x2a) + 0xaf) < '\0') {
          *(undefined *)(*(int *)(puVar5 + 0x2a) + 0xaf) = 0;
        }
      }
    }
    else {
      FUN_80027c04(piVar6,param_3,(int)puVar5,(float *)0x0,(int)(ushort *)uVar15);
    }
    *(ushort *)(piVar6 + 6) = *(ushort *)(piVar6 + 6) | 8;
  }
  FUN_8003c270(param_3,piVar6);
  uVar12 = (uint)*(ushort *)(param_3 + 0xd8) << 3;
  FUN_80013a84(local_f8,*(undefined4 *)(param_3 + 0xd4),uVar12,uVar12);
  puVar4 = puVar5;
  if (*(int *)(param_3 + 0xa4) != 0) {
    FUN_80247618(pfVar7,afStack_a4,afStack_64);
    FUN_8025d80c(afStack_64,(uint)DAT_802cbab1);
  }
  do {
    puVar9 = puVar4;
    puVar4 = *(ushort **)(puVar9 + 0x62);
  } while (puVar4 != (ushort *)0x0);
  uVar12 = (uint)*(byte *)(*(int *)(*(int *)(puVar9 + 0x32) + 0xc) + 0x65);
  if (uVar12 == 0xff) {
    local_100 = DAT_803dc0c8;
    FUN_8025c428(3,(byte *)&local_100);
    FUN_8025cce8(0,1,0,5);
  }
  else {
    if (uVar12 < 8) {
      local_fc = (1 << uVar12) << 0x18;
      local_fc = local_fc >> 0x10;
    }
    else {
      local_fc = 1 << uVar12 - 8 & 0xff;
    }
    local_fc = local_fc << 0x10;
    local_fc = CONCAT31(local_fc._0_3_,0xff);
    local_104 = local_fc;
    FUN_8025c428(3,(byte *)&local_104);
    FUN_8025cce8(2,1,0,7);
  }
  FUN_80258944(0);
  FUN_8025ca04(1);
  FUN_8025be54(0);
  FUN_8025c828(0,0xff,0xff,4);
  FUN_8025be80(0);
  FUN_8025c1a4(0,0xf,0xf,0xf,6);
  FUN_8025c224(0,7,7,7,3);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  _local_108 = DAT_803dc0c8;
  dVar14 = (double)FLOAT_803df684;
  FUN_8025ca38(dVar14,dVar14,dVar14,dVar14,0,&local_108);
  FUN_80070434(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a5bc(1);
  if ((*(byte *)(*(int *)(puVar5 + 0x28) + 0x5f) & 4) == 0) {
    FUN_8007048c(0,3,0);
    FUN_80259288(0);
  }
  else {
    FUN_8007048c(1,3,1);
    FUN_80259288(1);
  }
  FUN_802585d8(9,piVar6[(*(ushort *)(piVar6 + 6) >> 1 & 1) + 7],6);
  bVar1 = false;
  uVar12 = local_e8;
  while (local_e8 = uVar12, !bVar1) {
    puVar13 = (undefined *)(local_f8[0] + ((int)local_e8 >> 3));
    uVar12 = local_e8 + 4;
    uVar3 = CONCAT12(puVar13[2],CONCAT11(puVar13[1],*puVar13)) >> (local_e8 & 7);
    uVar2 = uVar3 & 0xf;
    if (uVar2 == 3) {
      local_e8 = uVar12;
      FUN_80257b5c();
      if (1 < *(byte *)(param_3 + 0xf3)) {
        FUN_802570dc(0,1);
      }
      puVar13 = (undefined *)(local_f8[0] + ((int)local_e8 >> 3));
      if ((CONCAT12(puVar13[2],CONCAT11(puVar13[1],*puVar13)) >> (local_e8 & 7) & 1) == 0) {
        uVar12 = 2;
      }
      else {
        uVar12 = 3;
      }
      local_e8 = local_e8 + 1;
      FUN_802570dc(9,uVar12);
      if ((*(byte *)(unaff_r28 + 0x40) & 1) != 0) {
        local_e8 = local_e8 + 1;
      }
      if ((*(byte *)(unaff_r28 + 0x40) & 2) != 0) {
        local_e8 = local_e8 + 1;
      }
      FUN_802570dc(0xb,1);
      uVar12 = local_e8 + 1;
    }
    else if (uVar2 < 3) {
      if (uVar2 == 1) {
        puVar13 = (undefined *)(local_f8[0] + ((int)uVar12 >> 3));
        local_e8 = local_e8 + 10;
        unaff_r28 = FUN_800284e8(param_3,(uint3)(CONCAT12(puVar13[2],CONCAT11(puVar13[1],*puVar13))
                                                >> (uVar12 & 7)) & 0x3f);
        uVar12 = local_e8;
      }
      else if ((uVar3 & 0xf) != 0) {
        puVar13 = (undefined *)(local_f8[0] + ((int)uVar12 >> 3));
        local_e8 = local_e8 + 0xc;
        puVar10 = (undefined4 *)
                  FUN_80028438(param_3,(uint)*(byte *)(param_3 + 0xf5) +
                                       ((uint3)(CONCAT12(puVar13[2],CONCAT11(puVar13[1],*puVar13))
                                               >> (uVar12 & 7)) & 0xff));
        FUN_8025d63c(*puVar10,(uint)*(ushort *)(puVar10 + 1));
        uVar12 = local_e8;
      }
    }
    else if (uVar2 == 5) {
      bVar1 = true;
    }
    else if (uVar2 < 5) {
      local_e8 = uVar12;
      FUN_8003e158(param_3,piVar6,local_f8,pfVar7);
      uVar12 = local_e8;
    }
  }
  FUN_80286884();
  return;
}

