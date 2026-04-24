// Function: FUN_801265b0
// Entry: 801265b0
// Size: 4652 bytes

/* WARNING: Removing unreachable block (ram,0x801277bc) */
/* WARNING: Removing unreachable block (ram,0x801277b4) */
/* WARNING: Removing unreachable block (ram,0x801277ac) */
/* WARNING: Removing unreachable block (ram,0x801274ec) */
/* WARNING: Removing unreachable block (ram,0x801265d0) */
/* WARNING: Removing unreachable block (ram,0x801265c8) */
/* WARNING: Removing unreachable block (ram,0x801265c0) */

void FUN_801265b0(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  ushort uVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined *puVar6;
  int iVar7;
  undefined4 extraout_r4;
  undefined4 uVar8;
  undefined4 uVar9;
  int *piVar10;
  int *piVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  int *piVar14;
  undefined4 in_r9;
  int *piVar15;
  undefined4 in_r10;
  int iVar16;
  short sVar17;
  double dVar18;
  undefined8 extraout_f1;
  double dVar19;
  undefined8 uVar20;
  double dVar21;
  double dVar22;
  double dVar23;
  double in_f29;
  double dVar24;
  double in_f30;
  double dVar25;
  double in_f31;
  double dVar26;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_b8;
  int local_b4;
  int local_b0;
  int local_ac;
  int local_a8;
  undefined auStack_a4 [12];
  longlong local_98;
  longlong local_90;
  longlong local_88;
  longlong local_80;
  undefined4 local_78;
  uint uStack_74;
  longlong local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  FUN_8028683c();
  FUN_8002bac4();
  FUN_8025da88(0,0,0x280,0x1e0);
  if (DAT_803de400 != 0) {
    param_2 = (double)FLOAT_803e2abc;
    FUN_8007668c(param_2,param_2,0x280,0x1e0);
  }
  switch(DAT_803de400) {
  case 0:
    FUN_80129a98();
    break;
  case 1:
    uVar20 = FUN_80019940(0xff,0xff,0xff,0xff);
    uVar20 = FUN_800199a8(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xb);
    FUN_80016848(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3dd,200,300);
  case 2:
    FUN_80129d10();
    break;
  case 3:
    FUN_80129d10();
    fVar2 = FLOAT_803e2b40 * FLOAT_803de3e0;
    local_98 = (longlong)(int)fVar2;
    dVar19 = (double)FUN_80294964();
    FLOAT_803de4d0 = (float)dVar19;
    FLOAT_803de3c8 = FLOAT_803de3c8 + FLOAT_803dc074;
    dVar19 = (double)FUN_80294b54();
    local_90 = (longlong)(int)((double)FLOAT_803dc6b4 * dVar19);
    DAT_803de3d0 = (ushort)(int)((double)FLOAT_803dc6b4 * dVar19);
    dVar19 = (double)FUN_80294b54();
    iVar7 = (int)((double)FLOAT_803de3cc * dVar19 + (double)FLOAT_803dc6bc);
    local_88 = (longlong)iVar7;
    DAT_803de3d2 = (ushort)iVar7;
    dVar19 = (double)FUN_80294b54();
    iVar7 = (int)((double)FLOAT_803dc6b8 * dVar19 + (double)FLOAT_803de43c);
    local_80 = (longlong)iVar7;
    DAT_803de3d4 = (ushort)iVar7;
    FLOAT_803dc6a4 = (float)(DOUBLE_803e2cf0 * (double)FLOAT_803de3e0);
    dVar22 = (double)FLOAT_803dc6a4;
    FLOAT_803dc69c =
         (float)-(DOUBLE_803e2cf0 * (DOUBLE_803e2be0 - (double)FLOAT_803de3e0) - DOUBLE_803e2cf8);
    FUN_8011f234((double)FLOAT_803e2abc,(double)FLOAT_803dc69c,(double)FLOAT_803dc6a0,dVar22,
                 DAT_803de3d0,DAT_803de3d2,DAT_803de3d4);
    iVar7 = FUN_8002b660(DAT_803de4e0);
    uVar9 = 0;
    uVar8 = 0;
    uVar12 = 1;
    iVar16 = DAT_803de4e0;
    FUN_8003ba50(0,0,0,0,DAT_803de4e0,1);
    *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
    uStack_74 = (int)(short)(int)fVar2 ^ 0x80000000;
    local_78 = 0x43300000;
    iVar7 = (int)((float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e2af8) * FLOAT_803de4d0
                 );
    local_70 = (longlong)iVar7;
    sVar17 = (short)iVar7;
    local_68 = (double)CONCAT44(0x43300000,(int)sVar17 ^ 0x80000000);
    dVar23 = local_68 - DOUBLE_803e2af8;
    local_60 = (double)CONCAT44(0x43300000,(int)DAT_803de3dc ^ 0x80000000);
    iVar7 = (int)(dVar23 * (DOUBLE_803e2d00 - (local_60 - DOUBLE_803e2af8)) * DOUBLE_803e2d08);
    local_58 = (double)(longlong)iVar7;
    uVar13 = extraout_r4;
    dVar19 = DOUBLE_803e2af8;
    dVar21 = FUN_80019c38();
    if (dVar21 == (double)FLOAT_803e2abc) {
      if (DAT_803de444 == '\0') {
        if (DAT_803de448 == 0) {
          DAT_803de448 = FUN_80054ed0(dVar21,dVar23,dVar19,dVar22,param_5,param_6,param_7,param_8,
                                      0xbe7,uVar13,uVar9,uVar8,iVar16,uVar12,in_r9,in_r10);
        }
        if (DAT_803de448 != 0) {
          dVar23 = (double)FLOAT_803e2d18;
          local_58 = (double)(longlong)(int)FLOAT_803e2d1c;
          FUN_8011f088((double)FLOAT_803e2b00,dVar23,DAT_803de448,0x96 - DAT_803de3dc,(char)iVar7,
                       (int)FLOAT_803e2d1c,0);
        }
      }
      uVar20 = FUN_80128260();
      if (DAT_803de444 == '\0') {
        DAT_803de4a4 = (undefined2 *)&DAT_8031c468;
      }
      else {
        DAT_803de4a4 = &DAT_8031c640;
      }
      FUN_801287ac(uVar20,dVar23,dVar19,dVar22,param_5,param_6,param_7,param_8);
      iVar7 = FUN_8002b660(iRam803de4e4);
      FUN_8003ba50(0,0,0,0,iRam803de4e4,1);
      *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
      FUN_8000f478(0);
      FUN_8000f584();
      FUN_8000fc5c((double)FLOAT_803de47c);
      FUN_8000fb20();
      FUN_8000f7a0();
      FUN_8025da88(0,0,0x280,0x1e0);
    }
    else {
      uVar4 = FUN_80022264(0,0x1e);
      uVar5 = FUN_80022264(0,0x1e);
      FUN_8011ebbc((double)FLOAT_803e2d10,(double)FLOAT_803e2d14,DAT_803a9760,0xff,
                   (char)((int)sVar17 / 2),0x230,400,uVar5 << 1,uVar4 << 1);
      iVar7 = FUN_8002b660(iRam803de4e4);
      FUN_8003ba50(0,0,0,0,iRam803de4e4,1);
      *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
      FUN_8000f478(0);
      FUN_8000f584();
      FUN_8000fc5c((double)FLOAT_803de47c);
      FUN_8000fb20();
      FUN_8000f7a0();
    }
    break;
  case 4:
    FUN_80129d10();
    iVar7 = FUN_80019c30();
    uVar1 = *(ushort *)(&DAT_802c8e0a + (uint)(byte)(&DAT_802c7b54)[iVar7 * 8] * 0x10);
    fVar2 = FLOAT_803e2b40 * FLOAT_803de3e0;
    local_58 = (double)(longlong)(int)fVar2;
    dVar19 = (double)FUN_80294964();
    FLOAT_803de4d0 = (float)dVar19;
    FLOAT_803de3c8 = FLOAT_803de3c8 + FLOAT_803dc074;
    dVar19 = (double)FUN_80294b54();
    local_60 = (double)(longlong)(int)((double)FLOAT_803dc6b4 * dVar19);
    DAT_803de3d0 = (ushort)(int)((double)FLOAT_803dc6b4 * dVar19);
    dVar19 = (double)FUN_80294b54();
    iVar7 = (int)((double)FLOAT_803de3cc * dVar19 + (double)FLOAT_803dc6bc);
    local_68 = (double)(longlong)iVar7;
    DAT_803de3d2 = (ushort)iVar7;
    dVar19 = (double)FUN_80294b54();
    iVar7 = (int)((double)FLOAT_803dc6b8 * dVar19 + (double)FLOAT_803de43c);
    local_70 = (longlong)iVar7;
    DAT_803de3d4 = (ushort)iVar7;
    FLOAT_803dc6a4 = (float)(DOUBLE_803e2cf0 * (double)FLOAT_803de3e0);
    dVar22 = (double)FLOAT_803dc6a4;
    FLOAT_803dc69c =
         (float)-(DOUBLE_803e2cf0 * (DOUBLE_803e2be0 - (double)FLOAT_803de3e0) - DOUBLE_803e2cf8);
    dVar21 = (double)FLOAT_803dc69c;
    dVar23 = (double)FLOAT_803dc6a0;
    FUN_8011f234((double)FLOAT_803e2abc,dVar21,dVar23,dVar22,DAT_803de3d0,DAT_803de3d2,DAT_803de3d4)
    ;
    iVar7 = FUN_8002b660(DAT_803de4e0);
    FUN_8003ba50(0,0,0,0,DAT_803de4e0,1);
    *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
    dVar19 = FUN_80019c38();
    if (dVar19 == (double)FLOAT_803e2abc) {
      iVar7 = FUN_8002b660(iRam803de4e4);
      FUN_8003ba50(0,0,0,0,iRam803de4e4,1);
      *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
      FUN_8001b4f8(FUN_8011e974);
      DAT_803dc6f2 = 0xc0;
      FLOAT_803dc6f4 = FLOAT_803e2d20;
      dVar19 = (double)FUN_80019940(0xff,0xff,0xff,0xff);
      if (DAT_803de560 == DAT_803de456) {
        if ((DAT_803de424 != 0) && (1 < *(ushort *)(DAT_803de424 + 2))) {
          iVar7 = 0x96;
          iVar3 = 4;
          dVar26 = (double)FLOAT_803e2ae8;
          dVar24 = DOUBLE_803e2af8;
          dVar25 = DOUBLE_803e2d28;
          for (iVar16 = 1; iVar16 < (int)(uint)*(ushort *)(DAT_803de424 + 2); iVar16 = iVar16 + 1) {
            FUN_80015e00(*(undefined4 *)(*(int *)(DAT_803de424 + 8) + iVar3),0x79,0xf0,iVar7);
            FUN_800163fc(*(undefined4 *)(*(int *)(DAT_803de424 + 8) + iVar3),0x79,0,0,&local_a8,
                         &local_ac,&local_b0,&local_b4);
            local_58 = (double)CONCAT44(0x43300000,local_b4 - local_b0 ^ 0x80000000);
            dVar19 = (double)(float)(local_58 - dVar24);
            local_60 = (double)CONCAT44(0x43300000,uVar1 ^ 0x80000000);
            dVar18 = (double)(float)((double)(float)(dVar19 / (double)(float)(local_60 - dVar24)) +
                                    dVar25);
            if (dVar18 < dVar26) {
              dVar18 = dVar26;
            }
            local_68 = (double)(longlong)(int)dVar18;
            iVar7 = iVar7 + (int)dVar18 * (uint)uVar1;
            iVar3 = iVar3 + 4;
          }
        }
      }
      else {
        dVar19 = (double)FUN_80016848(dVar19,dVar21,dVar23,dVar22,param_5,param_6,param_7,param_8,
                                      0x515,200,0x96);
      }
      FUN_80016848(dVar19,dVar21,dVar23,dVar22,param_5,param_6,param_7,param_8,0x3de,200,0x154);
      DAT_803dc6f2 = 0x100;
      FUN_8001b4f8(0);
      FUN_8000f478(0);
      FUN_8000f584();
      FUN_8000fc5c((double)FLOAT_803de47c);
      FUN_8000fb20();
      FUN_8000f7a0();
    }
    else {
      uVar4 = FUN_80022264(0,0x1e);
      uVar5 = FUN_80022264(0,0x1e);
      FUN_8011ebbc((double)FLOAT_803e2d10,(double)FLOAT_803e2d14,DAT_803a9760,0xff,
                   (char)((int)(short)(int)fVar2 / 2),0x230,400,uVar5 << 1,uVar4 << 1);
      iVar7 = FUN_8002b660(iRam803de4e4);
      FUN_8003ba50(0,0,0,0,iRam803de4e4,1);
      *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
      FUN_8000f478(0);
      FUN_8000f584();
      FUN_8000fc5c((double)FLOAT_803de47c);
      FUN_8000fb20();
      FUN_8000f7a0();
    }
    break;
  case 5:
    FUN_801277dc();
    break;
  case 6:
  case 7:
  case 8:
  case 9:
  case 10:
    FUN_80129d10();
    iVar7 = (int)(FLOAT_803e2b40 * FLOAT_803de3e0);
    local_58 = (double)(longlong)iVar7;
    dVar19 = (double)FUN_80294964();
    FLOAT_803de4d0 = (float)dVar19;
    FLOAT_803de3c8 = FLOAT_803de3c8 + FLOAT_803dc074;
    dVar19 = (double)FUN_80294b54();
    local_60 = (double)(longlong)(int)((double)FLOAT_803dc6b4 * dVar19);
    DAT_803de3d0 = (ushort)(int)((double)FLOAT_803dc6b4 * dVar19);
    dVar19 = (double)FUN_80294b54();
    iVar16 = (int)((double)FLOAT_803de3cc * dVar19 + (double)FLOAT_803dc6bc);
    local_68 = (double)(longlong)iVar16;
    DAT_803de3d2 = (ushort)iVar16;
    dVar19 = (double)FUN_80294b54();
    iVar16 = (int)((double)FLOAT_803dc6b8 * dVar19 + (double)FLOAT_803de43c);
    local_70 = (longlong)iVar16;
    DAT_803de3d4 = (ushort)iVar16;
    FLOAT_803dc6a4 = (float)(DOUBLE_803e2cf0 * (double)FLOAT_803de3e0);
    dVar22 = (double)FLOAT_803dc6a4;
    FLOAT_803dc69c =
         (float)-(DOUBLE_803e2cf0 * (DOUBLE_803e2be0 - (double)FLOAT_803de3e0) - DOUBLE_803e2cf8);
    dVar21 = (double)FLOAT_803dc69c;
    dVar23 = (double)FLOAT_803dc6a0;
    FUN_8011f234((double)FLOAT_803e2abc,dVar21,dVar23,dVar22,DAT_803de3d0,DAT_803de3d2,DAT_803de3d4)
    ;
    iVar3 = FUN_8002b660(DAT_803de4e0);
    uVar13 = 1;
    iVar16 = DAT_803de4e0;
    FUN_8003ba50(0,0,0,0,DAT_803de4e0,1);
    *(ushort *)(iVar3 + 0x18) = *(ushort *)(iVar3 + 0x18) & 0xfff7;
    dVar19 = FUN_80019c38();
    if (dVar19 != (double)FLOAT_803e2abc) {
      uVar4 = FUN_80022264(0,0x1e);
      uVar5 = FUN_80022264(0,0x1e);
      FUN_8011ebbc((double)FLOAT_803e2d10,(double)FLOAT_803e2d14,DAT_803a9760,0xff,
                   (char)((int)(short)iVar7 / 2),0x230,400,uVar5 << 1,uVar4 << 1);
      iVar7 = FUN_8002b660(iRam803de4e4);
      FUN_8003ba50(0,0,0,0,iRam803de4e4,1);
      *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
      FUN_8000f478(0);
      FUN_8000f584();
      FUN_8000fc5c((double)FLOAT_803de47c);
      FUN_8000fb20();
      FUN_8000f7a0();
      break;
    }
    DAT_803de4a4 = (undefined2 *)&DAT_8031c980;
    FUN_801287ac(dVar19,dVar21,dVar23,dVar22,param_5,param_6,param_7,param_8);
    FUN_8001b4f8(FUN_8011e974);
    uVar9 = 0xff;
    uVar20 = FUN_80019940(0xff,0xff,0xff,0xff);
    DAT_803dc6f2 = 0x100;
    FLOAT_803dc6f4 = FLOAT_803e2d20;
    if (DAT_803de400 == 8) {
      iVar3 = (**(code **)(*DAT_803dd72c + 0x8c))();
      local_b8 = DAT_803e2a84;
      uVar20 = FUN_80016848(extraout_f1,dVar21,dVar23,dVar22,param_5,param_6,param_7,param_8,0x3e0,
                            200,0x118);
      FUN_8028fde8(uVar20,dVar21,dVar23,dVar22,param_5,param_6,param_7,param_8,(int)&local_b8,
                   &DAT_803dc7d0,(uint)*(byte *)(iVar3 + 9),uVar9,iVar16,uVar13,in_r9,in_r10);
      FLOAT_803dc6f4 = FLOAT_803e2ae4;
      FUN_80015e00(&local_b8,0x93,0x14a,0xdc);
      FLOAT_803dc6f4 = FLOAT_803e2d20;
      FUN_8011f088((double)FLOAT_803e2b4c,(double)FLOAT_803e2c98,DAT_803a9744,0x100,(char)iVar7,600,
                   0);
    }
    else if (DAT_803de400 < 8) {
      if (DAT_803de400 == 6) {
LAB_801270b8:
        FUN_80016848(uVar20,dVar21,dVar23,dVar22,param_5,param_6,param_7,param_8,0x3ce,200,0x96);
      }
      else if (5 < DAT_803de400) {
LAB_80127094:
        uVar20 = FUN_80016848(uVar20,dVar21,dVar23,dVar22,param_5,param_6,param_7,param_8,0x3cf,200,
                              0x109);
        FUN_80016848(uVar20,dVar21,dVar23,dVar22,param_5,param_6,param_7,param_8,0x3e1,200,0x96);
      }
    }
    else {
      if (DAT_803de400 == 10) goto LAB_801270b8;
      if (DAT_803de400 < 10) goto LAB_80127094;
    }
    FLOAT_803dc6f4 = FLOAT_803e2ae4;
    puVar6 = FUN_80017400(0x7f);
    FUN_800162c4(0x3cd,0,0,&local_a8,&local_ac,&local_b0,&local_b4);
    *(char *)(DAT_803de4a4 + 4) = (char)(local_ac - local_a8);
    local_58 = (double)CONCAT44(0x43300000,
                                (((int)*(short *)(puVar6 + 0x14) + (uint)*(ushort *)(puVar6 + 8)) -
                                (local_ac - local_a8 >> 1)) - 0x140 ^ 0x80000000);
    iVar7 = (int)(FLOAT_803dc6f4 * (float)(local_58 - DOUBLE_803e2af8) + FLOAT_803e2bb4);
    local_60 = (double)(longlong)iVar7;
    DAT_803de4a4[1] = (short)iVar7;
    puVar6 = FUN_80017400(0x80);
    FUN_800162c4(0x3cc,0,0,&local_a8,&local_ac,&local_b0,&local_b4);
    *(char *)(DAT_803de4a4 + 0x14) = (char)(local_ac - local_a8);
    dVar19 = (double)FLOAT_803dc6f4;
    local_68 = (double)CONCAT44(0x43300000,
                                (int)*(short *)(puVar6 + 0x14) + (local_ac - local_a8 >> 1) + -0x140
                                ^ 0x80000000);
    iVar7 = (int)(dVar19 * (double)(float)(local_68 - DOUBLE_803e2af8) + (double)FLOAT_803e2bb4);
    local_70 = (longlong)iVar7;
    DAT_803de4a4[0x11] = (short)iVar7;
    if (DAT_803de458 == 0) {
      uVar20 = FUN_80019940(0xff,0xff,0xff,0xff);
    }
    else {
      uVar20 = FUN_80019940(0x96,0x96,0x96,0xff);
    }
    FUN_80016848(uVar20,dVar19,dVar23,dVar22,param_5,param_6,param_7,param_8,0x3cd,0,200);
    if (DAT_803de458 == 0) {
      uVar20 = FUN_80019940(0x96,0x96,0x96,0xff);
    }
    else {
      uVar20 = FUN_80019940(0xff,0xff,0xff,0xff);
    }
    FUN_80016848(uVar20,dVar19,dVar23,dVar22,param_5,param_6,param_7,param_8,0x3cc,0,200);
    FUN_8001b4f8(0);
    iVar7 = FUN_8002b660(iRam803de4e4);
    FUN_8003ba50(0,0,0,0,iRam803de4e4,1);
    *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
    FUN_8000f478(0);
    FUN_8000f584();
    FUN_8000fc5c((double)FLOAT_803de47c);
    FUN_8000fb20();
    FUN_8000f7a0();
    break;
  case 0xb:
    dVar19 = (double)FUN_80294964();
    FLOAT_803de4d0 = (float)dVar19;
    FLOAT_803de3c8 = FLOAT_803de3c8 + FLOAT_803dc074;
    dVar19 = (double)FUN_80294b54();
    local_58 = (double)(longlong)(int)((double)FLOAT_803dc6b4 * dVar19);
    DAT_803de3d0 = (ushort)(int)((double)FLOAT_803dc6b4 * dVar19);
    dVar19 = (double)FUN_80294b54();
    iVar7 = (int)((double)FLOAT_803de3cc * dVar19 + (double)FLOAT_803dc6bc);
    local_60 = (double)(longlong)iVar7;
    DAT_803de3d2 = (ushort)iVar7;
    dVar19 = (double)FUN_80294b54();
    iVar7 = (int)((double)FLOAT_803dc6b8 * dVar19 + (double)FLOAT_803de43c);
    local_68 = (double)(longlong)iVar7;
    DAT_803de3d4 = (ushort)iVar7;
    FLOAT_803dc6a4 = (float)(DOUBLE_803e2cf0 * (double)FLOAT_803de3e0);
    dVar23 = (double)FLOAT_803dc6a4;
    FLOAT_803dc69c =
         (float)-(DOUBLE_803e2cf0 * (DOUBLE_803e2be0 - (double)FLOAT_803de3e0) - DOUBLE_803e2cf8);
    dVar19 = (double)FLOAT_803dc69c;
    dVar21 = (double)FLOAT_803dc6a0;
    FUN_8011f234((double)FLOAT_803e2abc,dVar19,dVar21,dVar23,DAT_803de3d0,DAT_803de3d2,DAT_803de3d4)
    ;
    iVar7 = FUN_8002b660(DAT_803de4e0);
    FUN_8003ba50(0,0,0,0,DAT_803de4e0,1);
    *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
    FUN_8001b4f8(FUN_8011e974);
    uVar20 = FUN_80019940(0xff,0xff,0xff,0xff);
    DAT_803dc6f2 = 0x100;
    FLOAT_803dc6f4 = FLOAT_803e2d20;
    if (DAT_803de3d8 == 1) {
      FUN_80016848(uVar20,dVar19,dVar21,dVar23,param_5,param_6,param_7,param_8,0x440,0,0x78);
      piVar10 = &local_a8;
      piVar11 = &local_ac;
      piVar14 = &local_b0;
      piVar15 = &local_b4;
      uVar20 = FUN_800162c4(0x440,0,0,piVar10,piVar11,piVar14,piVar15);
      iVar7 = local_b4 - local_b0;
      FUN_8028fde8(uVar20,dVar19,dVar21,dVar23,param_5,param_6,param_7,param_8,(int)auStack_a4,
                   &DAT_803dc7c0,(uint)(byte)(&DAT_8031bc84)[DAT_803de3d6 * 8],piVar10,piVar11,
                   piVar14,piVar15,in_r10);
      FUN_80015e00(auStack_a4,0x79,0,iVar7 + 0x7d);
      uVar20 = FUN_800163fc(auStack_a4,0x79,0,0,&local_a8,&local_ac,&local_b0,&local_b4);
      iVar7 = (local_b4 - local_b0) + iVar7;
      FUN_80016848(uVar20,dVar19,dVar21,dVar23,param_5,param_6,param_7,param_8,0x441,0,iVar7 + 0x82)
      ;
      uVar20 = FUN_800162c4(0x441,0,0,&local_a8,&local_ac,&local_b0,&local_b4);
      iVar7 = iVar7 + 10 + (local_b4 - local_b0);
      FUN_80016848(uVar20,dVar19,dVar21,dVar23,param_5,param_6,param_7,param_8,
                   (int)*(short *)(&DAT_8031bc86 + DAT_803de3d6 * 8),0,iVar7 + 0x78);
      uVar20 = FUN_800162c4((int)*(short *)(&DAT_8031bc86 + DAT_803de3d6 * 8),0,0,&local_a8,
                            &local_ac,&local_b0,&local_b4);
      iVar7 = (local_b4 - local_b0) + iVar7;
      FUN_80016848(uVar20,dVar19,dVar21,dVar23,param_5,param_6,param_7,param_8,0x442,0,iVar7 + 0x82)
      ;
      uVar20 = FUN_800162c4(0x442,0,0,&local_a8,&local_ac,&local_b0,&local_b4);
      FUN_80016848(uVar20,dVar19,dVar21,dVar23,param_5,param_6,param_7,param_8,0x43a,0,
                   (local_b4 - local_b0) + iVar7 + 0x8c);
    }
    else if (DAT_803de3d8 == 0) {
      FUN_80016848(uVar20,dVar19,dVar21,dVar23,param_5,param_6,param_7,param_8,0x43a,0,0xb4);
    }
    else if (DAT_803de3d8 < 3) {
      FUN_80016848(uVar20,dVar19,dVar21,dVar23,param_5,param_6,param_7,param_8,0x443,0,0xa0);
      uVar20 = FUN_800162c4(0x443,0,0,&local_a8,&local_ac,&local_b0,&local_b4);
      iVar7 = local_b4 - local_b0;
      FUN_80016848(uVar20,dVar19,dVar21,dVar23,param_5,param_6,param_7,param_8,
                   (int)*(short *)(&DAT_8031bc86 + DAT_803de3d6 * 8),0,iVar7 + 0xa5);
      uVar20 = FUN_800162c4((int)*(short *)(&DAT_8031bc86 + DAT_803de3d6 * 8),0,0,&local_a8,
                            &local_ac,&local_b0,&local_b4);
      FUN_80016848(uVar20,dVar19,dVar21,dVar23,param_5,param_6,param_7,param_8,0x444,0,
                   (local_b4 - local_b0) + iVar7 + 0xaf);
    }
    FUN_8001b4f8(0);
    iVar7 = FUN_8002b660(iRam803de4e4);
    FUN_8003ba50(0,0,0,0,iRam803de4e4,1);
    *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
    FUN_8000f478(0);
    FUN_8000f584();
    FUN_8000fc5c((double)FLOAT_803de47c);
    FUN_8000fb20();
    FUN_8000f7a0();
  }
  FUN_80286888();
  return;
}

