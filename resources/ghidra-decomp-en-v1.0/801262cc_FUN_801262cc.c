// Function: FUN_801262cc
// Entry: 801262cc
// Size: 4564 bytes

/* WARNING: Removing unreachable block (ram,0x801271c8) */

void FUN_801262cc(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  float fVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  undefined8 uVar10;
  int local_a8;
  int local_a4;
  undefined auStack160 [4];
  undefined auStack156 [4];
  undefined4 local_98;
  int local_94;
  int local_90;
  undefined auStack140 [4];
  undefined auStack136 [4];
  undefined auStack132 [4];
  undefined auStack128 [4];
  int local_7c;
  int local_78;
  undefined auStack116 [12];
  longlong local_68;
  longlong local_60;
  longlong local_58;
  longlong local_50;
  undefined4 local_48;
  uint uStack68;
  longlong local_40;
  double local_38;
  double local_30;
  double local_28;
  
  uVar10 = FUN_802860dc();
  uVar4 = FUN_8002b9ec();
  FUN_8025d324(0,0,0x280,0x1e0);
  if (DAT_803dd780 != 0) {
    FUN_80076510((double)FLOAT_803e1e3c,(double)FLOAT_803e1e3c,0x280,0x1e0);
  }
  switch(DAT_803dd780) {
  case 0:
    FUN_8012975c((int)((ulonglong)uVar10 >> 0x20),(int)uVar10,param_3);
    break;
  case 1:
    FUN_80019908(0xff,0xff,0xff,0xff);
    FUN_80019970(0xb);
    FUN_80016810(0x3dd,200,300);
  case 2:
    FUN_801299d4();
    break;
  case 3:
    FUN_801299d4();
    fVar2 = FLOAT_803e1ec0 * FLOAT_803dd760;
    local_68 = (longlong)(int)fVar2;
    dVar9 = (double)FUN_80294204((double)((FLOAT_803e1ec8 * FLOAT_803dd7bc) / FLOAT_803e1e94));
    FLOAT_803dd850 = (float)dVar9;
    FLOAT_803dd748 = FLOAT_803dd748 + FLOAT_803db414;
    dVar9 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba40));
    local_60 = (longlong)(int)((double)FLOAT_803dba4c * dVar9);
    DAT_803dd750 = (undefined2)(int)((double)FLOAT_803dba4c * dVar9);
    dVar9 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba44));
    iVar7 = (int)((double)FLOAT_803dd74c * dVar9 + (double)FLOAT_803dba54);
    local_58 = (longlong)iVar7;
    DAT_803dd752 = (undefined2)iVar7;
    dVar9 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba48));
    uVar3 = (uint)((double)FLOAT_803dba50 * dVar9 + (double)FLOAT_803dd7bc);
    local_50 = (longlong)(int)uVar3;
    DAT_803dd754 = (undefined2)uVar3;
    FLOAT_803dba3c = (float)(DOUBLE_803e2070 * (double)FLOAT_803dd760);
    FLOAT_803dba34 =
         (float)-(DOUBLE_803e2070 * (DOUBLE_803e1f60 - (double)FLOAT_803dd760) - DOUBLE_803e2078);
    FUN_8011ef50((double)FLOAT_803e1e3c,(double)FLOAT_803dba34,(double)FLOAT_803dba38,DAT_803dd750,
                 DAT_803dd752,uVar3 & 0xffff);
    iVar7 = FUN_8002b588(DAT_803dd860);
    FUN_8003b958(0,0,0,0,DAT_803dd860,1);
    *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
    uStack68 = (int)(short)(int)fVar2 ^ 0x80000000;
    local_48 = 0x43300000;
    iVar7 = (int)((float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e1e78) * FLOAT_803dd850)
    ;
    local_40 = (longlong)iVar7;
    local_38 = (double)CONCAT44(0x43300000,(int)(short)iVar7 ^ 0x80000000);
    local_30 = (double)CONCAT44(0x43300000,(int)DAT_803dd75c ^ 0x80000000);
    uVar3 = (uint)((local_38 - DOUBLE_803e1e78) * (DOUBLE_803e2080 - (local_30 - DOUBLE_803e1e78)) *
                  DOUBLE_803e2088);
    local_28 = (double)(longlong)(int)uVar3;
    dVar9 = (double)FUN_80019c00();
    if (dVar9 == (double)FLOAT_803e1e3c) {
      if (DAT_803dd7c4 == '\0') {
        if (DAT_803dd7c8 == 0) {
          DAT_803dd7c8 = FUN_80054d54(0xbe7);
        }
        if (DAT_803dd7c8 != 0) {
          local_28 = (double)(longlong)(int)FLOAT_803e209c;
          FUN_8011eda4((double)FLOAT_803e1e80,(double)FLOAT_803e2098,DAT_803dd7c8,
                       0x96 - DAT_803dd75c,uVar3 & 0xff,(int)FLOAT_803e209c,0);
        }
      }
      FUN_80127f24(uVar3);
      if (DAT_803dd7c4 == '\0') {
        DAT_803dd824 = &DAT_8031b818;
      }
      else {
        DAT_803dd824 = &DAT_8031b9f0;
      }
      FUN_80128470(iVar7);
      iVar7 = FUN_8002b588(uRam803dd864);
      FUN_8003b958(0,0,0,0,uRam803dd864,1);
      *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
      FUN_8000f458(0);
      FUN_8000f564();
      FUN_8000fc3c((double)FLOAT_803dd7fc);
      FUN_8000fb00();
      FUN_8000f780();
      FUN_8025d324(0,0,0x280,0x1e0);
    }
    else {
      iVar6 = FUN_800221a0(0,0x1e);
      iVar8 = FUN_800221a0(0,0x1e);
      FUN_8011e8d8((double)FLOAT_803e2090,(double)FLOAT_803e2094,DAT_803a8b00,0xff,
                   (int)(short)iVar7 / 2 & 0xff,0x230,400,iVar8 << 1,iVar6 << 1);
      iVar7 = FUN_8002b588(uRam803dd864);
      FUN_8003b958(0,0,0,0,uRam803dd864,1);
      *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
      FUN_8000f458(0);
      FUN_8000f564();
      FUN_8000fc3c((double)FLOAT_803dd7fc);
      FUN_8000fb00();
      FUN_8000f780();
    }
    break;
  case 4:
    FUN_801299d4();
    fVar2 = FLOAT_803e1ec0 * FLOAT_803dd760;
    local_28 = (double)(longlong)(int)fVar2;
    dVar9 = (double)FUN_80294204((double)((FLOAT_803e1ec8 * FLOAT_803dd7bc) / FLOAT_803e1e94));
    FLOAT_803dd850 = (float)dVar9;
    FLOAT_803dd748 = FLOAT_803dd748 + FLOAT_803db414;
    dVar9 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba40));
    local_30 = (double)(longlong)(int)((double)FLOAT_803dba4c * dVar9);
    DAT_803dd750 = (undefined2)(int)((double)FLOAT_803dba4c * dVar9);
    dVar9 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba44));
    iVar7 = (int)((double)FLOAT_803dd74c * dVar9 + (double)FLOAT_803dba54);
    local_38 = (double)(longlong)iVar7;
    DAT_803dd752 = (undefined2)iVar7;
    dVar9 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba48));
    uVar3 = (uint)((double)FLOAT_803dba50 * dVar9 + (double)FLOAT_803dd7bc);
    local_40 = (longlong)(int)uVar3;
    DAT_803dd754 = (undefined2)uVar3;
    FLOAT_803dba3c = (float)(DOUBLE_803e2070 * (double)FLOAT_803dd760);
    FLOAT_803dba34 =
         (float)-(DOUBLE_803e2070 * (DOUBLE_803e1f60 - (double)FLOAT_803dd760) - DOUBLE_803e2078);
    FUN_8011ef50((double)FLOAT_803e1e3c,(double)FLOAT_803dba34,(double)FLOAT_803dba38,DAT_803dd750,
                 DAT_803dd752,uVar3 & 0xffff);
    iVar7 = FUN_8002b588(DAT_803dd860);
    FUN_8003b958(0,0,0,0,DAT_803dd860,1);
    *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
    dVar9 = (double)FUN_80019c00();
    if (dVar9 == (double)FLOAT_803e1e3c) {
      iVar7 = FUN_8002b588(uRam803dd864);
      FUN_8003b958(0,0,0,0,uRam803dd864,1);
      *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
      FUN_8001b444(FUN_8011e690);
      DAT_803dba8a = 0xc0;
      FLOAT_803dba8c = FLOAT_803e20a0;
      FUN_80019908(0xff,0xff,0xff,0xff);
      if (DAT_803dd8e0 == DAT_803dd7d6) {
        if ((DAT_803dd7a4 != 0) && (1 < *(ushort *)(DAT_803dd7a4 + 2))) {
          iVar7 = 0x96;
          iVar8 = 4;
          for (iVar6 = 1; iVar6 < (int)(uint)*(ushort *)(DAT_803dd7a4 + 2); iVar6 = iVar6 + 1) {
            FUN_80015dc8(*(undefined4 *)(*(int *)(DAT_803dd7a4 + 8) + iVar8),0x79,0xf0,iVar7);
            FUN_800163c4(*(undefined4 *)(*(int *)(DAT_803dd7a4 + 8) + iVar8),0x79,0,0,auStack136,
                         auStack140,&local_90,&local_94);
            iVar5 = FUN_80019bf8();
            uVar3 = local_94 - local_90;
            if ((int)uVar3 <=
                (int)(uint)(ushort)(&DAT_802c868a)[(uint)(byte)(&DAT_802c73d4)[iVar5 * 8] * 8]) {
              iVar5 = FUN_80019bf8();
              uVar3 = (uint)(ushort)(&DAT_802c868a)[(uint)(byte)(&DAT_802c73d4)[iVar5 * 8] * 8];
            }
            iVar7 = iVar7 + uVar3;
            iVar8 = iVar8 + 4;
          }
        }
      }
      else {
        FUN_80016810(0x515,200,0x96);
      }
      FUN_80016810(0x3de,200,0x154);
      DAT_803dba8a = 0x100;
      FUN_8001b444(0);
      FUN_8000f458(0);
      FUN_8000f564();
      FUN_8000fc3c((double)FLOAT_803dd7fc);
      FUN_8000fb00();
      FUN_8000f780();
    }
    else {
      iVar7 = FUN_800221a0(0,0x1e);
      iVar6 = FUN_800221a0(0,0x1e);
      FUN_8011e8d8((double)FLOAT_803e2090,(double)FLOAT_803e2094,DAT_803a8b00,0xff,
                   (int)(short)(int)fVar2 / 2 & 0xff,0x230,400,iVar6 << 1,iVar7 << 1);
      iVar7 = FUN_8002b588(uRam803dd864);
      FUN_8003b958(0,0,0,0,uRam803dd864,1);
      *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
      FUN_8000f458(0);
      FUN_8000f564();
      FUN_8000fc3c((double)FLOAT_803dd7fc);
      FUN_8000fb00();
      FUN_8000f780();
    }
    break;
  case 5:
    FUN_801274a0(uVar4);
    break;
  case 6:
  case 7:
  case 8:
  case 9:
  case 10:
    FUN_801299d4();
    uVar3 = (uint)(FLOAT_803e1ec0 * FLOAT_803dd760);
    local_28 = (double)(longlong)(int)uVar3;
    dVar9 = (double)FUN_80294204((double)((FLOAT_803e1ec8 * FLOAT_803dd7bc) / FLOAT_803e1e94));
    FLOAT_803dd850 = (float)dVar9;
    FLOAT_803dd748 = FLOAT_803dd748 + FLOAT_803db414;
    dVar9 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba40));
    local_30 = (double)(longlong)(int)((double)FLOAT_803dba4c * dVar9);
    DAT_803dd750 = (undefined2)(int)((double)FLOAT_803dba4c * dVar9);
    dVar9 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba44));
    iVar7 = (int)((double)FLOAT_803dd74c * dVar9 + (double)FLOAT_803dba54);
    local_38 = (double)(longlong)iVar7;
    DAT_803dd752 = (undefined2)iVar7;
    dVar9 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba48));
    uVar1 = (uint)((double)FLOAT_803dba50 * dVar9 + (double)FLOAT_803dd7bc);
    local_40 = (longlong)(int)uVar1;
    DAT_803dd754 = (undefined2)uVar1;
    FLOAT_803dba3c = (float)(DOUBLE_803e2070 * (double)FLOAT_803dd760);
    FLOAT_803dba34 =
         (float)-(DOUBLE_803e2070 * (DOUBLE_803e1f60 - (double)FLOAT_803dd760) - DOUBLE_803e2078);
    FUN_8011ef50((double)FLOAT_803e1e3c,(double)FLOAT_803dba34,(double)FLOAT_803dba38,DAT_803dd750,
                 DAT_803dd752,uVar1 & 0xffff);
    iVar7 = FUN_8002b588(DAT_803dd860);
    FUN_8003b958(0,0,0,0,DAT_803dd860,1);
    *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
    dVar9 = (double)FUN_80019c00();
    if (dVar9 != (double)FLOAT_803e1e3c) {
      iVar7 = FUN_800221a0(0,0x1e);
      iVar6 = FUN_800221a0(0,0x1e);
      FUN_8011e8d8((double)FLOAT_803e2090,(double)FLOAT_803e2094,DAT_803a8b00,0xff,
                   (int)(short)uVar3 / 2 & 0xff,0x230,400,iVar6 << 1,iVar7 << 1);
      iVar7 = FUN_8002b588(uRam803dd864);
      FUN_8003b958(0,0,0,0,uRam803dd864,1);
      *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
      FUN_8000f458(0);
      FUN_8000f564();
      FUN_8000fc3c((double)FLOAT_803dd7fc);
      FUN_8000fb00();
      FUN_8000f780();
      break;
    }
    DAT_803dd824 = &DAT_8031bd30;
    FUN_80128470(uVar3);
    FUN_8001b444(FUN_8011e690);
    FUN_80019908(0xff,0xff,0xff,0xff);
    DAT_803dba8a = 0x100;
    FLOAT_803dba8c = FLOAT_803e20a0;
    if (DAT_803dd780 == 8) {
      iVar7 = (**(code **)(*DAT_803dcaac + 0x8c))();
      local_98 = DAT_803e1e04;
      FUN_80016810(0x3e0,200,0x118);
      FUN_8028f688(&local_98,&DAT_803dbb68,*(undefined *)(iVar7 + 9));
      FLOAT_803dba8c = FLOAT_803e1e64;
      FUN_80015dc8(&local_98,0x93,0x14a,0xdc);
      FLOAT_803dba8c = FLOAT_803e20a0;
      FUN_8011eda4((double)FLOAT_803e1ecc,(double)FLOAT_803e2018,DAT_803a8ae4,0x100,uVar3 & 0xff,600
                   ,0);
    }
    else if (DAT_803dd780 < 8) {
      if (DAT_803dd780 == 6) {
LAB_80126d94:
        FUN_80016810(0x3ce,200,0x96);
      }
      else if (5 < DAT_803dd780) {
LAB_80126d70:
        FUN_80016810(0x3cf,200,0x118);
        FUN_80016810(0x3e1,200,0x96);
      }
    }
    else {
      if (DAT_803dd780 == 10) goto LAB_80126d94;
      if (DAT_803dd780 < 10) goto LAB_80126d70;
    }
    FLOAT_803dba8c = FLOAT_803e1e64;
    iVar7 = FUN_800173c8(0x7f);
    FUN_8001628c(0x3cd,0,0,&local_78,&local_7c,auStack128,auStack132);
    DAT_803dd824[8] = (char)(local_7c - local_78);
    local_28 = (double)CONCAT44(0x43300000,
                                (((int)*(short *)(iVar7 + 0x14) + (uint)*(ushort *)(iVar7 + 8)) -
                                (local_7c - local_78 >> 1)) - 0x140 ^ 0x80000000);
    iVar7 = (int)(FLOAT_803dba8c * (float)(local_28 - DOUBLE_803e1e78) + FLOAT_803e1f34);
    local_30 = (double)(longlong)iVar7;
    *(short *)(DAT_803dd824 + 2) = (short)iVar7;
    iVar7 = FUN_800173c8(0x80);
    FUN_8001628c(0x3cc,0,0,&local_78,&local_7c,auStack128,auStack132);
    DAT_803dd824[0x28] = (char)(local_7c - local_78);
    local_38 = (double)CONCAT44(0x43300000,
                                (int)*(short *)(iVar7 + 0x14) + (local_7c - local_78 >> 1) + -0x140
                                ^ 0x80000000);
    iVar7 = (int)(FLOAT_803dba8c * (float)(local_38 - DOUBLE_803e1e78) + FLOAT_803e1f34);
    local_40 = (longlong)iVar7;
    *(short *)(DAT_803dd824 + 0x22) = (short)iVar7;
    if (DAT_803dd7d8 == 0) {
      FUN_80019908(0xff,0xff,0xff,0xff);
    }
    else {
      FUN_80019908(0x96,0x96,0x96,0xff);
    }
    FUN_80016810(0x3cd,0,200);
    if (DAT_803dd7d8 == 0) {
      FUN_80019908(0x96,0x96,0x96,0xff);
    }
    else {
      FUN_80019908(0xff,0xff,0xff,0xff);
    }
    FUN_80016810(0x3cc,0,200);
    FUN_8001b444(0);
    iVar7 = FUN_8002b588(uRam803dd864);
    FUN_8003b958(0,0,0,0,uRam803dd864,1);
    *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
    FUN_8000f458(0);
    FUN_8000f564();
    FUN_8000fc3c((double)FLOAT_803dd7fc);
    FUN_8000fb00();
    FUN_8000f780();
    break;
  case 0xb:
    dVar9 = (double)FUN_80294204((double)((FLOAT_803e1ec8 * FLOAT_803dd7bc) / FLOAT_803e1e94));
    FLOAT_803dd850 = (float)dVar9;
    FLOAT_803dd748 = FLOAT_803dd748 + FLOAT_803db414;
    dVar9 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba40));
    local_28 = (double)(longlong)(int)((double)FLOAT_803dba4c * dVar9);
    DAT_803dd750 = (undefined2)(int)((double)FLOAT_803dba4c * dVar9);
    dVar9 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba44));
    iVar7 = (int)((double)FLOAT_803dd74c * dVar9 + (double)FLOAT_803dba54);
    local_30 = (double)(longlong)iVar7;
    DAT_803dd752 = (undefined2)iVar7;
    dVar9 = (double)FUN_802943f4((double)(FLOAT_803dd748 * FLOAT_803dba48));
    uVar3 = (uint)((double)FLOAT_803dba50 * dVar9 + (double)FLOAT_803dd7bc);
    local_38 = (double)(longlong)(int)uVar3;
    DAT_803dd754 = (undefined2)uVar3;
    FLOAT_803dba3c = (float)(DOUBLE_803e2070 * (double)FLOAT_803dd760);
    FLOAT_803dba34 =
         (float)-(DOUBLE_803e2070 * (DOUBLE_803e1f60 - (double)FLOAT_803dd760) - DOUBLE_803e2078);
    FUN_8011ef50((double)FLOAT_803e1e3c,(double)FLOAT_803dba34,(double)FLOAT_803dba38,DAT_803dd750,
                 DAT_803dd752,uVar3 & 0xffff);
    iVar7 = FUN_8002b588(DAT_803dd860);
    FUN_8003b958(0,0,0,0,DAT_803dd860,1);
    *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
    FUN_8001b444(FUN_8011e690);
    FUN_80019908(0xff,0xff,0xff,0xff);
    DAT_803dba8a = 0x100;
    FLOAT_803dba8c = FLOAT_803e20a0;
    if (DAT_803dd758 == 1) {
      FUN_80016810(0x440,0,0x78);
      FUN_8001628c(0x440,0,0,auStack156,auStack160,&local_a4,&local_a8);
      iVar7 = local_a8 - local_a4;
      FUN_8028f688(auStack116,&DAT_803dbb58,(&DAT_8031b034)[DAT_803dd756 * 8]);
      FUN_80015dc8(auStack116,0x79,0,iVar7 + 0x7d);
      FUN_800163c4(auStack116,0x79,0,0,auStack156,auStack160,&local_a4,&local_a8);
      iVar7 = (local_a8 - local_a4) + iVar7;
      FUN_80016810(0x441,0,iVar7 + 0x82);
      FUN_8001628c(0x441,0,0,auStack156,auStack160,&local_a4,&local_a8);
      iVar7 = iVar7 + 10 + (local_a8 - local_a4);
      FUN_80016810((int)*(short *)(&DAT_8031b036 + DAT_803dd756 * 8),0,iVar7 + 0x78);
      FUN_8001628c((int)*(short *)(&DAT_8031b036 + DAT_803dd756 * 8),0,0,auStack156,auStack160,
                   &local_a4,&local_a8);
      iVar7 = (local_a8 - local_a4) + iVar7;
      FUN_80016810(0x442,0,iVar7 + 0x82);
      FUN_8001628c(0x442,0,0,auStack156,auStack160,&local_a4,&local_a8);
      FUN_80016810(0x43a,0,(local_a8 - local_a4) + iVar7 + 0x8c);
    }
    else if (DAT_803dd758 == 0) {
      FUN_80016810(0x43a,0,0xb4);
    }
    else if (DAT_803dd758 < 3) {
      FUN_80016810(0x443,0,0xa0);
      FUN_8001628c(0x443,0,0,auStack156,auStack160,&local_a4,&local_a8);
      iVar7 = local_a8 - local_a4;
      FUN_80016810((int)*(short *)(&DAT_8031b036 + DAT_803dd756 * 8),0,iVar7 + 0xa5);
      FUN_8001628c((int)*(short *)(&DAT_8031b036 + DAT_803dd756 * 8),0,0,auStack156,auStack160,
                   &local_a4,&local_a8);
      FUN_80016810(0x444,0,(local_a8 - local_a4) + iVar7 + 0xaf);
    }
    FUN_8001b444(0);
    iVar7 = FUN_8002b588(uRam803dd864);
    FUN_8003b958(0,0,0,0,uRam803dd864,1);
    *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
    FUN_8000f458(0);
    FUN_8000f564();
    FUN_8000fc3c((double)FLOAT_803dd7fc);
    FUN_8000fb00();
    FUN_8000f780();
  }
  FUN_80286128();
  return;
}

