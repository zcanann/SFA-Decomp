// Function: FUN_800919c8
// Entry: 800919c8
// Size: 2632 bytes

/* WARNING: Removing unreachable block (ram,0x800923e8) */
/* WARNING: Removing unreachable block (ram,0x800923e0) */
/* WARNING: Removing unreachable block (ram,0x800923f0) */

void FUN_800919c8(undefined8 param_1,double param_2,double param_3)

{
  byte bVar1;
  float *pfVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  undefined2 uVar6;
  char cVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  undefined4 uVar11;
  double extraout_f1;
  undefined8 in_f29;
  double dVar12;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar13;
  double local_c8;
  double local_c0;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar13 = FUN_802860a8();
  pfVar2 = (float *)((ulonglong)uVar13 >> 0x20);
  uVar9 = (uint)*(ushort *)((int)pfVar2 + 0x26);
  dVar12 = extraout_f1;
  if ((&DAT_8039a828)[uVar9] != 0) {
    FUN_80090078(uVar9);
  }
  uVar3 = FUN_80023cc8(0x1454,0x17,0);
  (&DAT_8039a828)[uVar9] = uVar3;
  if ((&DAT_8039a828)[uVar9] == 0) {
    FUN_801378a8(s_warning_in_newcloud_dll_no_spare_8030f6b0);
  }
  else {
    FUN_800033a8((&DAT_8039a828)[uVar9],0,0x1454);
    *(uint *)((&DAT_8039a828)[uVar9] + 0x13f0) = uVar9;
    *(undefined *)((&DAT_8039a828)[uVar9] + 0x1453) = 0;
    *(uint *)((&DAT_8039a828)[uVar9] + 0x13f4) = (uint)*(byte *)(pfVar2 + 0x17);
    *(int *)(&DAT_8039a828)[uVar9] = (int)uVar13;
    *(undefined *)((&DAT_8039a828)[uVar9] + 0x144a) = *(undefined *)(pfVar2 + 0x16);
    *(undefined *)((&DAT_8039a828)[uVar9] + 0x144b) = *(undefined *)((int)pfVar2 + 0x59);
    *(float *)((&DAT_8039a828)[uVar9] + 0x140c) = (float)dVar12;
    *(float *)((&DAT_8039a828)[uVar9] + 0x1410) = (float)param_2;
    *(float *)((&DAT_8039a828)[uVar9] + 0x1414) = (float)param_3;
    if ((*(byte *)(pfVar2 + 0x16) & 1) != 0) {
      *(undefined *)((&DAT_8039a828)[uVar9] + 0x1451) = 1;
    }
    if ((*(byte *)(pfVar2 + 0x16) & 0x10) != 0) {
      *(undefined *)((&DAT_8039a828)[uVar9] + 0x144e) = 1;
    }
    *(undefined *)((&DAT_8039a828)[uVar9] + 0x1452) = 1;
    *(undefined *)((&DAT_8039a828)[uVar9] + 0x144d) = *(undefined *)((int)pfVar2 + 0x5d);
    iVar4 = (&DAT_8039a828)[uVar9];
    if (*(int *)(iVar4 + 0x13f4) == 0) {
      *(uint *)(iVar4 + 0x13fc) = (uint)*(ushort *)(pfVar2 + 10) << 3;
    }
    else {
      *(uint *)(iVar4 + 0x13fc) = (uint)*(ushort *)(pfVar2 + 10);
    }
    if (*(ushort *)((int)pfVar2 + 0x2a) == 0) {
      local_c0 = (double)CONCAT44(0x43300000,*(uint *)((&DAT_8039a828)[uVar9] + 0x13fc) ^ 0x80000000
                                 );
      *(float *)((&DAT_8039a828)[uVar9] + 0x142c) = (float)(local_c0 - DOUBLE_803df1a8);
    }
    else {
      local_c8 = (double)CONCAT44(0x43300000,*(uint *)((&DAT_8039a828)[uVar9] + 0x13fc) ^ 0x80000000
                                 );
      local_c0 = (double)CONCAT44(0x43300000,(uint)*(ushort *)((int)pfVar2 + 0x2a));
      *(float *)((&DAT_8039a828)[uVar9] + 0x142c) =
           (float)(local_c8 - DOUBLE_803df1a8) / (float)(local_c0 - DOUBLE_803df1b0);
    }
    if (*(ushort *)(pfVar2 + 0xb) == 0) {
      local_c0 = (double)CONCAT44(0x43300000,*(uint *)((&DAT_8039a828)[uVar9] + 0x13fc) ^ 0x80000000
                                 );
      *(float *)((&DAT_8039a828)[uVar9] + 0x1430) = (float)(local_c0 - DOUBLE_803df1a8);
    }
    else {
      local_c0 = (double)CONCAT44(0x43300000,*(uint *)((&DAT_8039a828)[uVar9] + 0x13fc) ^ 0x80000000
                                 );
      local_c8 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(pfVar2 + 0xb));
      *(float *)((&DAT_8039a828)[uVar9] + 0x1430) =
           (float)(local_c0 - DOUBLE_803df1a8) / (float)(local_c8 - DOUBLE_803df1b0);
    }
    *(float *)((&DAT_8039a828)[uVar9] + 0x1438) = pfVar2[2];
    iVar4 = (&DAT_8039a828)[uVar9];
    if (*(int *)(iVar4 + 0x13f4) == 0) {
      *(float *)(iVar4 + 0x1418) = FLOAT_803df234;
      *(float *)((&DAT_8039a828)[uVar9] + 0x141c) = FLOAT_803df238;
    }
    else {
      *(float *)(iVar4 + 0x1418) = pfVar2[1];
      *(float *)((&DAT_8039a828)[uVar9] + 0x141c) = FLOAT_803df1e4 * *pfVar2;
    }
    if (pfVar2[2] < FLOAT_803df1a4) {
      pfVar2[2] = FLOAT_803df1a0;
    }
    if (FLOAT_803df1a0 != pfVar2[2]) {
      *(float *)((&DAT_8039a828)[uVar9] + 0x1444) = FLOAT_803df23c;
      uVar5 = FUN_800221a0(1,(int)pfVar2[2]);
      local_c8 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      *(float *)((&DAT_8039a828)[uVar9] + 0x143c) =
           (float)(local_c8 - DOUBLE_803df1a8) * FLOAT_803df214;
    }
    *(undefined4 *)((&DAT_8039a828)[uVar9] + 0x1400) = 1;
    iVar4 = (&DAT_8039a828)[uVar9];
    bVar1 = *(byte *)(iVar4 + 0x144b);
    if ((bVar1 & 8) == 0) {
      if ((bVar1 & 0x10) == 0) {
        if ((bVar1 & 0x20) != 0) {
          *(undefined2 *)(iVar4 + 0x1448) = 100;
        }
      }
      else {
        *(undefined2 *)(iVar4 + 0x1448) = 200;
      }
    }
    else {
      *(undefined2 *)(iVar4 + 0x1448) = 800;
    }
    iVar4 = (&DAT_8039a828)[uVar9];
    FUN_8008fc9c((double)*(float *)(iVar4 + 0x1418),(double)*(float *)(iVar4 + 0x141c),iVar4 + 8,
                 uVar9);
    iVar4 = (&DAT_8039a828)[uVar9];
    FUN_8008fc00((double)*(float *)(iVar4 + 0x1418),(double)*(float *)(iVar4 + 0x141c),
                 iVar4 + 0x1378);
    uVar3 = FUN_80023cc8(*(int *)((&DAT_8039a828)[uVar9] + 0x13fc) * 0x18,0x17,0);
    *(undefined4 *)((&DAT_8039a828)[uVar9] + 4) = uVar3;
    if (*(int *)((&DAT_8039a828)[uVar9] + 4) == 0) {
      FUN_801378a8(s_warning_in_newclouds_dll_no_spar_8030f6f0);
      FUN_80023800((&DAT_8039a828)[uVar9]);
      (&DAT_8039a828)[uVar9] = 0;
    }
    else {
      iVar4 = 0;
      dVar12 = DOUBLE_803df1a8;
      for (iVar10 = 0; iVar8 = (&DAT_8039a828)[uVar9], iVar10 < *(int *)(iVar8 + 0x13fc);
          iVar10 = iVar10 + 1) {
        uVar5 = FUN_800221a0((int)*(float *)(iVar8 + 0x1378),(int)*(float *)(iVar8 + 0x139c));
        *(float *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4) =
             (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - dVar12);
        *(undefined4 *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 4) =
             *(undefined4 *)((&DAT_8039a828)[uVar9] + 5000);
        uVar5 = FUN_800221a0((int)*(float *)((&DAT_8039a828)[uVar9] + 0x1380),
                             (int)*(float *)((&DAT_8039a828)[uVar9] + 0x13b0));
        *(float *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 8) =
             (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - dVar12);
        uVar6 = FUN_800221a0(0,0x3d0);
        *(undefined2 *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 0x10) = uVar6;
        uVar6 = FUN_800221a0(0,0x13);
        *(undefined2 *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 0x12) = uVar6;
        if (*(int *)((&DAT_8039a828)[uVar9] + 0x13f4) == 0) {
          iVar8 = (uint)*(byte *)((int)pfVar2 + 0x5a) * 8;
          uVar5 = FUN_800221a0(*(undefined4 *)(&DAT_8030f558 + iVar8),
                               *(undefined4 *)(&DAT_8030f55c + iVar8));
          *(char *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 0x14) =
               (char)((int)uVar5 >> 2) + ((int)uVar5 < 0 && (uVar5 & 3) != 0);
          uVar5 = FUN_800221a0(0x4b,100);
          *(float *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 0xc) =
               (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803df1a8) /
               FLOAT_803df1fc;
          uVar5 = *(uint *)((&DAT_8039a828)[uVar9] + 0x13fc);
          *(char *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 0x16) =
               (char)(iVar10 / (int)(((int)uVar5 >> 2) + (uint)((int)uVar5 < 0 && (uVar5 & 3) != 0))
                     );
        }
        else {
          iVar8 = (uint)*(byte *)((int)pfVar2 + 0x5a) * 8;
          iVar8 = FUN_800221a0(*(undefined4 *)(&DAT_8030f558 + iVar8),
                               *(undefined4 *)(&DAT_8030f55c + iVar8));
          *(char *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 0x14) = (char)(iVar8 << 1);
          *(float *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 0xc) = FLOAT_803df1a4;
          *(undefined *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 0x16) = 0;
        }
        if (*(char *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 0x14) < '\x01') {
          *(undefined *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 0x14) = 1;
        }
        iVar8 = (uint)*(byte *)((int)pfVar2 + 0x5b) * 8;
        cVar7 = FUN_800221a0(*(undefined4 *)(&DAT_8030f530 + iVar8),
                             *(undefined4 *)(&DAT_8030f534 + iVar8));
        *(char *)(*(int *)((&DAT_8039a828)[uVar9] + 4) + iVar4 + 0x15) =
             (char)(*(int *)(&DAT_8030f534 + (uint)*(byte *)((int)pfVar2 + 0x5b) * 8) / 2) - cVar7;
        iVar4 = iVar4 + 0x18;
      }
      if (DAT_803db76c != 0) {
        DAT_8039a848 = 0x31e;
        DAT_8039a84c = 0xa9c;
        DAT_8039a850 = FLOAT_803df240;
        DAT_8039a854 = FLOAT_803df1a0;
        DAT_8039a858 = FLOAT_803df1a0;
        FUN_800701a4(&DAT_8039a850,&DAT_8039a854,&DAT_8039a858);
        DAT_8039a85c = FLOAT_803df1a4;
        DAT_8039a860 = 0;
        DAT_8039a864 = 0x3c5;
        DAT_8039a868 = 0xb72;
        DAT_8039a86c = FLOAT_803df1a0;
        DAT_8039a870 = FLOAT_803df1a0;
        DAT_8039a874 = FLOAT_803df240;
        FUN_800701a4(&DAT_8039a86c,&DAT_8039a870,&DAT_8039a874);
        DAT_8039a878 = FLOAT_803df1a4;
        DAT_8039a87c = 0;
        DAT_8039a880 = 0x335;
        DAT_8039a884 = 0xe13;
        DAT_8039a888 = FLOAT_803df1fc;
        DAT_8039a88c = FLOAT_803df1a0;
        DAT_8039a890 = FLOAT_803df1a0;
        FUN_800701a4(&DAT_8039a888,&DAT_8039a88c,&DAT_8039a890);
        DAT_8039a894 = FLOAT_803df1a4;
        DAT_8039a898 = 0;
        DAT_8039a89c = 0x254;
        DAT_8039a8a0 = 0xc70;
        DAT_8039a8a4 = FLOAT_803df1a0;
        DAT_8039a8a8 = FLOAT_803df1a0;
        DAT_8039a8ac = FLOAT_803df1fc;
        FUN_800701a4(&DAT_8039a8a4,&DAT_8039a8a8,&DAT_8039a8ac);
        DAT_8039a8b0 = FLOAT_803df1a4;
        DAT_8039a8b4 = 0;
        DAT_8039a8b8 = 0x107;
        DAT_8039a8bc = 0xb4a;
        DAT_8039a8c0 = FLOAT_803df1fc;
        DAT_8039a8c4 = FLOAT_803df1a0;
        DAT_8039a8c8 = FLOAT_803df1cc;
        FUN_800701a4(&DAT_8039a8c0,&DAT_8039a8c4,&DAT_8039a8c8);
        DAT_8039a8cc = FLOAT_803df1a4;
        DAT_8039a8d0 = 0;
        DAT_8039a8d4 = 0x68;
        DAT_8039a8d8 = 0xdf6;
        DAT_8039a8dc = FLOAT_803df1a0;
        DAT_8039a8e0 = FLOAT_803df1a0;
        DAT_8039a8e4 = FLOAT_803df240;
        FUN_800701a4(&DAT_8039a8dc,&DAT_8039a8e0,&DAT_8039a8e4);
        DAT_8039a8e8 = FLOAT_803df1a4;
        DAT_8039a8ec = 0;
        DAT_8039a848 = 0x31e;
        DAT_8039a84c = 0xa9c;
        DAT_8039a850 = FLOAT_803df1a0;
        DAT_8039a854 = FLOAT_803df1a0;
        DAT_8039a858 = FLOAT_803df1a0;
        DAT_8039a85c = FLOAT_803df1a0;
        DAT_8039a860 = 0;
        DAT_8039a864 = 0x3c5;
        DAT_8039a868 = 0xb72;
        DAT_8039a86c = FLOAT_803df1a0;
        DAT_8039a870 = FLOAT_803df1a0;
        DAT_8039a874 = FLOAT_803df1a0;
        DAT_8039a878 = FLOAT_803df1a0;
        DAT_8039a87c = 0;
        DAT_8039a880 = 0x335;
        DAT_8039a884 = 0xe13;
        DAT_8039a888 = FLOAT_803df1a0;
        DAT_8039a88c = FLOAT_803df1a0;
        DAT_8039a890 = FLOAT_803df1a0;
        DAT_8039a894 = FLOAT_803df1a0;
        DAT_8039a898 = 0;
        DAT_8039a89c = 0x254;
        DAT_8039a8a0 = 0xc70;
        DAT_8039a8a4 = FLOAT_803df1a0;
        DAT_8039a8a8 = FLOAT_803df1a0;
        DAT_8039a8ac = FLOAT_803df1a0;
        DAT_8039a8b0 = FLOAT_803df1a0;
        DAT_8039a8b4 = 0;
        DAT_8039a8b8 = 0x107;
        DAT_8039a8bc = 0xb4a;
        DAT_8039a8c0 = FLOAT_803df1a0;
        DAT_8039a8c4 = FLOAT_803df1a0;
        DAT_8039a8c8 = FLOAT_803df1a0;
        DAT_8039a8cc = FLOAT_803df1a0;
        DAT_8039a8d0 = 0;
        DAT_8039a8d4 = 0;
        DAT_8039a8d8 = 2000;
        DAT_8039a8dc = FLOAT_803df1a0;
        DAT_8039a8e0 = FLOAT_803df1a0;
        DAT_8039a8e4 = FLOAT_803df244;
        FUN_800701a4(&DAT_8039a8dc,&DAT_8039a8e0,&DAT_8039a8e4);
        DAT_8039a8e8 = FLOAT_803df1fc;
        DAT_8039a8ec = 0;
        DAT_803db76c = 0;
      }
    }
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  FUN_802860f4();
  return;
}

