// Function: FUN_80091c54
// Entry: 80091c54
// Size: 2632 bytes

/* WARNING: Removing unreachable block (ram,0x8009267c) */
/* WARNING: Removing unreachable block (ram,0x80092674) */
/* WARNING: Removing unreachable block (ram,0x8009266c) */
/* WARNING: Removing unreachable block (ram,0x80091c74) */
/* WARNING: Removing unreachable block (ram,0x80091c6c) */
/* WARNING: Removing unreachable block (ram,0x80091c64) */

void FUN_80091c54(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  float *pfVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  uint uVar9;
  double extraout_f1;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 uVar14;
  undefined8 local_c8;
  undefined8 local_c0;
  
  uVar14 = FUN_8028680c();
  pfVar2 = (float *)((ulonglong)uVar14 >> 0x20);
  uVar9 = (uint)*(ushort *)((int)pfVar2 + 0x26);
  dVar10 = extraout_f1;
  dVar11 = extraout_f1;
  dVar12 = param_2;
  dVar13 = param_3;
  if ((&DAT_8039b488)[uVar9] != 0) {
    dVar10 = (double)FUN_80090304(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,
                                  param_8,uVar9,(int)uVar14,param_11,param_12,param_13,param_14,
                                  param_15,param_16);
  }
  uVar5 = 0x17;
  uVar8 = 0;
  iVar3 = FUN_80023d8c(0x1454,0x17);
  (&DAT_8039b488)[uVar9] = iVar3;
  if ((&DAT_8039b488)[uVar9] == 0) {
    FUN_80137c30(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 s_warning_in_newcloud_dll_no_spare_80310270,uVar5,uVar8,param_12,param_13,param_14,
                 param_15,param_16);
  }
  else {
    FUN_800033a8((&DAT_8039b488)[uVar9],0,0x1454);
    *(uint *)((&DAT_8039b488)[uVar9] + 0x13f0) = uVar9;
    *(undefined *)((&DAT_8039b488)[uVar9] + 0x1453) = 0;
    *(uint *)((&DAT_8039b488)[uVar9] + 0x13f4) = (uint)*(byte *)(pfVar2 + 0x17);
    *(int *)(&DAT_8039b488)[uVar9] = (int)uVar14;
    *(undefined *)((&DAT_8039b488)[uVar9] + 0x144a) = *(undefined *)(pfVar2 + 0x16);
    *(undefined *)((&DAT_8039b488)[uVar9] + 0x144b) = *(undefined *)((int)pfVar2 + 0x59);
    *(float *)((&DAT_8039b488)[uVar9] + 0x140c) = (float)dVar11;
    *(float *)((&DAT_8039b488)[uVar9] + 0x1410) = (float)dVar12;
    *(float *)((&DAT_8039b488)[uVar9] + 0x1414) = (float)dVar13;
    if ((*(byte *)(pfVar2 + 0x16) & 1) != 0) {
      *(undefined *)((&DAT_8039b488)[uVar9] + 0x1451) = 1;
    }
    if ((*(byte *)(pfVar2 + 0x16) & 0x10) != 0) {
      *(undefined *)((&DAT_8039b488)[uVar9] + 0x144e) = 1;
    }
    *(undefined *)((&DAT_8039b488)[uVar9] + 0x1452) = 1;
    *(undefined *)((&DAT_8039b488)[uVar9] + 0x144d) = *(undefined *)((int)pfVar2 + 0x5d);
    iVar3 = (&DAT_8039b488)[uVar9];
    if (*(int *)(iVar3 + 0x13f4) == 0) {
      *(uint *)(iVar3 + 0x13fc) = (uint)*(ushort *)(pfVar2 + 10) << 3;
    }
    else {
      *(uint *)(iVar3 + 0x13fc) = (uint)*(ushort *)(pfVar2 + 10);
    }
    if (*(ushort *)((int)pfVar2 + 0x2a) == 0) {
      local_c0 = (double)CONCAT44(0x43300000,*(uint *)((&DAT_8039b488)[uVar9] + 0x13fc) ^ 0x80000000
                                 );
      *(float *)((&DAT_8039b488)[uVar9] + 0x142c) = (float)(local_c0 - DOUBLE_803dfe28);
    }
    else {
      local_c8 = (double)CONCAT44(0x43300000,*(uint *)((&DAT_8039b488)[uVar9] + 0x13fc) ^ 0x80000000
                                 );
      local_c0 = (double)CONCAT44(0x43300000,(uint)*(ushort *)((int)pfVar2 + 0x2a));
      *(float *)((&DAT_8039b488)[uVar9] + 0x142c) =
           (float)(local_c8 - DOUBLE_803dfe28) / (float)(local_c0 - DOUBLE_803dfe30);
    }
    if (*(ushort *)(pfVar2 + 0xb) == 0) {
      local_c0 = (double)CONCAT44(0x43300000,*(uint *)((&DAT_8039b488)[uVar9] + 0x13fc) ^ 0x80000000
                                 );
      *(float *)((&DAT_8039b488)[uVar9] + 0x1430) = (float)(local_c0 - DOUBLE_803dfe28);
    }
    else {
      local_c0 = (double)CONCAT44(0x43300000,*(uint *)((&DAT_8039b488)[uVar9] + 0x13fc) ^ 0x80000000
                                 );
      local_c8 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(pfVar2 + 0xb));
      *(float *)((&DAT_8039b488)[uVar9] + 0x1430) =
           (float)(local_c0 - DOUBLE_803dfe28) / (float)(local_c8 - DOUBLE_803dfe30);
    }
    *(float *)((&DAT_8039b488)[uVar9] + 0x1438) = pfVar2[2];
    iVar3 = (&DAT_8039b488)[uVar9];
    if (*(int *)(iVar3 + 0x13f4) == 0) {
      *(float *)(iVar3 + 0x1418) = FLOAT_803dfeb4;
      *(float *)((&DAT_8039b488)[uVar9] + 0x141c) = FLOAT_803dfeb8;
    }
    else {
      *(float *)(iVar3 + 0x1418) = pfVar2[1];
      *(float *)((&DAT_8039b488)[uVar9] + 0x141c) = FLOAT_803dfe64 * *pfVar2;
    }
    if (pfVar2[2] < FLOAT_803dfe24) {
      pfVar2[2] = FLOAT_803dfe20;
    }
    if (FLOAT_803dfe20 != pfVar2[2]) {
      *(float *)((&DAT_8039b488)[uVar9] + 0x1444) = FLOAT_803dfebc;
      uVar4 = FUN_80022264(1,(int)pfVar2[2]);
      local_c8 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      *(float *)((&DAT_8039b488)[uVar9] + 0x143c) =
           (float)(local_c8 - DOUBLE_803dfe28) * FLOAT_803dfe94;
    }
    *(undefined4 *)((&DAT_8039b488)[uVar9] + 0x1400) = 1;
    iVar3 = (&DAT_8039b488)[uVar9];
    bVar1 = *(byte *)(iVar3 + 0x144b);
    if ((bVar1 & 8) == 0) {
      if ((bVar1 & 0x10) == 0) {
        if ((bVar1 & 0x20) != 0) {
          *(undefined2 *)(iVar3 + 0x1448) = 100;
        }
      }
      else {
        *(undefined2 *)(iVar3 + 0x1448) = 200;
      }
    }
    else {
      *(undefined2 *)(iVar3 + 0x1448) = 800;
    }
    FUN_8008ff28((double)*(float *)((&DAT_8039b488)[uVar9] + 0x1418),
                 (double)*(float *)((&DAT_8039b488)[uVar9] + 0x141c),param_3,param_4,param_5,param_6
                 ,param_7,param_8);
    iVar3 = (&DAT_8039b488)[uVar9];
    dVar10 = (double)*(float *)(iVar3 + 0x141c);
    uVar14 = FUN_8008fe8c((double)*(float *)(iVar3 + 0x1418),dVar10,(float *)(iVar3 + 0x1378));
    uVar5 = 0;
    iVar3 = FUN_80023d8c(*(int *)((&DAT_8039b488)[uVar9] + 0x13fc) * 0x18,0x17);
    iVar6 = (&DAT_8039b488)[uVar9];
    *(int *)(iVar6 + 4) = iVar3;
    if (*(int *)((&DAT_8039b488)[uVar9] + 4) == 0) {
      FUN_80137c30(uVar14,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,
                   s_warning_in_newclouds_dll_no_spar_803102b0,iVar6,uVar5,param_12,param_13,
                   param_14,param_15,param_16);
      FUN_800238c4((&DAT_8039b488)[uVar9]);
      (&DAT_8039b488)[uVar9] = 0;
    }
    else {
      iVar3 = 0;
      dVar10 = DOUBLE_803dfe28;
      for (iVar6 = 0; iVar7 = (&DAT_8039b488)[uVar9], iVar6 < *(int *)(iVar7 + 0x13fc);
          iVar6 = iVar6 + 1) {
        uVar4 = FUN_80022264((int)*(float *)(iVar7 + 0x1378),(int)*(float *)(iVar7 + 0x139c));
        *(float *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3) =
             (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - dVar10);
        *(undefined4 *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 4) =
             *(undefined4 *)((&DAT_8039b488)[uVar9] + 5000);
        uVar4 = FUN_80022264((int)*(float *)((&DAT_8039b488)[uVar9] + 0x1380),
                             (int)*(float *)((&DAT_8039b488)[uVar9] + 0x13b0));
        *(float *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 8) =
             (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - dVar10);
        uVar4 = FUN_80022264(0,0x3d0);
        *(short *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 0x10) = (short)uVar4;
        uVar4 = FUN_80022264(0,0x13);
        *(short *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 0x12) = (short)uVar4;
        if (*(int *)((&DAT_8039b488)[uVar9] + 0x13f4) == 0) {
          iVar7 = (uint)*(byte *)((int)pfVar2 + 0x5a) * 8;
          uVar4 = FUN_80022264(*(uint *)(&DAT_80310118 + iVar7),*(uint *)(&DAT_8031011c + iVar7));
          *(char *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 0x14) =
               (char)((int)uVar4 >> 2) + ((int)uVar4 < 0 && (uVar4 & 3) != 0);
          uVar4 = FUN_80022264(0x4b,100);
          *(float *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 0xc) =
               (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803dfe28) /
               FLOAT_803dfe7c;
          uVar4 = *(uint *)((&DAT_8039b488)[uVar9] + 0x13fc);
          *(char *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 0x16) =
               (char)(iVar6 / (int)(((int)uVar4 >> 2) + (uint)((int)uVar4 < 0 && (uVar4 & 3) != 0)))
          ;
        }
        else {
          iVar7 = (uint)*(byte *)((int)pfVar2 + 0x5a) * 8;
          uVar4 = FUN_80022264(*(uint *)(&DAT_80310118 + iVar7),*(uint *)(&DAT_8031011c + iVar7));
          *(char *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 0x14) = (char)(uVar4 << 1);
          *(float *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 0xc) = FLOAT_803dfe24;
          *(undefined *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 0x16) = 0;
        }
        if (*(char *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 0x14) < '\x01') {
          *(undefined *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 0x14) = 1;
        }
        iVar7 = (uint)*(byte *)((int)pfVar2 + 0x5b) * 8;
        uVar4 = FUN_80022264(*(uint *)(&DAT_803100f0 + iVar7),*(uint *)(&DAT_803100f4 + iVar7));
        *(char *)(*(int *)((&DAT_8039b488)[uVar9] + 4) + iVar3 + 0x15) =
             (char)(*(int *)(&DAT_803100f4 + (uint)*(byte *)((int)pfVar2 + 0x5b) * 8) / 2) -
             (char)uVar4;
        iVar3 = iVar3 + 0x18;
      }
      if (DAT_803dc3cc != 0) {
        DAT_8039b4a8 = 0x31e;
        DAT_8039b4ac = 0xa9c;
        DAT_8039b4b0 = FLOAT_803dfec0;
        DAT_8039b4b4 = FLOAT_803dfe20;
        DAT_8039b4b8 = FLOAT_803dfe20;
        FUN_80070320(&DAT_8039b4b0,&DAT_8039b4b4,&DAT_8039b4b8);
        DAT_8039b4bc = FLOAT_803dfe24;
        DAT_8039b4c0 = 0;
        DAT_8039b4c4 = 0x3c5;
        DAT_8039b4c8 = 0xb72;
        DAT_8039b4cc = FLOAT_803dfe20;
        DAT_8039b4d0 = FLOAT_803dfe20;
        DAT_8039b4d4 = FLOAT_803dfec0;
        FUN_80070320(&DAT_8039b4cc,&DAT_8039b4d0,&DAT_8039b4d4);
        DAT_8039b4d8 = FLOAT_803dfe24;
        DAT_8039b4dc = 0;
        DAT_8039b4e0 = 0x335;
        DAT_8039b4e4 = 0xe13;
        DAT_8039b4e8 = FLOAT_803dfe7c;
        DAT_8039b4ec = FLOAT_803dfe20;
        DAT_8039b4f0 = FLOAT_803dfe20;
        FUN_80070320(&DAT_8039b4e8,&DAT_8039b4ec,&DAT_8039b4f0);
        DAT_8039b4f4 = FLOAT_803dfe24;
        DAT_8039b4f8 = 0;
        DAT_8039b4fc = 0x254;
        DAT_8039b500 = 0xc70;
        DAT_8039b504 = FLOAT_803dfe20;
        DAT_8039b508 = FLOAT_803dfe20;
        DAT_8039b50c = FLOAT_803dfe7c;
        FUN_80070320(&DAT_8039b504,&DAT_8039b508,&DAT_8039b50c);
        DAT_8039b510 = FLOAT_803dfe24;
        DAT_8039b514 = 0;
        DAT_8039b518 = 0x107;
        DAT_8039b51c = 0xb4a;
        DAT_8039b520 = FLOAT_803dfe7c;
        DAT_8039b524 = FLOAT_803dfe20;
        DAT_8039b528 = FLOAT_803dfe4c;
        FUN_80070320(&DAT_8039b520,&DAT_8039b524,&DAT_8039b528);
        DAT_8039b52c = FLOAT_803dfe24;
        DAT_8039b530 = 0;
        DAT_8039b534 = 0x68;
        DAT_8039b538 = 0xdf6;
        DAT_8039b53c = FLOAT_803dfe20;
        DAT_8039b540 = FLOAT_803dfe20;
        DAT_8039b544 = FLOAT_803dfec0;
        FUN_80070320(&DAT_8039b53c,&DAT_8039b540,&DAT_8039b544);
        DAT_8039b548 = FLOAT_803dfe24;
        DAT_8039b54c = 0;
        DAT_8039b4a8 = 0x31e;
        DAT_8039b4ac = 0xa9c;
        DAT_8039b4b0 = FLOAT_803dfe20;
        DAT_8039b4b4 = FLOAT_803dfe20;
        DAT_8039b4b8 = FLOAT_803dfe20;
        DAT_8039b4bc = FLOAT_803dfe20;
        DAT_8039b4c0 = 0;
        DAT_8039b4c4 = 0x3c5;
        DAT_8039b4c8 = 0xb72;
        DAT_8039b4cc = FLOAT_803dfe20;
        DAT_8039b4d0 = FLOAT_803dfe20;
        DAT_8039b4d4 = FLOAT_803dfe20;
        DAT_8039b4d8 = FLOAT_803dfe20;
        DAT_8039b4dc = 0;
        DAT_8039b4e0 = 0x335;
        DAT_8039b4e4 = 0xe13;
        DAT_8039b4e8 = FLOAT_803dfe20;
        DAT_8039b4ec = FLOAT_803dfe20;
        DAT_8039b4f0 = FLOAT_803dfe20;
        DAT_8039b4f4 = FLOAT_803dfe20;
        DAT_8039b4f8 = 0;
        DAT_8039b4fc = 0x254;
        DAT_8039b500 = 0xc70;
        DAT_8039b504 = FLOAT_803dfe20;
        DAT_8039b508 = FLOAT_803dfe20;
        DAT_8039b50c = FLOAT_803dfe20;
        DAT_8039b510 = FLOAT_803dfe20;
        DAT_8039b514 = 0;
        DAT_8039b518 = 0x107;
        DAT_8039b51c = 0xb4a;
        DAT_8039b520 = FLOAT_803dfe20;
        DAT_8039b524 = FLOAT_803dfe20;
        DAT_8039b528 = FLOAT_803dfe20;
        DAT_8039b52c = FLOAT_803dfe20;
        DAT_8039b530 = 0;
        DAT_8039b534 = 0;
        DAT_8039b538 = 2000;
        DAT_8039b53c = FLOAT_803dfe20;
        DAT_8039b540 = FLOAT_803dfe20;
        DAT_8039b544 = FLOAT_803dfec4;
        FUN_80070320(&DAT_8039b53c,&DAT_8039b540,&DAT_8039b544);
        DAT_8039b548 = FLOAT_803dfe7c;
        DAT_8039b54c = 0;
        DAT_803dc3cc = 0;
      }
    }
  }
  FUN_80286858();
  return;
}

