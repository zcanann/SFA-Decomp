// Function: FUN_8020a760
// Entry: 8020a760
// Size: 848 bytes

/* WARNING: Removing unreachable block (ram,0x8020aa90) */

void FUN_8020a760(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  char cVar7;
  int iVar5;
  uint uVar6;
  int iVar8;
  float *pfVar9;
  undefined4 uVar10;
  double dVar11;
  undefined8 in_f31;
  undefined8 uVar12;
  undefined auStack136 [12];
  undefined auStack124 [12];
  undefined auStack112 [12];
  float local_64;
  float local_60;
  float local_5c;
  longlong local_58;
  longlong local_50;
  undefined4 local_48;
  uint uStack68;
  double local_40;
  double local_38;
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar12 = FUN_802860d8();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  iVar8 = (int)uVar12;
  if ((-1 < param_3) && (param_3 < 4)) {
    if (param_3 == 2) {
      if (((*(byte *)(iVar8 + 0x198) >> 6 & 1) == 0) && (cVar7 = FUN_8002e04c(), cVar7 != '\0')) {
        iVar4 = FUN_8002bdf4(0x24,0x709);
        *(undefined *)(iVar4 + 4) = 2;
        *(undefined *)(iVar4 + 5) = 1;
        *(undefined *)(iVar4 + 6) = 0xff;
        *(undefined *)(iVar4 + 7) = 0xff;
        *(undefined4 *)(iVar4 + 8) = *(undefined4 *)(iVar8 + 0x1c);
        *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(iVar8 + 0x20);
        *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar8 + 0x24);
        *(undefined2 *)(iVar4 + 0x1a) = 0x3c;
        local_38 = (double)(longlong)(int)FLOAT_803dc194;
        *(short *)(iVar4 + 0x1c) = (short)(int)FLOAT_803dc194;
        local_40 = (double)(longlong)(int)FLOAT_803dc190;
        *(char *)(iVar4 + 0x19) = (char)(int)FLOAT_803dc190;
        FUN_8002b5a0(iVar3);
        FUN_8000bb18(iVar3,0x477);
      }
    }
    else if ((((param_3 < 2) && (0 < param_3)) &&
             (iVar4 = FUN_8002b9ec(), (*(byte *)(iVar8 + 0x198) >> 6 & 1) != 0)) &&
            (cVar7 = FUN_8002e04c(), cVar7 != '\0')) {
      iVar5 = FUN_8002bdf4(0x20,0x70f);
      *(undefined4 *)(iVar5 + 8) = *(undefined4 *)(iVar8 + 0x1c);
      *(undefined4 *)(iVar5 + 0xc) = *(undefined4 *)(iVar8 + 0x20);
      *(undefined4 *)(iVar5 + 0x10) = *(undefined4 *)(iVar8 + 0x24);
      *(undefined *)(iVar5 + 4) = 1;
      *(undefined *)(iVar5 + 5) = 1;
      *(undefined *)(iVar5 + 6) = 0xff;
      *(undefined *)(iVar5 + 7) = 0xff;
      if ((iVar4 != 0) && (iVar5 = FUN_8002b5a0(iVar3), iVar5 != 0)) {
        dVar11 = (double)FUN_80021704(iVar3 + 0x18,iVar4 + 0x18);
        iVar1 = (int)-(float)((double)FLOAT_803dc188 * dVar11);
        local_58 = (longlong)iVar1;
        iVar2 = (int)((double)FLOAT_803dc188 * dVar11);
        local_50 = (longlong)iVar2;
        uStack68 = FUN_800221a0(iVar1,iVar2);
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_64 = *(float *)(iVar4 + 0xc) +
                   (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e6528);
        uVar6 = FUN_800221a0(iVar1,iVar2);
        local_40 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_60 = *(float *)(iVar4 + 0x10) + (float)(local_40 - DOUBLE_803e6528);
        uVar6 = FUN_800221a0(iVar1,iVar2);
        local_38 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_5c = *(float *)(iVar4 + 0x14) + (float)(local_38 - DOUBLE_803e6528);
        FUN_80247754(iVar4 + 0xc,iVar8 + 0x1c,auStack112);
        FUN_80247754(&local_64,iVar8 + 0x1c,auStack124);
        FUN_80247794(auStack112,auStack112);
        dVar11 = (double)FUN_8024782c(iVar4 + 0x24,auStack112);
        dVar11 = (double)(float)((double)*(float *)(iVar8 + 0x188) * dVar11 +
                                (double)*(float *)(iVar8 + 0x184));
        FUN_80247778(dVar11,auStack112,iVar5 + 0x24);
        pfVar9 = *(float **)(iVar5 + 0xb8);
        FUN_8024782c(auStack112,auStack124);
        FUN_80247778(auStack112,auStack136);
        FUN_80247754(auStack124,auStack136,auStack136);
        FUN_80247794(auStack136,auStack136);
        FUN_80247778((double)(*(float *)(iVar8 + 0x184) * FLOAT_803dc18c),auStack136,iVar5 + 0x24);
        *pfVar9 = (float)dVar11;
        FUN_80217f80(iVar5);
        FUN_8008016c(iVar8 + 0x18);
        FUN_80080178(iVar8 + 0x18,0x1e);
        FUN_8000bb18(iVar3,0x477);
        FUN_8000bb18(iVar3,0x3c8);
      }
    }
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  FUN_80286124();
  return;
}

