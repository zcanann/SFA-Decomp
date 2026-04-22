#include "ghidra_import.h"
#include "main/dll/anim.h"

extern undefined4 FUN_800033a8();
extern undefined8 FUN_80003494();
extern undefined4 FUN_800066e0();
extern undefined4 FUN_8000a538();
extern bool FUN_8000b598();
extern undefined4 FUN_8000b7dc();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000da78();
extern void* FUN_8000facc();
extern int FUN_80010340();
extern int FUN_800128fc();
extern undefined8 FUN_80012d20();
extern uint FUN_800138d4();
extern uint FUN_800138e4();
extern undefined4 FUN_80013900();
extern undefined8 FUN_80013978();
extern undefined8 FUN_800139e8();
extern undefined4 FUN_80013a08();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_80013ee8();
extern uint FUN_80014e9c();
extern undefined4 FUN_80020000();
extern uint FUN_80020078();
extern undefined8 FUN_800201ac();
extern undefined4 FUN_80021754();
extern double FUN_80021794();
extern undefined4 FUN_800217c8();
extern uint FUN_80022150();
extern uint FUN_80022264();
extern undefined4 FUN_800228f0();
extern undefined4 FUN_8002b678();
extern undefined4 FUN_8002ba34();
extern int FUN_8002bac4();
extern void* FUN_8002becc();
extern undefined4 FUN_8002cc9c();
extern undefined4 FUN_8002cf80();
extern int FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_8002f6cc();
extern undefined8 FUN_8003042c();
extern undefined4 FUN_80035ea4();
extern undefined4 FUN_80035eec();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036018();
extern int FUN_80036974();
extern uint FUN_80036d04();
extern int FUN_80036e58();
extern int FUN_80036f50();
extern void* FUN_80037048();
extern undefined8 FUN_8003709c();
extern undefined4 FUN_800372f8();
extern int FUN_800375e4();
extern undefined4 FUN_800377d0();
extern undefined4 FUN_800379bc();
extern undefined4 FUN_80037a5c();
extern undefined4 FUN_80038524();
extern int FUN_800386e0();
extern void* FUN_80039598();
extern undefined4 FUN_800396d0();
extern undefined4 FUN_8003b6d8();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80043604();
extern undefined4 FUN_80043658();
extern undefined4 FUN_8004832c();
extern undefined4 FUN_80055464();
extern undefined4 FUN_8005a310();
extern undefined4 FUN_8005b128();
extern int FUN_8005b478();
extern uint FUN_8005b60c();
extern undefined4 FUN_8007d858();
extern undefined4 FUN_80097568();
extern undefined4 FUN_80098bb4();
extern undefined4 FUN_8009a010();
extern undefined8 FUN_8009a468();
extern undefined4 FUN_80137cd0();
extern undefined4 FUN_801d84c4();
extern undefined4 FUN_801d8650();
extern undefined4 FUN_801fe7a4();
extern undefined4 FUN_801fe954();
extern int FUN_801feb98();
extern undefined4 FUN_801fedac();
extern undefined4 FUN_80222268();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double FUN_80247f54();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80296848();
extern undefined4 FUN_8029725c();
extern undefined4 SUB42();

extern undefined4 DAT_802c2c90;
extern undefined4 DAT_802c2c94;
extern undefined4 DAT_802c2c98;
extern undefined4 DAT_802c2c9c;
extern undefined4 DAT_8032a158;
extern undefined4 DAT_8032a274;
extern undefined4 DAT_8032a280;
extern undefined4 DAT_8032a284;
extern undefined4 DAT_8032a290;
extern undefined4 DAT_8032a2a4;
extern undefined4 DAT_8032a31c;
extern undefined4 DAT_8032a33c;
extern undefined4 DAT_8032a34c;
extern undefined4 DAT_8032a35c;
extern undefined4 DAT_8032a36c;
extern undefined4 DAT_8032a37c;
extern undefined4 DAT_8032a38c;
extern undefined2 DAT_8032a488;
extern undefined4 DAT_8032a494;
extern undefined4 DAT_8032a496;
extern undefined4 DAT_8032a498;
extern undefined4 DAT_803add20;
extern undefined4 DAT_803add2c;
extern undefined4 DAT_803add30;
extern undefined4 DAT_803add34;
extern undefined4 DAT_803add38;
extern undefined4 DAT_803add3c;
extern undefined4 DAT_803add40;
extern undefined4 DAT_803add44;
extern undefined4 DAT_803add48;
extern undefined4 DAT_803add4c;
extern undefined4 DAT_803add50;
extern undefined4 DAT_803add54;
extern undefined4 DAT_803add58;
extern undefined4 DAT_803add5c;
extern undefined4 DAT_803add60;
extern undefined4 DAT_803add64;
extern undefined4 DAT_803add68;
extern undefined4 DAT_803add6c;
extern undefined4 DAT_803add70;
extern undefined4 DAT_803add74;
extern undefined4 DAT_803add78;
extern undefined4 DAT_803add7c;
extern undefined4 DAT_803add80;
extern undefined4 DAT_803add84;
extern undefined4 DAT_803add88;
extern undefined4 DAT_803add8c;
extern undefined4 DAT_803add90;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcdd8;
extern undefined4 DAT_803dcde0;
extern undefined4 DAT_803dcde8;
extern undefined4 DAT_803dcdea;
extern undefined4 DAT_803dcdeb;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de960;
extern undefined4 DAT_803de968;
extern undefined4 DAT_803e6e58;
extern undefined4 DAT_803e6e5c;
extern f64 DOUBLE_803e6ea8;
extern f64 DOUBLE_803e6f78;
extern f64 DOUBLE_803e7000;
extern f64 DOUBLE_803e7048;
extern f64 DOUBLE_803e7058;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803dcdc8;
extern f32 FLOAT_803dcdcc;
extern f32 FLOAT_803dcdd0;
extern f32 FLOAT_803dcdd4;
extern f32 FLOAT_803dcddc;
extern f32 FLOAT_803e6e60;
extern f32 FLOAT_803e6e64;
extern f32 FLOAT_803e6e7c;
extern f32 FLOAT_803e6e84;
extern f32 FLOAT_803e6e98;
extern f32 FLOAT_803e6eb8;
extern f32 FLOAT_803e6ebc;
extern f32 FLOAT_803e6ec0;
extern f32 FLOAT_803e6ec4;
extern f32 FLOAT_803e6ec8;
extern f32 FLOAT_803e6ecc;
extern f32 FLOAT_803e6ed0;
extern f32 FLOAT_803e6ed4;
extern f32 FLOAT_803e6ed8;
extern f32 FLOAT_803e6edc;
extern f32 FLOAT_803e6ee0;
extern f32 FLOAT_803e6ee4;
extern f32 FLOAT_803e6ee8;
extern f32 FLOAT_803e6eec;
extern f32 FLOAT_803e6ef0;
extern f32 FLOAT_803e6ef4;
extern f32 FLOAT_803e6ef8;
extern f32 FLOAT_803e6efc;
extern f32 FLOAT_803e6f00;
extern f32 FLOAT_803e6f08;
extern f32 FLOAT_803e6f0c;
extern f32 FLOAT_803e6f14;
extern f32 FLOAT_803e6f18;
extern f32 FLOAT_803e6f1c;
extern f32 FLOAT_803e6f20;
extern f32 FLOAT_803e6f2c;
extern f32 FLOAT_803e6f38;
extern f32 FLOAT_803e6f40;
extern f32 FLOAT_803e6f44;
extern f32 FLOAT_803e6f48;
extern f32 FLOAT_803e6f4c;
extern f32 FLOAT_803e6f50;
extern f32 FLOAT_803e6f58;
extern f32 FLOAT_803e6f5c;
extern f32 FLOAT_803e6f60;
extern f32 FLOAT_803e6f64;
extern f32 FLOAT_803e6f68;
extern f32 FLOAT_803e6f6c;
extern f32 FLOAT_803e6f70;
extern f32 FLOAT_803e6f80;
extern f32 FLOAT_803e6f84;
extern f32 FLOAT_803e6f88;
extern f32 FLOAT_803e6f8c;
extern f32 FLOAT_803e6f90;
extern f32 FLOAT_803e6f94;
extern f32 FLOAT_803e6f98;
extern f32 FLOAT_803e6f9c;
extern f32 FLOAT_803e6fa0;
extern f32 FLOAT_803e6fa4;
extern f32 FLOAT_803e6fa8;
extern f32 FLOAT_803e6fac;
extern f32 FLOAT_803e6fb0;
extern f32 FLOAT_803e6fb4;
extern f32 FLOAT_803e6fb8;
extern f32 FLOAT_803e6fbc;
extern f32 FLOAT_803e6fc0;
extern f32 FLOAT_803e6fc4;
extern f32 FLOAT_803e6fc8;
extern f32 FLOAT_803e6fcc;
extern f32 FLOAT_803e6fd0;
extern f32 FLOAT_803e6fd4;
extern f32 FLOAT_803e6fd8;
extern f32 FLOAT_803e6fdc;
extern f32 FLOAT_803e6fe0;
extern f32 FLOAT_803e6fe4;
extern f32 FLOAT_803e6fe8;
extern f32 FLOAT_803e6fec;
extern f32 FLOAT_803e6ff0;
extern f32 FLOAT_803e6ff4;
extern f32 FLOAT_803e7008;
extern f32 FLOAT_803e700c;
extern f32 FLOAT_803e7010;
extern f32 FLOAT_803e7014;
extern f32 FLOAT_803e7018;
extern f32 FLOAT_803e701c;
extern f32 FLOAT_803e7020;
extern f32 FLOAT_803e7034;
extern f32 FLOAT_803e7038;
extern f32 FLOAT_803e703c;
extern f32 FLOAT_803e7040;
extern f32 FLOAT_803e7060;
extern f32 FLOAT_803e7064;
extern f32 FLOAT_803e7068;
extern f32 FLOAT_803e706c;
extern f32 FLOAT_803e7070;
extern f32 FLOAT_803e7074;
extern f32 FLOAT_803e7078;
extern undefined4 PTR_DAT_8032a154;

/*
 * --INFO--
 *
 * Function: FUN_801ff168
 * EN v1.0 Address: 0x801FF168
 * EN v1.0 Size: 3320b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ff168(void)
{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  char cVar7;
  uint uVar6;
  int in_r7;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  float *pfVar10;
  int iVar11;
  double dVar12;
  undefined8 uVar13;
  double dVar14;
  double dVar15;
  double in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_58;
  undefined4 local_54;
  undefined4 local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  undefined8 local_30;
  
  psVar3 = (short *)FUN_80286838();
  iVar11 = *(int *)(psVar3 + 0x26);
  iVar4 = FUN_8002bac4();
  pfVar10 = *(float **)(psVar3 + 0x5c);
  local_54 = DAT_803e6e58;
  local_50 = DAT_803e6e5c;
  dVar14 = (double)*(float *)(psVar3 + 8);
  dVar15 = (double)*(float *)(psVar3 + 10);
  iVar5 = FUN_8005b478((double)*(float *)(psVar3 + 6),dVar14);
  if (iVar5 != -1) {
    FUN_801fe7a4((int)psVar3);
    *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
         *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) & 0xfbff;
    switch(*(undefined *)(pfVar10 + 0x46)) {
    case 1:
      if (*(int *)(psVar3 + 0x7c) == 0) {
        *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) | 1;
      }
      *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
      break;
    case 2:
      if ((*(byte *)((int)pfVar10 + 0x119) & 4) != 0) {
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        fVar2 = FLOAT_803e6e7c;
        *(float *)(psVar3 + 0x12) =
             *(float *)(psVar3 + 0x12) +
             (*(float *)(iVar11 + 8) - *(float *)(psVar3 + 6)) / FLOAT_803e6e7c;
        *(float *)(psVar3 + 0x14) =
             *(float *)(psVar3 + 0x14) + (*(float *)(iVar11 + 0xc) - *(float *)(psVar3 + 8)) / fVar2
        ;
        *(float *)(psVar3 + 0x16) =
             *(float *)(psVar3 + 0x16) +
             (*(float *)(iVar11 + 0x10) - *(float *)(psVar3 + 10)) / fVar2;
        uVar6 = FUN_80020078(0x44d);
        if (uVar6 != 0) {
          *(undefined *)(pfVar10 + 0x46) = 10;
        }
      }
      *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) | 0x400;
      local_40 = FLOAT_803e6e60;
      local_3c = FLOAT_803e6e60;
      local_38 = FLOAT_803e6e60;
      FUN_801fedac();
      *(float *)(psVar3 + 0x12) = *(float *)(psVar3 + 0x12) + local_40;
      *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) + local_3c;
      *(float *)(psVar3 + 0x16) = *(float *)(psVar3 + 0x16) + local_38;
      iVar5 = FUN_801feb98((double)(*(float *)(psVar3 + 0x12) * FLOAT_803dc074),
                           (double)(*(float *)(psVar3 + 0x16) * FLOAT_803dc074),(int)psVar3,
                           &local_58,1);
      fVar2 = FLOAT_803e6ecc;
      if (iVar5 != 0) {
        *(float *)(psVar3 + 0x12) = FLOAT_803e6ecc * *(float *)(psVar3 + 0x12);
        *(float *)(psVar3 + 0x16) = fVar2 * *(float *)(psVar3 + 0x16);
        FUN_801feb98((double)(*(float *)(psVar3 + 0x12) * FLOAT_803dc074),
                     (double)(*(float *)(psVar3 + 0x16) * FLOAT_803dc074),(int)psVar3,&local_58,1);
      }
      local_58 = local_58 + *pfVar10;
      if (FLOAT_803dc078 == FLOAT_803e6e60) {
        *(float *)(psVar3 + 0x14) = FLOAT_803e6e60;
      }
      else {
        *(float *)(psVar3 + 0x14) = local_58 * FLOAT_803e6ed0 * FLOAT_803dc078;
      }
      FUN_80022264(100,5000);
      FUN_80022264(100,5000);
      dVar14 = (double)(*(float *)(psVar3 + 0x14) * FLOAT_803dc074);
      dVar15 = (double)(*(float *)(psVar3 + 0x16) * FLOAT_803dc074);
      FUN_8002ba34((double)(*(float *)(psVar3 + 0x12) * FLOAT_803dc074),dVar14,dVar15,(int)psVar3);
      uVar6 = FUN_80022264(0,10);
      if ((uVar6 == 0) && (local_58 < FLOAT_803e6e98)) {
        uVar6 = FUN_80022264(1,10);
        local_30 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        in_f4 = (double)(float)(local_30 - DOUBLE_803e6ea8);
        dVar14 = (double)(*(float *)(psVar3 + 8) - *pfVar10);
        dVar15 = (double)*(float *)(psVar3 + 10);
        (**(code **)(*DAT_803dd718 + 0x14))((double)*(float *)(psVar3 + 6),(int)*psVar3,1);
      }
      uVar6 = FUN_80020078(0x426);
      if (uVar6 == 0) {
        if ((*(byte *)((int)pfVar10 + 0x119) & 2) != 0) {
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        }
      }
      else {
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
        dVar14 = (double)FLOAT_803e6ed4;
        *pfVar10 = -(float)(dVar14 * (double)FLOAT_803dc074 - (double)*pfVar10);
        if (*pfVar10 < FLOAT_803e6e84) {
          uVar6 = FUN_80020078(0x428);
          FUN_800201ac(0x428,uVar6 + 1);
          *(undefined *)(pfVar10 + 0x46) = 7;
          fVar2 = FLOAT_803e6e60;
          *(float *)(psVar3 + 0x14) = FLOAT_803e6e60;
          *(float *)(psVar3 + 0x12) = fVar2;
          *(float *)(psVar3 + 0x16) = fVar2;
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        }
      }
      break;
    case 4:
      *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
      break;
    case 5:
      if (*(int *)(psVar3 + 0x7c) == 0) {
        *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) | 1;
      }
      dVar14 = (double)FLOAT_803e6e60;
      iVar5 = FUN_801feb98(dVar14,dVar14,(int)psVar3,&local_58,1);
      if (iVar5 == 0) {
        *(undefined *)(pfVar10 + 0x46) = 2;
      }
      else {
        fVar2 = local_58;
        if (local_58 < FLOAT_803e6e60) {
          fVar2 = -local_58;
        }
        if (FLOAT_803e6eb8 <= fVar2) {
          *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) + FLOAT_803e6ebc;
          fVar2 = FLOAT_803e6e60;
          if (FLOAT_803e6e60 < local_58) {
            *(float *)(psVar3 + 0x14) = FLOAT_803e6ec0 * -*(float *)(psVar3 + 0x14);
            fVar1 = FLOAT_803e6ec4;
            *(float *)(psVar3 + 0x12) = *(float *)(psVar3 + 0x12) * FLOAT_803e6ec4;
            *(float *)(psVar3 + 0x16) = *(float *)(psVar3 + 0x16) * fVar1;
            fVar1 = *(float *)(psVar3 + 0x14);
            if (fVar1 < fVar2) {
              fVar1 = -fVar1;
            }
            if (FLOAT_803e6ec8 < fVar1) {
              FUN_8000bb38((uint)psVar3,0x2df);
            }
          }
          dVar14 = (double)(*(float *)(psVar3 + 0x14) * FLOAT_803dc074);
          dVar15 = (double)(*(float *)(psVar3 + 0x16) * FLOAT_803dc074);
          FUN_8002ba34((double)(*(float *)(psVar3 + 0x12) * FLOAT_803dc074),dVar14,dVar15,
                       (int)psVar3);
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        }
        else {
          if ((*(byte *)((int)pfVar10 + 0x119) & 0x10) == 0) {
            *(undefined *)(pfVar10 + 0x46) = 1;
          }
          else {
            *(undefined *)(pfVar10 + 0x46) = 0xd;
          }
          fVar2 = FLOAT_803e6e60;
          *(float *)(psVar3 + 0x12) = FLOAT_803e6e60;
          *(float *)(psVar3 + 0x16) = fVar2;
          *(float *)(psVar3 + 0x14) = fVar2;
          *(float *)(psVar3 + 8) = *(float *)(psVar3 + 8) + local_58;
        }
      }
      break;
    case 6:
      dVar12 = (double)FUN_80021754((float *)(psVar3 + 0xc),(float *)(iVar11 + 8));
      if ((dVar12 <= (double)FLOAT_803e6ed8) || ((*(byte *)((int)pfVar10 + 0x119) & 2) != 0)) {
        uVar6 = FUN_80014e9c(0);
        if ((uVar6 & 0x100) == 0) {
          *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
               *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) & 0xfffe;
          FUN_800379bc(dVar12,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,iVar4,0x100008,
                       (uint)psVar3,0x38000,in_r7,in_r8,in_r9,in_r10);
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        }
        else {
          *(undefined *)(pfVar10 + 0x46) = 5;
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
        }
      }
      else {
        iVar5 = FUN_8002bac4();
        iVar8 = *(int *)(psVar3 + 0x5c);
        iVar9 = *(int *)(psVar3 + 0x26);
        FUN_8003709c((int)psVar3,0x24);
        *(undefined *)(iVar8 + 0x118) = 3;
        FUN_800201ac(0x3c4,1);
        FUN_800201ac(0x86d,1);
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
        uVar13 = FUN_800201ac((int)*(short *)(iVar9 + 0x1c),1);
        *(undefined2 *)(iVar8 + 0x11c) = 0xffff;
        *(undefined2 *)(iVar8 + 0x11e) = 0;
        *(float *)(iVar8 + 0x120) = FLOAT_803e6e64;
        FUN_800379bc(uVar13,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,iVar5,0x7000a,(uint)psVar3,
                     iVar8 + 0x11c,in_r7,in_r8,in_r9,in_r10);
        psVar3[0x7c] = 0;
        psVar3[0x7d] = 0;
      }
      break;
    case 7:
      dVar14 = (double)FLOAT_803e6e60;
      FUN_801feb98(dVar14,dVar14,(int)psVar3,&local_58,0);
      fVar2 = local_58;
      if (local_58 < FLOAT_803e6e60) {
        fVar2 = -local_58;
      }
      if (FLOAT_803e6eb8 <= fVar2) {
        *(float *)(psVar3 + 0x14) = *(float *)(psVar3 + 0x14) + FLOAT_803e6edc;
        if (FLOAT_803e6e60 < local_58) {
          *(float *)(psVar3 + 0x14) = FLOAT_803e6ee0 * -*(float *)(psVar3 + 0x14);
        }
        dVar14 = (double)(*(float *)(psVar3 + 0x14) * FLOAT_803dc074);
        dVar15 = (double)(*(float *)(psVar3 + 0x16) * FLOAT_803dc074);
        FUN_8002ba34((double)(*(float *)(psVar3 + 0x12) * FLOAT_803dc074),dVar14,dVar15,(int)psVar3)
        ;
      }
      else {
        *(undefined *)(pfVar10 + 0x46) = 8;
        fVar2 = FLOAT_803e6e60;
        *(float *)(psVar3 + 0x12) = FLOAT_803e6e60;
        *(float *)(psVar3 + 0x16) = fVar2;
      }
      break;
    case 8:
      uVar6 = FUN_80020078(0x42a);
      if (uVar6 == 0) {
        uVar6 = FUN_80022264(0,10);
        if (uVar6 == 0) {
          in_r7 = -1;
          in_r8 = 0;
          in_r9 = *DAT_803dd708;
          (**(code **)(in_r9 + 8))(psVar3,0x3be,0,0);
        }
      }
      else {
        FUN_801fe954(psVar3,pfVar10);
      }
      break;
    case 9:
      iVar5 = FUN_80010340((double)FLOAT_803e6ee8,pfVar10 + 1);
      if ((iVar5 == 0) && (pfVar10[5] == 0.0)) {
        *(float *)(psVar3 + 0x12) = pfVar10[0x1b] - *(float *)(psVar3 + 6);
        *(float *)(psVar3 + 0x14) = pfVar10[0x1c] - *(float *)(psVar3 + 8);
        *(float *)(psVar3 + 0x16) = pfVar10[0x1d] - *(float *)(psVar3 + 10);
        dVar12 = FUN_80293900((double)(*(float *)(psVar3 + 0x16) * *(float *)(psVar3 + 0x16) +
                                      *(float *)(psVar3 + 0x12) * *(float *)(psVar3 + 0x12) +
                                      *(float *)(psVar3 + 0x14) * *(float *)(psVar3 + 0x14)));
        dVar14 = (double)FLOAT_803e6eec;
        if ((double)(float)(dVar14 * (double)FLOAT_803dc074) < dVar12) {
          FUN_800228f0((float *)(psVar3 + 0x12));
          dVar14 = (double)FLOAT_803e6eec;
          *(float *)(psVar3 + 0x12) =
               *(float *)(psVar3 + 0x12) * (float)(dVar14 * (double)FLOAT_803dc074);
          *(float *)(psVar3 + 0x14) =
               *(float *)(psVar3 + 0x14) * (float)(dVar14 * (double)FLOAT_803dc074);
          *(float *)(psVar3 + 0x16) =
               *(float *)(psVar3 + 0x16) * (float)(dVar14 * (double)FLOAT_803dc074);
          FUN_80137cd0();
        }
        *(float *)(psVar3 + 6) = *(float *)(psVar3 + 6) + *(float *)(psVar3 + 0x12);
        *(float *)(psVar3 + 8) = *(float *)(psVar3 + 8) + *(float *)(psVar3 + 0x14);
        *(float *)(psVar3 + 10) = *(float *)(psVar3 + 10) + *(float *)(psVar3 + 0x16);
      }
      else {
        cVar7 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar10 + 1);
        if (cVar7 != '\0') {
          *(undefined *)(pfVar10 + 0x46) = 5;
        }
      }
      break;
    case 10:
      in_r7 = *DAT_803dd71c;
      cVar7 = (**(code **)(in_r7 + 0x8c))((double)FLOAT_803e6ee4,pfVar10 + 1,psVar3,&local_54,2);
      if (cVar7 == '\0') {
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
        *(undefined *)(pfVar10 + 0x46) = 9;
        if ((*(byte *)((int)pfVar10 + 0x119) & 4) != 0) {
          *(byte *)((int)pfVar10 + 0x119) = *(byte *)((int)pfVar10 + 0x119) & 0xfb;
        }
      }
      else {
        *(undefined *)(pfVar10 + 0x46) = 5;
      }
      break;
    case 0xb:
      *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
      goto LAB_801ffe48;
    case 0xc:
      uVar6 = FUN_80020078((int)*(short *)(iVar11 + 0x24));
      if (uVar6 != 0) {
        FUN_800372f8((int)psVar3,0x24);
        *(undefined *)(pfVar10 + 0x46) = 5;
      }
      break;
    case 0xd:
      FUN_80035ff8((int)psVar3);
      dVar15 = (double)FLOAT_803e6ef0;
      *(float *)(psVar3 + 0x12) =
           *(float *)(psVar3 + 0x12) +
           (float)((double)(*(float *)(iVar11 + 8) - *(float *)(psVar3 + 6)) / dVar15);
      *(float *)(psVar3 + 0x14) =
           *(float *)(psVar3 + 0x14) +
           (float)((double)(*(float *)(iVar11 + 0xc) - *(float *)(psVar3 + 8)) / dVar15);
      *(float *)(psVar3 + 0x16) =
           *(float *)(psVar3 + 0x16) +
           (float)((double)(*(float *)(iVar11 + 0x10) - *(float *)(psVar3 + 10)) / dVar15);
      local_4c = *(float *)(psVar3 + 6) - *(float *)(iVar11 + 8);
      local_48 = *(float *)(psVar3 + 8) - *(float *)(iVar11 + 0xc);
      local_44 = *(float *)(psVar3 + 10) - *(float *)(iVar11 + 0x10);
      FUN_8000da78((uint)psVar3,0x442);
      dVar12 = (double)local_44;
      if (dVar12 < (double)FLOAT_803e6e60) {
        dVar12 = -dVar12;
      }
      dVar14 = (double)local_4c;
      if (dVar14 < (double)FLOAT_803e6e60) {
        dVar14 = -dVar14;
      }
      if (FLOAT_803e6ef4 <= (float)(dVar14 + dVar12)) {
        dVar15 = FUN_80247f54((float *)(psVar3 + 0x12));
        dVar14 = (double)FLOAT_803e6ef8;
        local_30 = (double)(longlong)(int)(dVar15 / dVar14);
        for (iVar5 = 0; iVar5 < (int)(dVar15 / dVar14); iVar5 = iVar5 + 1) {
          in_r7 = -1;
          in_r8 = 0;
          in_r9 = *DAT_803dd708;
          (**(code **)(in_r9 + 8))(psVar3,0x345,0,1);
        }
        dVar14 = (double)(*(float *)(psVar3 + 0x14) * FLOAT_803dc074);
        dVar15 = (double)(*(float *)(psVar3 + 0x16) * FLOAT_803dc074);
        FUN_8002ba34((double)(*(float *)(psVar3 + 0x12) * FLOAT_803dc074),dVar14,dVar15,(int)psVar3)
        ;
      }
      else {
        FUN_80036018((int)psVar3);
        *(undefined *)(pfVar10 + 0x46) = 1;
        *(undefined4 *)(psVar3 + 6) = *(undefined4 *)(iVar11 + 8);
        *(undefined4 *)(psVar3 + 8) = *(undefined4 *)(iVar11 + 0xc);
        *(undefined4 *)(psVar3 + 10) = *(undefined4 *)(iVar11 + 0x10);
      }
    }
    if ((*(byte *)((int)pfVar10 + 0x119) & 8) == 0) {
      if ((((*(byte *)((int)psVar3 + 0xaf) & 1) != 0) && (uVar6 = FUN_80020078(0x3c4), uVar6 == 0))
         && (dVar12 = (double)FUN_80021754((float *)(psVar3 + 0xc),(float *)(iVar4 + 0x18)),
            dVar12 < (double)FLOAT_803e6efc)) {
        if ((*(byte *)((int)pfVar10 + 0x119) & 1) == 0) {
          iVar4 = FUN_8002bac4();
          iVar11 = *(int *)(psVar3 + 0x5c);
          iVar5 = *(int *)(psVar3 + 0x26);
          FUN_8003709c((int)psVar3,0x24);
          *(undefined *)(iVar11 + 0x118) = 3;
          FUN_800201ac(0x3c4,1);
          FUN_800201ac(0x86d,1);
          *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
          uVar13 = FUN_800201ac((int)*(short *)(iVar5 + 0x1c),1);
          *(undefined2 *)(iVar11 + 0x11c) = 0xffff;
          *(undefined2 *)(iVar11 + 0x11e) = 0;
          *(float *)(iVar11 + 0x120) = FLOAT_803e6e64;
          FUN_800379bc(uVar13,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,iVar4,0x7000a,(uint)psVar3
                       ,iVar11 + 0x11c,in_r7,in_r8,in_r9,in_r10);
        }
        else {
          fVar2 = *(float *)(psVar3 + 8) - *(float *)(iVar4 + 0x10);
          if (fVar2 < FLOAT_803e6e60) {
            fVar2 = -fVar2;
          }
          if (fVar2 < FLOAT_803e6f00) {
            *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
            *(undefined *)(pfVar10 + 0x46) = 6;
            *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) =
                 *(ushort *)(*(int *)(psVar3 + 0x2a) + 0x60) & 0xfffe;
          }
        }
      }
    }
    else {
      *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) | 8;
      FUN_80035ff8((int)psVar3);
      uVar6 = FUN_80020078((int)*(short *)(iVar11 + 0x1c));
      if (uVar6 != 0) {
        *(byte *)((int)pfVar10 + 0x119) = *(byte *)((int)pfVar10 + 0x119) & 0xf6;
        *(byte *)((int)psVar3 + 0xaf) = *(byte *)((int)psVar3 + 0xaf) & 0xf7;
        FUN_80036018((int)psVar3);
      }
    }
  }
LAB_801ffe48:
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ffe60
 * EN v1.0 Address: 0x801FFE60
 * EN v1.0 Size: 92b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ffe60(short *param_1)
{
  int iVar1;
  
  FUN_801fe954(param_1,*(undefined4 **)(param_1 + 0x5c));
  FUN_80037a5c((int)param_1,8);
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0x4008;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ffebc
 * EN v1.0 Address: 0x801FFEBC
 * EN v1.0 Size: 344b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801ffebc(int param_1,undefined4 param_2,int param_3)
{
  int *piVar1;
  int iVar2;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    *(byte *)(piVar1 + 1) = *(char *)(param_3 + iVar2 + 0x81) << 7 | *(byte *)(piVar1 + 1) & 0x7f;
  }
  if (((*(char *)(piVar1 + 1) < '\0') && (*piVar1 < 2)) && (-1 < *piVar1)) {
    FUN_80097568((double)FLOAT_803e6f08,(double)FLOAT_803e6f0c,param_1,7,5,6,100,0,0x200000);
    FUN_80097568((double)FLOAT_803e6f08,(double)FLOAT_803e6f0c,param_1,6,1,6,100,0,0x200000);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80200014
 * EN v1.0 Address: 0x80200014
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80200014(int param_1)
{
  char cVar1;
  
  cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 8);
  if ((cVar1 != '\0') && (cVar1 != '\x04')) {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80200054
 * EN v1.0 Address: 0x80200054
 * EN v1.0 Size: 864b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80200054(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  byte bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  float fVar5;
  float *pfVar6;
  double dVar7;
  double dVar8;
  float afStack_68 [3];
  float afStack_5c [3];
  undefined2 local_50;
  short local_4e;
  undefined2 local_4c;
  undefined4 local_38;
  float fStack_34;
  
  pfVar6 = *(float **)(param_9 + 0x5c);
  iVar3 = FUN_8002bac4();
  fVar5 = FLOAT_803e6f14;
  bVar1 = *(byte *)(pfVar6 + 2);
  if (bVar1 == 3) {
    dVar7 = (double)FUN_80021754((float *)(param_9 + 0xc),(float *)(iVar3 + 0x18));
    if ((double)FLOAT_803dcdd0 <= dVar7) {
      dVar8 = (double)FLOAT_803dcdd4;
      FUN_80222268((double)(float)(dVar8 / (double)FLOAT_803e6f2c),param_2,param_3,param_4,param_5,
                   param_6,param_7,param_8,iVar3,(float *)(param_9 + 6),afStack_5c);
      FUN_80247eb8(afStack_5c,(float *)(param_9 + 6),afStack_68);
      FUN_80247ef8(afStack_68,afStack_68);
      if (dVar7 < dVar8) {
        dVar8 = dVar7;
      }
      FUN_80247edc(dVar8,afStack_68,(float *)(param_9 + 0x12));
      FUN_8002ba34((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                   (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                   (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
      local_4c = 0xff;
      local_4e = 0;
      local_50 = 0xff;
      FUN_80098bb4((double)FLOAT_803dcddc,param_9,1,0xc22,0x14,param_9 + 0x12);
    }
    else {
      FUN_8029725c(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,DAT_803dcdd8)
      ;
      FUN_8000bb38((uint)param_9,0x49);
      *(undefined *)(pfVar6 + 2) = 4;
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      if (FLOAT_803e6f14 < *pfVar6 - *(float *)(param_9 + 8)) {
        *(float *)(param_9 + 0x14) = FLOAT_803e6f18 * -*(float *)(param_9 + 0x14);
        fVar2 = *(float *)(param_9 + 0x14);
        if (fVar2 < fVar5) {
          fVar2 = -fVar2;
        }
        if (fVar2 < FLOAT_803e6f1c) {
          *(undefined *)(pfVar6 + 2) = 2;
          fVar5 = FLOAT_803e6f14;
          *(float *)(param_9 + 0x12) = FLOAT_803e6f14;
          *(float *)(param_9 + 0x16) = fVar5;
          goto LAB_80200364;
        }
      }
      *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) + FLOAT_803e6f20;
      FUN_8002ba34((double)*(float *)(param_9 + 0x12),(double)*(float *)(param_9 + 0x14),
                   (double)*(float *)(param_9 + 0x16),(int)param_9);
      local_4c = 0xff;
      fVar5 = pfVar6[1];
      iVar3 = (int)fVar5 / 0x500 + ((int)fVar5 >> 0x1f);
      local_4e = 0xff - (SUB42(fVar5,0) + ((short)iVar3 - (short)(iVar3 >> 0x1f)) * -0x500);
      local_50 = 0xff;
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x357,&local_50,0,0xffffffff,0);
    }
    else if (bVar1 == 0) {
      uVar4 = FUN_80020078((int)*(short *)(*(int *)(param_9 + 0x26) + 0x20));
      if (uVar4 == 1) {
        *(undefined *)(pfVar6 + 2) = 2;
      }
    }
    else {
      fStack_34 = -pfVar6[1];
      local_38 = 0x43300000;
      dVar7 = (double)FUN_802945e0();
      *(float *)(param_9 + 0x14) = (float)((double)FLOAT_803dcdc8 * dVar7);
      FUN_8002ba34((double)*(float *)(param_9 + 0x12),(double)*(float *)(param_9 + 0x14),
                   (double)*(float *)(param_9 + 0x16),(int)param_9);
      dVar7 = (double)FUN_800217c8((float *)(param_9 + 0xc),(float *)(iVar3 + 0x18));
      if (dVar7 < (double)FLOAT_803dcdcc) {
        *(undefined *)(pfVar6 + 2) = 3;
      }
      FUN_80098bb4((double)FLOAT_803dcddc,param_9,1,0xc22,0x14,param_9 + 0x12);
    }
  }
  else if (bVar1 == 5) {
    *(undefined *)(pfVar6 + 2) = 0;
  }
LAB_80200364:
  *param_9 = *param_9 + DAT_803dcde0;
  pfVar6[1] = (float)((int)pfVar6[1] + (uint)DAT_803dc070 * 0x500);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802003b4
 * EN v1.0 Address: 0x802003B4
 * EN v1.0 Size: 156b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802003b4(int param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar3 + 8) = 5;
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_2 + 0x10);
  fVar1 = FLOAT_803e6f14;
  *(float *)(param_1 + 0x2c) = FLOAT_803e6f14;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = FLOAT_803e6f38;
  uVar2 = FUN_80022264(0,0xffff);
  *(uint *)(iVar3 + 4) = uVar2;
  uVar2 = FUN_80020078((int)*(short *)(param_2 + 0x20));
  if (uVar2 != 0) {
    *(undefined *)(iVar3 + 8) = 4;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80200450
 * EN v1.0 Address: 0x80200450
 * EN v1.0 Size: 624b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80200450(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 uVar10;
  float local_28 [10];
  
  uVar10 = FUN_80286838();
  iVar4 = (int)((ulonglong)uVar10 >> 0x20);
  iVar5 = (int)uVar10;
  iVar8 = *(int *)(iVar4 + 0x4c);
  local_28[0] = FLOAT_803e6f44;
  iVar9 = *(int *)(*(int *)(iVar4 + 0xb8) + 0x40c);
  if ((*(char *)(iVar5 + 0x27b) == '\0') && (*(char *)(iVar9 + 0x34) == '\0')) {
    iVar8 = *(int *)(iVar9 + 0x2c);
    if (iVar8 == 1) {
      if (*(int *)(iVar5 + 0x2d0) == 0) {
        *(undefined *)(iVar9 + 0x34) = 1;
      }
    }
    else if ((iVar8 < 1) && (-1 < iVar8)) {
      if (*(int *)(iVar5 + 0x2d0) == 0) {
        *(undefined *)(iVar9 + 0x34) = 1;
      }
      else if ((*(int *)(iVar9 + 0x30) != 0) &&
              (uVar2 = FUN_80036d04(*(int *)(iVar5 + 0x2d0),*(int *)(iVar9 + 0x30)), uVar2 == 0)) {
        uVar3 = FUN_80036e58(*(undefined4 *)(iVar9 + 0x30),iVar4,(float *)0x0);
        *(undefined4 *)(iVar5 + 0x2d0) = uVar3;
        if (*(int *)(iVar5 + 0x2d0) == 0) {
          *(undefined *)(iVar9 + 0x34) = 1;
        }
        *(float *)(iVar5 + 0x280) = FLOAT_803e6f40;
      }
    }
    if (((*(short *)(iVar9 + 0x1c) == -1) && (*(int *)(iVar9 + 0x3c) != 0)) &&
       (iVar4 = (**(code **)(**(int **)(*(int *)(iVar9 + 0x3c) + 0x68) + 0x20))(), iVar4 == 0)) {
      *(undefined4 *)(iVar9 + 0x3c) = 0;
      *(undefined *)(iVar9 + 0x34) = 1;
    }
  }
  else {
    *(byte *)(iVar9 + 0x15) = *(byte *)(iVar9 + 0x15) & 0xfb;
    *(undefined *)(iVar9 + 0x34) = 0;
    uVar10 = extraout_f1;
    uVar2 = FUN_800138d4(*(short **)(iVar9 + 0x24));
    if (uVar2 == 0) {
      FUN_80013900(*(short **)(iVar9 + 0x24),iVar9 + 0x28);
    }
    else {
      if (*(int *)(iVar8 + 0x14) == -1) {
        FUN_8002cc9c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
        goto LAB_802006a8;
      }
      sVar1 = *(short *)(iVar8 + 0x24);
      iVar6 = (int)*(short *)(&DAT_8032a158 + sVar1 * 8);
      iVar7 = iVar6 * 0xc;
      for (; iVar6 != 0; iVar6 = iVar6 + -1) {
        iVar7 = iVar7 + -0xc;
        FUN_80013978(*(short **)(iVar9 + 0x24),(uint)((&PTR_DAT_8032a154)[sVar1 * 2] + iVar7));
      }
      *(undefined *)(iVar9 + 0x34) = 1;
      *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(iVar8 + 8);
      *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar8 + 0xc);
      *(undefined4 *)(iVar4 + 0x14) = *(undefined4 *)(iVar8 + 0x10);
    }
    iVar8 = *(int *)(iVar9 + 0x2c);
    if (iVar8 == 1) {
      *(undefined4 *)(iVar5 + 0x2d0) = *(undefined4 *)(iVar9 + 0x30);
    }
    else if (((iVar8 < 1) && (-1 < iVar8)) && (*(int *)(iVar9 + 0x30) != 0)) {
      uVar3 = FUN_80036e58(*(int *)(iVar9 + 0x30),iVar4,local_28);
      *(undefined4 *)(iVar5 + 0x2d0) = uVar3;
    }
    if (*(int *)(iVar5 + 0x2d0) != 0) {
      (**(code **)(*DAT_803dd70c + 0x14))(iVar4,iVar5,*(undefined4 *)(iVar9 + 0x28));
    }
  }
LAB_802006a8:
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802006c0
 * EN v1.0 Address: 0x802006C0
 * EN v1.0 Size: 572b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802006c0(void)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined8 uVar9;
  float local_28;
  undefined auStack_24 [36];
  
  uVar9 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  iVar6 = (int)uVar9;
  iVar7 = *(int *)(iVar2 + 0x4c);
  local_28 = FLOAT_803e6f44;
  puVar8 = *(undefined4 **)(*(int *)(iVar2 + 0xb8) + 0x40c);
  if ((*(char *)(iVar6 + 0x27b) == '\0') && ((*(byte *)(puVar8 + 0x11) >> 6 & 1) == 0)) {
    if ((puVar8[6] == 0) && (FLOAT_803e6f48 < (float)puVar8[0xe])) {
      puVar8[0xe] = (float)puVar8[0xe] - FLOAT_803e6f48;
      local_28 = FLOAT_803e6f4c;
      iVar1 = 3;
      puVar8 = (undefined4 *)0x8032a348;
      iVar7 = 0;
      while( true ) {
        puVar8 = puVar8 + -1;
        iVar1 = iVar1 + -1;
        if (iVar1 < 0) break;
        iVar5 = FUN_80036e58(*puVar8,iVar2,&local_28);
        if (iVar5 != 0) {
          iVar7 = iVar5;
        }
      }
      *(int *)(iVar6 + 0x2d0) = iVar7;
      if (iVar7 != 0) {
        if (FLOAT_803e6f50 <= local_28) {
          (**(code **)(*DAT_803dd70c + 0x14))(iVar2,iVar6,4);
        }
        else {
          (**(code **)(*DAT_803dd70c + 0x14))(iVar2,iVar6,2);
        }
      }
    }
  }
  else {
    *(byte *)((int)puVar8 + 0x15) = *(byte *)((int)puVar8 + 0x15) & 0xfb;
    *(byte *)(puVar8 + 0x11) = *(byte *)(puVar8 + 0x11) & 0xbf;
    uVar3 = FUN_800138d4((short *)puVar8[9]);
    if (uVar3 == 0) {
      FUN_80013900((short *)puVar8[9],(uint)auStack_24);
    }
    iVar1 = puVar8[8] - *(int *)*puVar8;
    iVar1 = iVar1 / 0xc + (iVar1 >> 0x1f);
    if ((int)*(short *)((int *)*puVar8 + 1) <= iVar1 - (iVar1 >> 0x1f)) {
      puVar8[8] = 0;
    }
    if (puVar8[8] == 0) {
      puVar8[8] = *(undefined4 *)*puVar8;
      *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar7 + 8);
      *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar7 + 0xc);
      *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(iVar7 + 0x10);
    }
    if (*(int *)(puVar8[8] + 4) != 0) {
      uVar4 = FUN_80036e58(*(int *)(puVar8[8] + 4),iVar2,&local_28);
      *(undefined4 *)(iVar6 + 0x2d0) = uVar4;
    }
    if (*(int *)(iVar6 + 0x2d0) != 0) {
      (**(code **)(*DAT_803dd70c + 0x14))(iVar2,iVar6,*(undefined4 *)puVar8[8]);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802008fc
 * EN v1.0 Address: 0x802008FC
 * EN v1.0 Size: 104b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_802008fc(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
    fVar1 = FLOAT_803e6f40;
    iVar2 = *(int *)(iVar2 + 0x40c);
    *(float *)(iVar2 + 0xc) = FLOAT_803e6f40;
    *(float *)(iVar2 + 0x10) = fVar1;
    *(float *)(iVar2 + 4) = fVar1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80200964
 * EN v1.0 Address: 0x80200964
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80200964(int param_1,int param_2)
{
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd738 + 0x4c))
              (param_1,(int)*(short *)(*(int *)(param_1 + 0xb8) + 0x3f0),0xffffffff,0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802009b8
 * EN v1.0 Address: 0x802009B8
 * EN v1.0 Size: 304b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_802009b8(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  
  fVar1 = FLOAT_803e6f40;
  if (*(char *)(param_2 + 0x27b) == '\0') {
    if (((*(char *)(param_2 + 0x346) != '\0') && (*(char *)(param_1 + 0x36) == '\0')) &&
       (*(char *)(param_2 + 0x346) != '\0')) {
      return 7;
    }
  }
  else {
    iVar2 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
    *(float *)(iVar2 + 0xc) = FLOAT_803e6f40;
    *(float *)(iVar2 + 0x10) = fVar1;
    *(float *)(iVar2 + 4) = fVar1;
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,6);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80200ae8
 * EN v1.0 Address: 0x80200AE8
 * EN v1.0 Size: 672b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80200ae8(double param_1,ushort *param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80200d88
 * EN v1.0 Address: 0x80200D88
 * EN v1.0 Size: 256b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80200d88(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(byte *)(iVar1 + 0x14) = *(byte *)(iVar1 + 0x14) | 2;
  *(byte *)(iVar1 + 0x15) = *(byte *)(iVar1 + 0x15) | 4;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e6f80;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    param_1 = FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,0x11,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 0x1f;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(param_10 + 0x2d0);
    *(undefined2 *)(iVar1 + 0x1c) = 0x24;
    *(undefined4 *)(iVar1 + 0x2c) = 0;
    FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(iVar1 + 0x18),0x11,param_9,0x12,param_13,param_14,param_15,param_16);
    FUN_8000bb38(param_9,0x1eb);
  }
  if (FLOAT_803e6f84 < *(float *)(param_9 + 0x98)) {
    *(undefined *)(iVar1 + 0x34) = 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80200e88
 * EN v1.0 Address: 0x80200E88
 * EN v1.0 Size: 544b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80200e88(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  short *psVar4;
  int iVar5;
  double dVar6;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  float local_24;
  float local_20;
  float local_1c;
  
  iVar5 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(byte *)(iVar5 + 0x14) = *(byte *)(iVar5 + 0x14) | 2;
  *(byte *)(iVar5 + 0x15) = *(byte *)(iVar5 + 0x15) & 0xfb;
  fVar1 = FLOAT_803e6f88;
  *(float *)(param_10 + 0x280) = *(float *)(param_10 + 0x280) / FLOAT_803e6f88;
  *(float *)(param_10 + 0x284) = *(float *)(param_10 + 0x284) / fVar1;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e6f8c;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x11,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 0x1f;
  if ((*(float *)(param_9 + 0x98) <= FLOAT_803e6f84) ||
     (*(float *)(param_9 + 0x10) < *(float *)(*(int *)(param_10 + 0x2d0) + 0x10) - FLOAT_803e6f90))
  {
    iVar3 = *(int *)(param_10 + 0x2d0);
    local_24 = *(float *)(iVar3 + 0xc) - *(float *)(param_9 + 0xc);
    local_20 = *(float *)(iVar3 + 0x10) - (*(float *)(param_9 + 0x10) + FLOAT_803e6f94);
    local_1c = *(float *)(iVar3 + 0x14) - *(float *)(param_9 + 0x14);
    dVar6 = FUN_80293900((double)(local_1c * local_1c + local_24 * local_24 + local_20 * local_20));
    if (dVar6 < (double)FLOAT_803e6f50) {
      local_40 = *(undefined4 *)(param_10 + 0x2d0);
      psVar4 = *(short **)(iVar5 + 0x24);
      local_48 = 0xe;
      local_44 = 1;
      uVar2 = FUN_800138e4(psVar4);
      if (uVar2 == 0) {
        FUN_80013978(psVar4,(uint)&local_48);
      }
      *(undefined *)(iVar5 + 0x34) = 1;
    }
  }
  else {
    psVar4 = *(short **)(iVar5 + 0x24);
    local_30 = 9;
    local_2c = 0;
    local_28 = 0x24;
    uVar2 = FUN_800138e4(psVar4);
    if (uVar2 == 0) {
      FUN_80013978(psVar4,(uint)&local_30);
    }
    *(undefined *)(iVar5 + 0x34) = 1;
    local_34 = *(undefined4 *)(param_10 + 0x2d0);
    psVar4 = *(short **)(iVar5 + 0x24);
    local_3c = 7;
    local_38 = 1;
    uVar2 = FUN_800138e4(psVar4);
    if (uVar2 == 0) {
      FUN_80013978(psVar4,(uint)&local_3c);
    }
    *(undefined *)(iVar5 + 0x34) = 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802010a8
 * EN v1.0 Address: 0x802010A8
 * EN v1.0 Size: 980b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802010a8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020147c
 * EN v1.0 Address: 0x8020147C
 * EN v1.0 Size: 1300b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020147c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80201990
 * EN v1.0 Address: 0x80201990
 * EN v1.0 Size: 660b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80201990(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  ushort *puVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 uVar6;
  undefined4 uVar7;
  short *psVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  undefined4 local_58;
  undefined4 local_54;
  int local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  uVar11 = FUN_80286840();
  fVar1 = FLOAT_803e6f40;
  puVar2 = (ushort *)((ulonglong)uVar11 >> 0x20);
  iVar5 = (int)uVar11;
  iVar9 = *(int *)(*(int *)(puVar2 + 0x5c) + 0x40c);
  uVar7 = *(undefined4 *)(iVar9 + 0x30);
  uVar6 = *(undefined4 *)(iVar9 + 0x2c);
  *(float *)(iVar5 + 0x280) = FLOAT_803e6f40;
  *(float *)(iVar5 + 0x284) = fVar1;
  *(byte *)(iVar9 + 0x14) = *(byte *)(iVar9 + 0x14) | 2;
  if ((*(int *)(iVar9 + 0x18) == 0) && (*(short *)(iVar9 + 0x1c) != -1)) {
    local_38 = *(undefined4 *)(iVar9 + 0x30);
    local_3c = *(undefined4 *)(iVar9 + 0x2c);
    psVar8 = *(short **)(iVar9 + 0x24);
    local_40 = *(undefined4 *)(iVar9 + 0x28);
    uVar3 = FUN_800138e4(psVar8);
    if (uVar3 == 0) {
      FUN_80013978(psVar8,(uint)&local_40);
    }
    psVar8 = *(short **)(iVar9 + 0x24);
    local_4c = 8;
    local_48 = uVar6;
    local_44 = uVar7;
    uVar3 = FUN_800138e4(psVar8);
    if (uVar3 == 0) {
      FUN_80013978(psVar8,(uint)&local_4c);
    }
    *(undefined *)(iVar9 + 0x34) = 1;
    local_50 = (int)*(short *)(iVar9 + 0x1c);
    psVar8 = *(short **)(iVar9 + 0x24);
    local_58 = 9;
    local_54 = 0;
    uVar3 = FUN_800138e4(psVar8);
    if (uVar3 == 0) {
      FUN_80013978(psVar8,(uint)&local_58);
    }
    *(undefined *)(iVar9 + 0x34) = 1;
  }
  else {
    *(byte *)(iVar9 + 0x15) = *(byte *)(iVar9 + 0x15) | 4;
    if ((*(int *)(iVar9 + 0x18) != 0) && ((*(uint *)(iVar5 + 0x314) & 0x200) != 0)) {
      iVar4 = *(int *)(iVar5 + 0x2d0);
      local_34 = *(float *)(iVar4 + 0xc) - *(float *)(puVar2 + 6);
      local_30 = *(float *)(iVar4 + 0x10) - *(float *)(puVar2 + 8);
      local_2c = *(float *)(iVar4 + 0x14) - *(float *)(puVar2 + 10);
      dVar10 = FUN_80293900((double)(local_34 * local_34 + local_2c * local_2c));
      local_30 = local_30 * FLOAT_803e6fa8;
      param_2 = (double)local_30;
      dVar10 = (double)(float)(dVar10 / (double)FLOAT_803e6fac);
      dVar10 = (double)(float)(-(double)(float)(dVar10 * (double)(float)((double)FLOAT_803e6fb0 *
                                                                        dVar10) - param_2) / dVar10)
      ;
      local_24 = (float)(dVar10 * (double)FLOAT_803e6fb4);
      local_28 = FLOAT_803e6f40;
      local_20 = FLOAT_803e6fb8;
      in_r6 = 0x11;
      FUN_800379bc(dVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar9 + 0x18),0x11,(uint)puVar2,0x11,in_r7,in_r8,in_r9,in_r10);
      (**(code **)(**(int **)(*(int *)(iVar9 + 0x18) + 0x68) + 0x24))
                (*(int *)(iVar9 + 0x18),&local_28);
      *(undefined4 *)(iVar9 + 0x18) = 0;
      *(undefined2 *)(iVar9 + 0x1c) = 0xffff;
    }
    iVar4 = FUN_800386e0(puVar2,*(int *)(iVar5 + 0x2d0),(float *)0x0);
    *puVar2 = *puVar2 + (short)iVar4;
    *(undefined *)(iVar5 + 0x34d) = 0x11;
    if (*(char *)(iVar5 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   puVar2,0x12,0,in_r6,in_r7,in_r8,in_r9,in_r10);
      *(undefined *)(iVar5 + 0x346) = 0;
    }
    if (*(char *)(iVar5 + 0x346) != '\0') {
      *(undefined *)(iVar9 + 0x34) = 1;
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80201c24
 * EN v1.0 Address: 0x80201C24
 * EN v1.0 Size: 440b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80201c24(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar7;
  undefined4 uVar8;
  int iVar9;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 uVar10;
  undefined4 local_38;
  undefined4 local_34;
  int local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  uVar10 = FUN_8028683c();
  uVar3 = (uint)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  iVar9 = *(int *)(*(int *)(uVar3 + 0xb8) + 0x40c);
  uVar8 = *(undefined4 *)(iVar9 + 0x30);
  *(byte *)(iVar9 + 0x14) = *(byte *)(iVar9 + 0x14) | 2;
  fVar2 = FLOAT_803e6f40;
  *(float *)(iVar6 + 0x280) = FLOAT_803e6f40;
  *(float *)(iVar6 + 0x284) = fVar2;
  uVar10 = extraout_f1;
  if ((*(int *)(iVar6 + 0x2d0) == 0) ||
     (iVar4 = (**(code **)(**(int **)(*(int *)(iVar6 + 0x2d0) + 0x68) + 0x20))(),
     uVar10 = extraout_f1_00, iVar4 == 0)) {
    *(undefined *)(iVar9 + 0x34) = 1;
  }
  if ((*(int *)(iVar9 + 0x18) == 0) && (sVar1 = *(short *)(iVar9 + 0x1c), sVar1 != -1)) {
    local_24 = *(undefined4 *)(iVar9 + 0x30);
    local_28 = *(undefined4 *)(iVar9 + 0x2c);
    psVar7 = *(short **)(iVar9 + 0x24);
    local_2c = *(undefined4 *)(iVar9 + 0x28);
    uVar5 = FUN_800138e4(psVar7);
    if (uVar5 == 0) {
      uVar10 = FUN_80013978(psVar7,(uint)&local_2c);
    }
    psVar7 = *(short **)(iVar9 + 0x24);
    local_38 = 7;
    local_34 = 0;
    local_30 = (int)sVar1;
    uVar5 = FUN_800138e4(psVar7);
    if (uVar5 == 0) {
      uVar10 = FUN_80013978(psVar7,(uint)&local_38);
    }
    *(undefined *)(iVar9 + 0x34) = 1;
    *(undefined2 *)(iVar9 + 0x1c) = 0xffff;
  }
  if ((*(uint *)(iVar6 + 0x314) & 0x200) != 0) {
    *(undefined4 *)(iVar9 + 0x18) = *(undefined4 *)(iVar6 + 0x2d0);
    *(short *)(iVar9 + 0x1c) = (short)uVar8;
    *(undefined4 *)(iVar9 + 0x2c) = 0;
    in_r6 = 0x12;
    FUN_800379bc(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(iVar9 + 0x18),0x11,uVar3,0x12,in_r7,in_r8,in_r9,in_r10);
    FUN_8000bb38(uVar3,0x1eb);
  }
  *(undefined *)(iVar6 + 0x34d) = 0x12;
  if (*(char *)(iVar6 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar3,0x10,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar6 + 0x346) = 0;
  }
  if (*(char *)(iVar6 + 0x346) != '\0') {
    *(undefined *)(iVar9 + 0x34) = 1;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80201ddc
 * EN v1.0 Address: 0x80201DDC
 * EN v1.0 Size: 1076b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80201ddc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80202210
 * EN v1.0 Address: 0x80202210
 * EN v1.0 Size: 1240b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80202210(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802026e8
 * EN v1.0 Address: 0x802026E8
 * EN v1.0 Size: 484b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802026e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  undefined8 uVar9;
  undefined auStack_28 [40];
  
  uVar9 = FUN_80286840();
  uVar2 = (uint)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  iVar7 = *(int *)(uVar2 + 0xb8);
  iVar6 = *(int *)(uVar2 + 0x4c);
  iVar5 = *(int *)(iVar7 + 0x40c);
  *(undefined *)(iVar4 + 0x34d) = 0x11;
  fVar1 = FLOAT_803e6f40;
  if (*(char *)(iVar4 + 0x27a) != '\0') {
    *(float *)(iVar4 + 0x284) = FLOAT_803e6f40;
    *(float *)(iVar4 + 0x280) = fVar1;
    *(undefined4 *)(iVar4 + 0x2d0) = 0;
    *(undefined *)(iVar4 + 0x25f) = 1;
    *(undefined *)(iVar4 + 0x349) = 0;
    *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
    FUN_80035ff8(uVar2);
    uVar9 = FUN_8003709c(uVar2,3);
    if (*(int *)(iVar5 + 0x18) != 0) {
      in_r6 = 0x10;
      FUN_800379bc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar5 + 0x18),0x11,uVar2,0x10,in_r7,in_r8,in_r9,in_r10);
      *(undefined2 *)(iVar5 + 0x1c) = 0xffff;
      *(undefined4 *)(iVar5 + 0x18) = 0;
    }
  }
  if (*(char *)(iVar4 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar2,1,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar4 + 0x346) = 0;
  }
  *(float *)(iVar4 + 0x2a0) = FLOAT_803e6fcc;
  dVar8 = (double)*(float *)(uVar2 + 0x98);
  if ((double)FLOAT_803e6fd0 < dVar8) {
    FUN_80020000((int)*(short *)(iVar6 + 0x18));
    if (*(int *)(iVar6 + 0x14) == -1) {
      FUN_8002cc9c(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2);
      goto LAB_802028b4;
    }
    while (uVar3 = FUN_800138d4(*(short **)(iVar5 + 0x24)), uVar3 == 0) {
      FUN_80013900(*(short **)(iVar5 + 0x24),(uint)auStack_28);
    }
    if (*(short *)(iVar6 + 0x2c) == 0) {
      (**(code **)(*DAT_803dd72c + 100))((double)FLOAT_803e6fd4,*(undefined4 *)(iVar6 + 0x14));
    }
    *(byte *)(iVar7 + 0x404) = *(byte *)(iVar7 + 0x404) | *(byte *)(iVar6 + 0x2b);
  }
  (**(code **)(*DAT_803dd70c + 0x34))(uVar2,iVar4,0,2,&DAT_8032a274);
  (**(code **)(*DAT_803dd70c + 0x34))(uVar2,iVar4,7,0,&DAT_8032a280);
LAB_802028b4:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802028cc
 * EN v1.0 Address: 0x802028CC
 * EN v1.0 Size: 404b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802028cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  iVar4 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    param_1 = FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    if (*(int *)(iVar4 + 0x18) != 0) {
      FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar4 + 0x18),0x11,param_9,0x10,param_13,param_14,param_15,param_16);
      *(undefined4 *)(iVar4 + 0x18) = 0;
    }
    iVar1 = FUN_8002bac4();
    iVar1 = (**(code **)(**(int **)(*(int *)(iVar1 + 200) + 0x68) + 0x44))();
    if (iVar1 == 0) {
      uVar2 = FUN_80022264(0,2);
      FUN_8000bb38(param_9,(ushort)*(undefined4 *)(&DAT_8032a290 + uVar2 * 4));
    }
    else {
      uVar2 = FUN_80022264(3,4);
      FUN_8000bb38(param_9,(ushort)*(undefined4 *)(&DAT_8032a290 + uVar2 * 4));
    }
    local_20 = *(undefined4 *)(iVar4 + 0x30);
    local_24 = *(undefined4 *)(iVar4 + 0x2c);
    psVar3 = *(short **)(iVar4 + 0x24);
    local_28 = *(undefined4 *)(iVar4 + 0x28);
    uVar2 = FUN_800138e4(psVar3);
    if (uVar2 == 0) {
      FUN_80013978(psVar3,(uint)&local_28);
    }
    *(undefined4 *)(iVar4 + 0x3c) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 0x10;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e6fd8;
  *(float *)(param_10 + 0x280) = FLOAT_803e6f40;
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined *)(iVar4 + 0x34) = 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80202a60
 * EN v1.0 Address: 0x80202A60
 * EN v1.0 Size: 252b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80202a60(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80036018(param_9);
  }
  uVar1 = 0xffffffff;
  FUN_80035eec(param_9,10,1,-1);
  *(float *)(param_10 + 0x2a0) = FLOAT_803e6f8c;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,10,0,uVar1,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  iVar2 = *(int *)(iVar2 + 0x40c);
  *(byte *)(iVar2 + 0x14) = *(byte *)(iVar2 + 0x14) | 2;
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & 0xfffffffe;
    *(byte *)(iVar2 + 0x14) = *(byte *)(iVar2 + 0x14) | 1;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined *)(iVar2 + 0x34) = 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80202b5c
 * EN v1.0 Address: 0x80202B5C
 * EN v1.0 Size: 156b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80202b5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80036018(param_9);
  }
  uVar1 = 0xffffffff;
  FUN_80035eec(param_9,10,1,-1);
  *(float *)(param_10 + 0x2a0) = FLOAT_803e6f8c;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,5,0,uVar1,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80202bf8
 * EN v1.0 Address: 0x80202BF8
 * EN v1.0 Size: 352b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80202bf8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar4 = *(int *)(iVar3 + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80036018(param_9);
  }
  uVar2 = 0xffffffff;
  FUN_80035eec(param_9,10,1,-1);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    uVar1 = FUN_80022264(0,1);
    if (uVar1 == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,7,0,uVar2,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,6,0,uVar2,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         FLOAT_803e6fdc +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 0x406)) - DOUBLE_803e6f78) /
         FLOAT_803e6fe0;
  }
  *(float *)(param_10 + 0x280) = FLOAT_803e6f40;
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined *)(iVar4 + 0x34) = 1;
  }
  *(byte *)(iVar4 + 0x14) = *(byte *)(iVar4 + 0x14) | 2;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80202d58
 * EN v1.0 Address: 0x80202D58
 * EN v1.0 Size: 416b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80202d58(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  int iVar2;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar6 >> 0x20);
  iVar2 = (int)uVar6;
  iVar5 = *(int *)(uVar1 + 0xb8);
  iVar3 = *(int *)(uVar1 + 0x4c);
  iVar4 = *(int *)(iVar5 + 0x40c);
  if (*(char *)(iVar2 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar1,0xe,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar2 + 0x346) = 0;
  }
  *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) | 8;
  if (FLOAT_803e6fe4 < *(float *)(uVar1 + 0x98)) {
    *(byte *)(iVar4 + 0x14) = *(byte *)(iVar4 + 0x14) | 2;
    FUN_80035ff8(uVar1);
  }
  if (*(char *)(iVar2 + 0x27a) != '\0') {
    *(float *)(iVar2 + 0x2a0) = FLOAT_803e6f8c;
    *(float *)(iVar2 + 0x280) = FLOAT_803e6f40;
  }
  if (*(char *)(iVar2 + 0x346) != '\0') {
    FUN_8000bb38(uVar1,0x1ea);
    *(float *)(iVar4 + 4) = FLOAT_803e6f60;
    uVar6 = FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,uVar1,8,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined4 *)(iVar2 + 0x2d0) = 0;
    *(undefined *)(iVar2 + 0x25f) = 0;
    *(undefined *)(iVar2 + 0x349) = 0;
    *(undefined2 *)(iVar5 + 0x402) = 0;
    *(byte *)(iVar5 + 0x404) = *(byte *)(iVar5 + 0x404) | *(byte *)(iVar3 + 0x2b);
    if (*(int *)(iVar4 + 0x18) != 0) {
      FUN_800379bc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar4 + 0x18),0x11,uVar1,0x13,in_r7,in_r8,in_r9,in_r10);
      *(undefined4 *)(iVar4 + 0x18) = 0;
      *(undefined2 *)(iVar4 + 0x1c) = 0xffff;
    }
    if ((*(byte *)(iVar4 + 0x15) & 2) == 0) {
      *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) | 8;
    }
    *(undefined *)(iVar4 + 0x34) = 1;
  }
  (**(code **)(*DAT_803dd70c + 0x34))(uVar1,iVar2,7,0,&DAT_8032a280);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80202ef8
 * EN v1.0 Address: 0x80202EF8
 * EN v1.0 Size: 364b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80202ef8(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  if (*(char *)(param_2 + 0x27a) == '\0') {
    FUN_80035eec(param_1,10,1,-1);
  }
  else {
    *(undefined *)(param_2 + 0x25f) = 1;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(undefined *)(param_2 + 0x34d) = 1;
    *(float *)(param_2 + 0x2a0) =
         FLOAT_803e6fe8 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e6f78) /
         FLOAT_803e6fec;
    FUN_80036018(param_1);
    *(undefined4 *)(iVar1 + 0x18) = 0;
    *(undefined2 *)(iVar1 + 0x1c) = 0xffff;
  }
  if (*(char *)(param_2 + 0x346) != '\0') {
    *(undefined2 *)(iVar2 + 0x402) = 1;
    *(undefined *)(iVar1 + 0x34) = 1;
  }
  if ((*(uint *)(param_2 + 0x314) & 0x200) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & 0xfffffdff;
    *(byte *)(iVar1 + 0x14) = *(byte *)(iVar1 + 0x14) | 4;
  }
  if (*(float *)(param_1 + 0x98) < FLOAT_803e6ff0) {
    *(byte *)(iVar1 + 0x14) = *(byte *)(iVar1 + 0x14) | 2;
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_1,param_2,7,0,&DAT_8032a280);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80203064
 * EN v1.0 Address: 0x80203064
 * EN v1.0 Size: 588b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203064(undefined4 param_1,undefined4 param_2,float *param_3,int param_4)
{
  float fVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  double dVar7;
  double extraout_f1;
  double dVar8;
  double in_f28;
  double dVar9;
  double in_f29;
  double in_f30;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  float local_38;
  float fStack_34;
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
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar12 = FUN_8028683c();
  psVar2 = (short *)((ulonglong)uVar12 >> 0x20);
  puVar6 = (undefined4 *)uVar12;
  iVar5 = *(int *)(psVar2 + 0x5c);
  dVar10 = (double)FLOAT_803e6f40;
  dVar11 = (double)FLOAT_803e6ff4;
  dVar9 = extraout_f1;
  dVar7 = dVar10;
  for (iVar4 = 0; iVar4 < param_4; iVar4 = iVar4 + 1) {
    local_78 = (float)dVar11;
    iVar3 = FUN_80036e58(*puVar6,psVar2,&local_78);
    if (iVar3 != 0) {
      if (local_78 == FLOAT_803e6f40) goto LAB_80203278;
      fVar1 = FLOAT_803e6f60 - local_78 / FLOAT_803e6ff4;
      fVar1 = fVar1 * fVar1;
      fVar1 = fVar1 * fVar1;
      local_6c = FLOAT_803e6f60 / local_78;
      local_74 = (*(float *)(iVar3 + 0xc) - *(float *)(psVar2 + 6)) * local_6c;
      local_70 = (*(float *)(iVar3 + 0x10) - *(float *)(psVar2 + 8)) * local_6c;
      local_6c = (*(float *)(iVar3 + 0x14) - *(float *)(psVar2 + 10)) * local_6c;
      dVar7 = -(double)(float)(dVar9 * (double)(local_74 * fVar1 * *param_3) - dVar7);
      dVar10 = -(double)(float)(dVar9 * (double)(local_6c * fVar1 * *param_3) - dVar10);
    }
    puVar6 = puVar6 + 1;
    param_3 = param_3 + 1;
  }
  uStack_64 = (int)*psVar2 ^ 0x80000000;
  local_68 = 0x43300000;
  dVar11 = (double)FUN_802945e0();
  uStack_5c = (int)*psVar2 ^ 0x80000000;
  local_60 = 0x43300000;
  dVar8 = (double)FUN_80294964();
  *(float *)(iVar5 + 0x284) =
       *(float *)(iVar5 + 0x284) + (float)(dVar7 * dVar8 - (double)(float)(dVar10 * dVar11));
  *(float *)(iVar5 + 0x280) =
       *(float *)(iVar5 + 0x280) + (float)(-dVar10 * dVar8 - (double)(float)(dVar7 * dVar11));
  dVar11 = (double)*(float *)(iVar5 + 0x280);
  dVar7 = -dVar9;
  dVar10 = dVar7;
  if ((dVar7 <= dVar11) && (dVar10 = dVar11, dVar9 < dVar11)) {
    dVar10 = dVar9;
  }
  *(float *)(iVar5 + 0x280) = (float)dVar10;
  dVar10 = (double)*(float *)(iVar5 + 0x284);
  if ((dVar7 <= dVar10) && (dVar7 = dVar10, dVar9 < dVar10)) {
    dVar7 = dVar9;
  }
  *(float *)(iVar5 + 0x284) = (float)dVar7;
LAB_80203278:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802032b0
 * EN v1.0 Address: 0x802032B0
 * EN v1.0 Size: 300b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802032b0(double param_1,double param_2,undefined8 param_3,double param_4,ushort *param_5,
            int param_6)
{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  float local_48 [5];
  
  iVar3 = *(int *)(param_5 + 0x5c);
  iVar1 = FUN_800386e0(param_5,param_6,local_48);
  if ((double)FLOAT_803e6f40 == param_4) {
    uVar2 = 0;
  }
  else {
    dVar5 = (double)(float)((double)(float)((double)local_48[0] - param_1) / param_4);
    dVar4 = dVar5;
    if (dVar5 < (double)FLOAT_803e6f40) {
      dVar4 = -dVar5;
    }
    if ((double)FLOAT_803e7008 <= dVar4) {
      if (dVar5 < (double)FLOAT_803e6f40) {
        param_2 = -param_2;
      }
      *(float *)(iVar3 + 0x280) =
           FLOAT_803dc074 * FLOAT_803e6fe4 *
           ((float)(param_2 *
                   (double)(FLOAT_803e6f60 -
                           (float)((double)CONCAT44(0x43300000,(int)(short)iVar1 ^ 0x80000000) -
                                  DOUBLE_803e7000) / FLOAT_803e700c)) - *(float *)(iVar3 + 0x280)) +
           *(float *)(iVar3 + 0x280);
      *(float *)(iVar3 + 0x284) = FLOAT_803e6f40;
      uVar2 = 0;
    }
    else {
      uVar2 = 1;
    }
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_802033dc
 * EN v1.0 Address: 0x802033DC
 * EN v1.0 Size: 332b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802033dc(double param_1,double param_2,undefined8 param_3,double param_4,ushort *param_5,
            int param_6)
{
  int iVar1;
  int iVar2;
  double dVar3;
  float local_58 [7];
  
  iVar2 = *(int *)(param_5 + 0x5c);
  if ((param_5 != (ushort *)0x0) && (param_6 != 0)) {
    iVar1 = FUN_800386e0(param_5,param_6,local_58);
    if ((double)FLOAT_803e6f40 != param_4) {
      if ((double)local_58[0] < param_1) {
        dVar3 = (double)(*(float *)(param_5 + 8) - *(float *)(param_6 + 0x10));
        if (dVar3 < (double)FLOAT_803e6f40) {
          dVar3 = -dVar3;
        }
        if (dVar3 < (double)FLOAT_803e7010) {
          return 1;
        }
      }
      *(float *)(iVar2 + 0x280) =
           FLOAT_803dc074 * FLOAT_803e6fe4 *
           ((float)(param_2 *
                   (double)(FLOAT_803e6f60 -
                           (float)((double)CONCAT44(0x43300000,(int)(short)iVar1 ^ 0x80000000) -
                                  DOUBLE_803e7000) / FLOAT_803e700c)) - *(float *)(iVar2 + 0x280)) +
           *(float *)(iVar2 + 0x280);
      *(float *)(iVar2 + 0x284) = FLOAT_803e6f40;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80203528
 * EN v1.0 Address: 0x80203528
 * EN v1.0 Size: 272b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203528(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  undefined2 *puVar4;
  int iVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar6;
  
  uVar3 = FUN_8002e144();
  if ((uVar3 & 0xff) != 0) {
    puVar4 = FUN_8002becc(0x24,0x30a);
    *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar6 = (double)FLOAT_803e7014;
    *(float *)(puVar4 + 6) = (float)(dVar6 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar4 + 2) = 1;
    *(undefined *)((int)puVar4 + 5) = 1;
    *(undefined *)(puVar4 + 3) = 0xff;
    *(undefined *)((int)puVar4 + 7) = 0xff;
    iVar5 = FUN_8002e088(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar5 != 0) {
      fVar1 = *(float *)(param_10 + 0x2c0) / FLOAT_803e6f4c;
      fVar2 = FLOAT_803e6f50 * fVar1;
      *(float *)(iVar5 + 0x24) =
           (*(float *)(*(int *)(param_10 + 0x2d0) + 0xc) - *(float *)(param_9 + 0xc)) / fVar2;
      *(float *)(iVar5 + 0x28) =
           ((FLOAT_803e7018 * fVar1 + *(float *)(*(int *)(param_10 + 0x2d0) + 0x10)) -
           *(float *)(param_9 + 0x10)) / fVar2;
      *(float *)(iVar5 + 0x2c) =
           (*(float *)(*(int *)(param_10 + 0x2d0) + 0x14) - *(float *)(param_9 + 0x14)) / fVar2;
      *(int *)(iVar5 + 0xc4) = param_9;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80203638
 * EN v1.0 Address: 0x80203638
 * EN v1.0 Size: 324b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203638(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int iVar2;
  
  iVar1 = *(int *)(param_10 + 0x40c);
  if (((*(byte *)(iVar1 + 0x14) & 1) != 0) && (*(int *)(param_10 + 0x2d0) != 0)) {
    FUN_80203528(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  }
  if ((*(byte *)(iVar1 + 0x14) & 2) != 0) {
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x345,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x345,0,2,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x345,0,2,0xffffffff,0);
  }
  if ((*(byte *)(iVar1 + 0x14) & 4) != 0) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x343,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 10);
  }
  *(undefined *)(iVar1 + 0x14) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8020377c
 * EN v1.0 Address: 0x8020377C
 * EN v1.0 Size: 760b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020377c(undefined4 param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar7 = FUN_8028683c();
  uVar1 = (uint)((ulonglong)uVar7 >> 0x20);
  iVar3 = (int)uVar7;
  iVar5 = *(int *)(iVar3 + 0x40c);
  local_30 = FLOAT_803e6f48;
  iVar4 = *(int *)(uVar1 + 0x4c);
  uStack_1c = (uint)*(ushort *)(iVar3 + 0x3fe);
  local_20 = 0x43300000;
  iVar2 = (**(code **)(*DAT_803dd738 + 0x48))
                    ((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6f78),uVar1
                     ,param_3,0x8000);
  if ((iVar2 == 0) && ((*(byte *)(iVar3 + 0x404) & 0x10) != 0)) {
    iVar2 = FUN_80036f50(0x24,uVar1,&local_30);
  }
  if ((((iVar2 == 0) && ((*(byte *)(iVar3 + 0x404) & 0x10) != 0)) &&
      ((*(byte *)(iVar3 + 0x404) & 2) == 0)) && ((*(byte *)(iVar4 + 0x2b) & 2) != 0)) {
    iVar2 = FUN_80036f50(0x24,uVar1,(float *)0x0);
  }
  if ((iVar2 == 0) || ((*(byte *)(iVar3 + 0x404) & 2) != 0)) {
    iVar2 = FUN_8002bac4();
    if (iVar2 == 0) {
      dVar6 = (double)FLOAT_803e6fec;
    }
    else {
      local_2c = *(float *)(iVar2 + 0x18) - *(float *)(uVar1 + 0x18);
      local_28 = *(float *)(iVar2 + 0x1c) - *(float *)(uVar1 + 0x1c);
      local_24 = *(float *)(iVar2 + 0x20) - *(float *)(uVar1 + 0x20);
      dVar6 = FUN_80293900((double)(local_24 * local_24 + local_2c * local_2c + local_28 * local_28)
                          );
    }
    if ((*(float *)(iVar5 + 0x10) < *(float *)(iVar5 + 0xc)) && (dVar6 < (double)FLOAT_803e701c)) {
      FUN_8000bb38(uVar1,(ushort)DAT_8032a284);
      uStack_1c = FUN_80022264(0x32,0xfa);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(iVar5 + 0x10) =
           *(float *)(iVar5 + 0x10) +
           (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7000);
    }
    *(float *)(iVar5 + 0xc) = *(float *)(iVar5 + 0xc) + FLOAT_803dc074;
  }
  else {
    (**(code **)(*DAT_803dd738 + 0x28))
              (uVar1,param_3,iVar3 + 0x35c,(int)*(short *)(iVar3 + 0x3f4),0,0,0,8,0xffffffff);
    *(int *)(param_3 + 0x2d0) = iVar2;
    *(undefined *)(param_3 + 0x349) = 0;
    FUN_800372f8(uVar1,3);
    *(undefined2 *)(iVar3 + 0x402) = 1;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80203a74
 * EN v1.0 Address: 0x80203A74
 * EN v1.0 Size: 136b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203a74(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  FUN_8003709c(param_9,3);
  uVar3 = FUN_800139e8(*(uint *)(iVar1 + 0x24));
  if (*(int *)(param_9 + 200) != 0) {
    FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
    *(undefined4 *)(param_9 + 200) = 0;
  }
  (**(code **)(*DAT_803dd738 + 0x40))(param_9,iVar2,3);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80203afc
 * EN v1.0 Address: 0x80203AFC
 * EN v1.0 Size: 368b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203afc(void)
{
  int iVar1;
  char in_r8;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_80286838();
  iVar2 = *(int *)(iVar1 + 0xb8);
  iVar3 = *(int *)(iVar2 + 0x40c);
  if (*(int *)(iVar3 + 0x18) != 0) {
    *(undefined4 *)(*(int *)(iVar3 + 0x18) + 0xc) = *(undefined4 *)(iVar1 + 0xc);
    *(undefined4 *)(*(int *)(iVar3 + 0x18) + 0x10) = *(undefined4 *)(iVar1 + 0x10);
    *(undefined4 *)(*(int *)(iVar3 + 0x18) + 0x14) = *(undefined4 *)(iVar1 + 0x14);
    *(float *)(*(int *)(iVar3 + 0x18) + 0x10) =
         *(float *)(*(int *)(iVar3 + 0x18) + 0x10) + FLOAT_803e6f68;
  }
  if (((in_r8 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) && (*(short *)(iVar2 + 0x402) != 0)) {
    if (*(float *)(iVar2 + 1000) != FLOAT_803e6f40) {
      FUN_8003b6d8(200,0,0,(char)(int)*(float *)(iVar2 + 1000));
    }
    FUN_8003b9ec(iVar1);
    if ((*(ushort *)(iVar2 + 0x400) & 0x60) != 0) {
      FUN_8009a010((double)FLOAT_803e6f60,(double)*(float *)(iVar2 + 1000),iVar1,3,(int *)0x0);
    }
    iVar2 = *(int *)(iVar3 + 0x18);
    if ((iVar2 != 0) && (*(int *)(iVar2 + 0x50) != 0)) {
      FUN_80038524(iVar1,3,(float *)(iVar2 + 0xc),(undefined4 *)(iVar2 + 0x10),
                   (float *)(iVar2 + 0x14),0);
      FUN_8003b9ec(*(int *)(iVar3 + 0x18));
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80203c6c
 * EN v1.0 Address: 0x80203C6C
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203c6c(int param_1)
{
  (**(code **)(*DAT_803dd70c + 0xc))(param_1,*(undefined4 *)(param_1 + 0xb8),&DAT_803add54);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80203ca8
 * EN v1.0 Address: 0x80203CA8
 * EN v1.0 Size: 1080b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80203ca8(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined4 in_r7;
  undefined4 uVar5;
  undefined4 in_r8;
  undefined4 uVar6;
  undefined4 in_r9;
  undefined4 uVar7;
  undefined4 in_r10;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  double extraout_f1;
  double dVar13;
  undefined8 extraout_f1_00;
  undefined8 uVar14;
  uint local_48 [3];
  float local_3c;
  float local_38;
  float local_34;
  
  uVar2 = FUN_80286830();
  iVar12 = *(int *)(uVar2 + 0xb8);
  iVar11 = *(int *)(uVar2 + 0x4c);
  iVar10 = *(int *)(iVar12 + 0x40c);
  *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
  if ((*(byte *)(iVar10 + 0x44) >> 4 & 1) != 0) {
    sVar1 = *(short *)(iVar11 + 0x24);
    uVar3 = FUN_80013a08(0x14,0xc);
    *(undefined4 *)(iVar10 + 0x24) = uVar3;
    iVar8 = (int)*(short *)(&DAT_8032a158 + sVar1 * 8);
    iVar9 = iVar8 * 0xc;
    for (; iVar8 != 0; iVar8 = iVar8 + -1) {
      iVar9 = iVar9 + -0xc;
      FUN_80013978(*(short **)(iVar10 + 0x24),(uint)((&PTR_DAT_8032a154)[sVar1 * 2] + iVar9));
    }
    *(undefined *)(iVar10 + 0x34) = 1;
    *(byte *)(iVar10 + 0x44) = *(byte *)(iVar10 + 0x44) & 0xef;
  }
  uVar4 = FUN_80020078((int)*(short *)(iVar12 + 0x3f6));
  if (uVar4 != 0) {
    if (*(int *)(uVar2 + 0xf4) == 0) {
      if (*(int *)(uVar2 + 0xf8) == 0) {
        *(undefined4 *)(uVar2 + 0xc) = *(undefined4 *)(iVar11 + 8);
        *(undefined4 *)(uVar2 + 0x10) = *(undefined4 *)(iVar11 + 0xc);
        *(undefined4 *)(uVar2 + 0x14) = *(undefined4 *)(iVar11 + 0x10);
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar11 + 0x2e),uVar2,0xffffffff);
        *(undefined4 *)(uVar2 + 0xf8) = 1;
      }
      else {
        iVar10 = (**(code **)(*DAT_803dd738 + 0x30))(uVar2,iVar12,0);
        if (iVar10 == 0) {
          *(undefined2 *)(iVar12 + 0x402) = 0;
        }
        else {
          iVar10 = *(int *)(iVar12 + 0x2d0);
          dVar13 = extraout_f1;
          if (iVar10 != 0) {
            local_3c = *(float *)(iVar10 + 0x18) - *(float *)(uVar2 + 0x18);
            param_4 = (double)local_3c;
            local_38 = *(float *)(iVar10 + 0x1c) - *(float *)(uVar2 + 0x1c);
            param_3 = (double)local_38;
            local_34 = *(float *)(iVar10 + 0x20) - *(float *)(uVar2 + 0x20);
            param_2 = (double)(local_34 * local_34);
            dVar13 = FUN_80293900((double)(float)(param_2 +
                                                 (double)((float)(param_4 * param_4) +
                                                         (float)(param_3 * param_3))));
            *(float *)(iVar12 + 0x2c0) = (float)dVar13;
          }
          local_48[0] = 0;
          local_48[1] = 0;
          iVar10 = *(int *)(*(int *)(uVar2 + 0xb8) + 0x40c);
          while (iVar11 = FUN_800375e4(uVar2,local_48,local_48 + 2,local_48 + 1), iVar11 != 0) {
            if ((local_48[0] == 0x11) && (*(short *)(iVar10 + 0x1c) != -1)) {
              uVar3 = 0x14;
              FUN_800379bc(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           *(int *)(iVar10 + 0x18),0x11,uVar2,0x14,in_r7,in_r8,in_r9,in_r10);
              *(undefined4 *)(iVar10 + 0x18) = 0;
              *(undefined2 *)(iVar10 + 0x1c) = 0xffff;
              dVar13 = (double)FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,
                                            param_6,param_7,param_8,uVar2,0xf,0,uVar3,in_r7,in_r8,
                                            in_r9,in_r10);
            }
          }
          iVar10 = (**(code **)(*DAT_803dd738 + 0x50))
                             (uVar2,iVar12,iVar12 + 0x35c,(int)*(short *)(iVar12 + 0x3f4),
                              &DAT_8032a2a4,&DAT_8032a31c,1,&DAT_803add20);
          uVar14 = extraout_f1_00;
          if (iVar10 != 0) {
            DAT_803add2c = *(undefined4 *)(uVar2 + 0xc);
            DAT_803add30 = *(undefined4 *)(uVar2 + 0x10);
            DAT_803add34 = *(undefined4 *)(uVar2 + 0x14);
            uVar14 = FUN_8009a468(uVar2,&DAT_803add20,1,(int *)0x0);
          }
          if (*(short *)(iVar12 + 0x402) == 0) {
            FUN_8020377c(uVar2,iVar12,iVar12);
          }
          else {
            iVar10 = *(int *)(iVar12 + 0x40c);
            FUN_80203638(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2,iVar12
                        );
            (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e7020,uVar2,iVar12,0xffffffff);
            if ((*(byte *)(iVar10 + 0x15) & 4) == 0) {
              (**(code **)(*DAT_803dd70c + 0x30))((double)FLOAT_803dc074,uVar2,iVar12,4);
            }
            *(undefined4 *)(iVar12 + 0x3e0) = *(undefined4 *)(uVar2 + 0xc0);
            *(undefined4 *)(uVar2 + 0xc0) = 0;
            (**(code **)(*DAT_803dd70c + 8))
                      ((double)FLOAT_803dc074,(double)FLOAT_803dc074,uVar2,iVar12,&DAT_803add54,
                       &DAT_803add38);
            *(undefined4 *)(uVar2 + 0xc0) = *(undefined4 *)(iVar12 + 0x3e0);
          }
        }
      }
    }
    else if (((*(byte *)(iVar12 + 0x404) & 4) == 0) &&
            (iVar10 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar11 + 0x14)),
            iVar10 != 0)) {
      uVar3 = 0x10;
      uVar5 = 7;
      uVar6 = 0x10a;
      uVar7 = 0x26;
      iVar10 = *DAT_803dd738;
      (**(code **)(iVar10 + 0x58))((double)FLOAT_803e6f94,uVar2,iVar11,iVar12);
      FUN_800372f8(uVar2,3);
      *(undefined2 *)(iVar12 + 0x402) = 0;
      FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   uVar2,8,0x10,uVar3,uVar5,uVar6,uVar7,iVar10);
      *(undefined *)(iVar12 + 0x346) = 0;
      *(undefined *)(uVar2 + 0x36) = 0xff;
      *(byte *)(uVar2 + 0xaf) = *(byte *)(uVar2 + 0xaf) | 8;
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802040e0
 * EN v1.0 Address: 0x802040E0
 * EN v1.0 Size: 432b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802040e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80204290
 * EN v1.0 Address: 0x80204290
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204290(void)
{
  FUN_802042b0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802042b0
 * EN v1.0 Address: 0x802042B0
 * EN v1.0 Size: 296b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802042b0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802043d8
 * EN v1.0 Address: 0x802043D8
 * EN v1.0 Size: 396b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802043d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  uint uVar2;
  undefined2 *puVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  int local_28 [10];
  
  uVar2 = FUN_8028683c();
  iVar7 = *(int *)(uVar2 + 0x4c);
  uVar8 = extraout_f1;
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar6 = iVar6 + 1) {
    if ((((*(char *)(param_11 + iVar6 + 0x81) == '\x01') &&
         (uVar4 = FUN_80020078((int)*(char *)(iVar7 + 0x19) + 0xa29), uVar4 == 0)) &&
        (uVar4 = FUN_8002e144(), (uVar4 & 0xff) != 0)) &&
       (uVar4 = FUN_8005b60c(0x4658a,(int *)0x0,(int *)0x0,(int *)0x0,(uint *)0x0), uVar4 != 0)) {
      puVar3 = FUN_8002becc(0x38,0x539);
      uVar8 = FUN_80003494((uint)puVar3,uVar4,0x38);
      *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(uVar2 + 0xc);
      *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(uVar2 + 0x10);
      *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(uVar2 + 0x14);
      *(undefined4 *)(puVar3 + 10) = 0xffffffff;
      puVar3[0xd] = 0x95;
      FUN_8002b678(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2,puVar3);
    }
  }
  uVar4 = FUN_80020078((int)*(short *)(iVar7 + 0x1e));
  if ((uVar4 != 0) || (DAT_803de960 != 0)) {
    piVar5 = FUN_80037048(0x24,local_28);
    FUN_800377d0(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,3,uVar2,0x11,0,
                 param_14,param_15,param_16);
    while (iVar6 = local_28[0] + -1, bVar1 = local_28[0] != 0, local_28[0] = iVar6, bVar1) {
      iVar6 = *piVar5;
      piVar5 = piVar5 + 1;
      FUN_8003709c(iVar6,0x24);
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204564
 * EN v1.0 Address: 0x80204564
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204564(int param_1)
{
  FUN_8003709c(param_1,0x1e);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204588
 * EN v1.0 Address: 0x80204588
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204588(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802045bc
 * EN v1.0 Address: 0x802045BC
 * EN v1.0 Size: 148b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802045bc(int param_1)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x1e));
  if (uVar1 == 0) {
    uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x20));
    if (uVar1 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar2 + 0x19),param_1,0xffffffff);
    }
  }
  else {
    FUN_8002cf80(param_1);
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204650
 * EN v1.0 Address: 0x80204650
 * EN v1.0 Size: 128b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204650(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802046d0
 * EN v1.0 Address: 0x802046D0
 * EN v1.0 Size: 648b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802046d0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  int iVar2;
  uint uVar3;
  char cVar4;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short sVar5;
  undefined2 *puVar6;
  undefined2 *puVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  
  uVar1 = FUN_80286840();
  puVar7 = *(undefined2 **)(uVar1 + 0xb8);
  uVar8 = extraout_f1;
  iVar2 = FUN_8002bac4();
  if (DAT_803dcdeb != '\0') {
    FUN_800201ac(0x2d,1);
    FUN_800201ac(0x1d7,1);
    puVar6 = &DAT_8032a488;
    for (sVar5 = 0; sVar5 < 9; sVar5 = sVar5 + 1) {
      uVar3 = FUN_80022264(1,4);
      *puVar6 = (short)uVar3;
      puVar6 = puVar6 + 1;
    }
    uVar8 = FUN_800201ac(0x5e4,0);
    *puVar7 = 0;
    DAT_803dcdeb = '\0';
  }
  uVar3 = FUN_80020078(0x5e3);
  if (((uVar3 == 0) && (uVar3 = FUN_80020078(0x5e0), uVar3 != 0)) &&
     (uVar3 = FUN_80020078(0x5e1), uVar3 != 0)) {
    FUN_8000bb38(uVar1,0x7a);
    uVar8 = FUN_800201ac(0x5e3,1);
  }
  uVar3 = FUN_80020078(0x792);
  if (((uVar3 == 0) && (uVar3 = FUN_80020078(0xb8c), uVar3 != 0)) &&
     (uVar3 = FUN_80020078(0xb8c), uVar3 != 0)) {
    FUN_8000bb38(uVar1,0x7a);
    uVar8 = FUN_800201ac(0x792,1);
  }
  uVar3 = FUN_80020078(0xe58);
  if (uVar3 == 0) {
    uVar3 = FUN_80020078(0x635);
    if ((uVar3 == 0) || (*(char *)(puVar7 + 3) != '\0')) {
      uVar3 = FUN_80020078(0x635);
      if ((uVar3 == 0) && (*(char *)(puVar7 + 3) == '\x01')) {
        *(undefined *)(puVar7 + 3) = 0;
        uVar8 = FUN_800201ac(0x5e4,0);
      }
    }
    else {
      FUN_8000bb38(0,0x1c4);
      puVar6 = &DAT_8032a488;
      for (sVar5 = 0; sVar5 < 9; sVar5 = sVar5 + 1) {
        uVar3 = FUN_80022264(1,4);
        *puVar6 = (short)uVar3;
        puVar6 = puVar6 + 1;
      }
      uVar8 = FUN_800201ac(0x5e4,1);
      *(undefined *)(puVar7 + 3) = 1;
    }
    uVar3 = FUN_80020078(0x5e5);
    if (uVar3 != 0) {
      *puVar7 = 300;
      FUN_800379bc(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x60005,uVar1
                   ,0,in_r7,in_r8,in_r9,in_r10);
    }
  }
  uVar3 = FUN_80020078(0x7a1);
  if ((uVar3 != 0) &&
     (cVar4 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(uVar1 + 0xac),6), cVar4 == '\0')) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(uVar1 + 0xac),6,1);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204958
 * EN v1.0 Address: 0x80204958
 * EN v1.0 Size: 460b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204958(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  short sVar4;
  undefined2 *puVar5;
  undefined2 *puVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  
  uVar1 = FUN_80286840();
  puVar6 = *(undefined2 **)(uVar1 + 0xb8);
  uVar7 = extraout_f1;
  iVar2 = FUN_8002bac4();
  if (DAT_803dcdea != '\0') {
    puVar5 = &DAT_8032a488;
    DAT_8032a494 = 0;
    DAT_8032a496 = 0;
    DAT_8032a498 = 0;
    for (sVar4 = 0; sVar4 < 6; sVar4 = sVar4 + 1) {
      uVar3 = FUN_80022264(1,4);
      *puVar5 = (short)uVar3;
      puVar5 = puVar5 + 1;
    }
    uVar7 = FUN_800201ac(0x5e4,0);
    *puVar6 = 0;
    DAT_803dcdea = '\0';
  }
  uVar3 = FUN_80020078(0x5e3);
  if (((uVar3 == 0) && (uVar3 = FUN_80020078(0x5e0), uVar3 != 0)) &&
     (uVar3 = FUN_80020078(0x5e1), uVar3 != 0)) {
    uVar7 = FUN_800201ac(0x5e3,1);
  }
  uVar3 = FUN_80020078(0xe57);
  if (uVar3 == 0) {
    uVar3 = FUN_80020078(0x635);
    if ((uVar3 == 0) || (*(char *)(puVar6 + 3) != '\0')) {
      uVar3 = FUN_80020078(0x635);
      if ((uVar3 == 0) && (*(char *)(puVar6 + 3) == '\x01')) {
        *(undefined *)(puVar6 + 3) = 0;
        uVar7 = FUN_800201ac(0x5e4,0);
      }
    }
    else {
      FUN_8000bb38(0,0x447);
      puVar5 = &DAT_8032a488;
      for (sVar4 = 0; sVar4 < 6; sVar4 = sVar4 + 1) {
        uVar3 = FUN_80022264(1,4);
        *puVar5 = (short)uVar3;
        puVar5 = puVar5 + 1;
      }
      uVar7 = FUN_800201ac(0x5e4,1);
      *(undefined *)(puVar6 + 3) = 1;
    }
    uVar3 = FUN_80020078(0x5e5);
    if (uVar3 != 0) {
      *puVar6 = 300;
      FUN_800379bc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x60005,uVar1
                   ,1,in_r7,in_r8,in_r9,in_r10);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204b24
 * EN v1.0 Address: 0x80204B24
 * EN v1.0 Size: 204b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80204b24(int param_1)
{
  short sVar1;
  int iVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0xb8);
  iVar2 = FUN_8002bac4();
  sVar1 = *psVar3;
  if (0 < sVar1) {
    *psVar3 = sVar1 - (short)(int)FLOAT_803dc074;
    FUN_80296848(iVar2,0x51e);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80204bf0
 * EN v1.0 Address: 0x80204BF0
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204bf0(int param_1)
{
  FUN_8003709c(param_1,9);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204c1c
 * EN v1.0 Address: 0x80204C1C
 * EN v1.0 Size: 524b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204c1c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  byte bVar6;
  int iVar7;
  undefined8 extraout_f1;
  double dVar8;
  
  iVar1 = FUN_8028683c();
  iVar7 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_8002bac4();
  uVar3 = FUN_80020078(0xd5d);
  uVar4 = FUN_80020078(0xd59);
  uVar5 = FUN_80020078(0xd5a);
  if (((((uVar3 & 0xff) != 0) && (-1 < *(char *)(iVar7 + 7))) ||
      (((uVar4 & 0xff) != 0 && ((*(byte *)(iVar7 + 7) >> 6 & 1) == 0)))) ||
     (((uVar5 & 0xff) != 0 && ((*(byte *)(iVar7 + 7) >> 5 & 1) == 0)))) {
    FUN_8000bb38(0,0x109);
  }
  *(byte *)(iVar7 + 7) = (byte)((uVar3 & 0xff) << 7) | *(byte *)(iVar7 + 7) & 0x7f;
  *(byte *)(iVar7 + 7) = (byte)((uVar4 & 0xff) << 6) & 0x40 | *(byte *)(iVar7 + 7) & 0xbf;
  *(byte *)(iVar7 + 7) = (byte)((uVar5 & 0xff) << 5) & 0x20 | *(byte *)(iVar7 + 7) & 0xdf;
  uVar3 = FUN_80020078(0x5e8);
  if (((uVar3 == 0) && (uVar3 = FUN_80020078(0x5ee), uVar3 != 0)) &&
     (uVar3 = FUN_80020078(0x5ef), uVar3 != 0)) {
    FUN_800201ac(0x5e8,1);
  }
  dVar8 = (double)*(float *)(iVar2 + 0x14);
  FUN_8005b128();
  bVar6 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar1 + 0xac));
  if (bVar6 == 2) {
    FUN_802046d0(extraout_f1,dVar8,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else if ((bVar6 < 2) && (bVar6 != 0)) {
    if ((DAT_803dcde8 != 0) &&
       (DAT_803dcde8 = DAT_803dcde8 - (short)(int)FLOAT_803dc074, DAT_803dcde8 < 1)) {
      DAT_803dcde8 = 0;
    }
    FUN_80204958(extraout_f1,dVar8,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  FUN_801d84c4(iVar7 + 8,2,-1,-1,0xdce,(int *)0x95);
  FUN_801d8650(iVar7 + 8,4,-1,-1,0xdce,(int *)0x37);
  FUN_801d8650(iVar7 + 8,1,-1,-1,0xdce,(int *)0xe4);
  FUN_800201ac(0xdcf,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80204e28
 * EN v1.0 Address: 0x80204E28
 * EN v1.0 Size: 400b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204e28(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80204fb8
 * EN v1.0 Address: 0x80204FB8
 * EN v1.0 Size: 88b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204fb8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  if ((param_10 == 0) && (iVar1 = *piVar2, iVar1 != 0)) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
    *piVar2 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80205010
 * EN v1.0 Address: 0x80205010
 * EN v1.0 Size: 404b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80205010(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  iVar3 = *(int *)(param_9 + 0xb8);
  uVar1 = FUN_8002e144();
  if (((((uVar1 & 0xff) != 0) && (*(short *)(iVar4 + 0x1a) == 7)) &&
      (*(short *)(iVar3 + 0x10) = *(short *)(iVar3 + 0x10) - (short)(int)FLOAT_803dc074,
      *(short *)(iVar3 + 0x10) < 1)) &&
     (uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0xc)), uVar1 != 0)) {
    *(undefined2 *)(iVar3 + 0x10) = *(undefined2 *)(iVar3 + 0xe);
    puVar2 = FUN_8002becc(0x24,0x71b);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 8);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0xc);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x10);
    *(undefined *)(puVar2 + 2) = *(undefined *)(iVar4 + 4);
    *(undefined *)((int)puVar2 + 5) = *(undefined *)(iVar4 + 5);
    *(undefined *)(puVar2 + 3) = *(undefined *)(iVar4 + 6);
    *(undefined *)((int)puVar2 + 7) = *(undefined *)(iVar4 + 7);
    puVar2[0xf] = 0xffff;
    puVar2[0x10] = 0xffff;
    puVar2[0xd] = 0xdc;
    iVar3 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                         *(undefined *)(param_9 + 0xac),0xffffffff,*(uint **)(param_9 + 0x30),in_r8,
                         in_r9,in_r10);
    *(int *)(iVar3 + 0xf4) = (int)*(char *)(iVar4 + 0x1e);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802051a4
 * EN v1.0 Address: 0x802051A4
 * EN v1.0 Size: 88b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802051a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)
{
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar1;
  
  uVar1 = (**(code **)(*DAT_803dd6f8 + 0x18))();
  FUN_800066e0(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0,0,0,0
               ,in_r9,in_r10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802051fc
 * EN v1.0 Address: 0x802051FC
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802051fc(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80205230
 * EN v1.0 Address: 0x80205230
 * EN v1.0 Size: 1068b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80205230(uint param_1)
{
  short sVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  bool bVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  
  iVar7 = *(int *)(param_1 + 0x4c);
  iVar8 = *(int *)(param_1 + 0xb8);
  iVar4 = FUN_8002bac4();
  fVar2 = FLOAT_803e7040;
  fVar3 = FLOAT_803e7038;
  if (iVar4 != 0) {
    sVar1 = *(short *)(iVar8 + 4);
    if (sVar1 == 2) {
      if (*(short *)(iVar8 + 10) == 0) {
        dVar9 = (double)FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
        if ((double)FLOAT_803e703c <= dVar9) {
          if (*(float *)(iVar7 + 0xc) <= *(float *)(iVar4 + 0x10)) {
            if ((*(float *)(iVar7 + 0xc) < *(float *)(iVar4 + 0x10)) &&
               (*(undefined2 *)(iVar8 + 4) = 4, *(char *)(iVar8 + 0xd) == '\x01')) {
              *(undefined *)(iVar8 + 0xd) = 0;
            }
          }
          else {
            *(undefined2 *)(iVar8 + 4) = 3;
            if (*(char *)(iVar8 + 0xd) == '\x01') {
              *(undefined *)(iVar8 + 0xd) = 0;
            }
          }
        }
        else if (*(float *)(param_1 + 0x10) == FLOAT_803e7038 + *(float *)(iVar7 + 0xc)) {
          *(undefined2 *)(iVar8 + 4) = 3;
          bVar6 = FUN_8000b598(param_1,8);
          if (!bVar6) {
            FUN_8000bb38(param_1,0x1cb);
            *(undefined *)(iVar8 + 0xd) = 1;
          }
        }
        else if (*(float *)(param_1 + 0x10) == *(float *)(iVar7 + 0xc) - FLOAT_803e7040) {
          *(undefined2 *)(iVar8 + 4) = 4;
          bVar6 = FUN_8000b598(param_1,8);
          if (!bVar6) {
            FUN_8000bb38(param_1,0x1cb);
            *(undefined *)(iVar8 + 0xd) = 1;
          }
        }
      }
      else {
        *(short *)(iVar8 + 10) = *(short *)(iVar8 + 10) - (short)(int)FLOAT_803dc074;
        if (*(short *)(iVar8 + 10) < 1) {
          *(undefined2 *)(iVar8 + 10) = 0;
        }
      }
    }
    else if (sVar1 < 2) {
      if (sVar1 == 0) {
        uVar5 = FUN_80020078((int)*(short *)(iVar8 + 6));
        if (((uVar5 == 0) || (*(char *)(iVar8 + 0xc) == '\x01')) ||
           (dVar9 = (double)FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18)),
           (double)FLOAT_803e7034 <= dVar9)) {
          if (((*(char *)(iVar8 + 0xc) == '\x01') &&
              (dVar9 = (double)FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18)),
              fVar2 = FLOAT_803e7038, dVar9 < (double)FLOAT_803e7034)) &&
             (*(float *)(param_1 + 0x10) < FLOAT_803e7038 + *(float *)(iVar7 + 0xc))) {
            *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803dc074;
            fVar2 = fVar2 + *(float *)(iVar7 + 0xc);
            if (fVar2 <= *(float *)(param_1 + 0x10)) {
              *(float *)(param_1 + 0x10) = fVar2;
              *(undefined2 *)(iVar8 + 4) = 1;
            }
          }
        }
        else if (*(float *)(param_1 + 0x10) < FLOAT_803e7038 + *(float *)(iVar7 + 0xc)) {
          bVar6 = FUN_8000b598(param_1,8);
          if (!bVar6) {
            FUN_8000bb38(param_1,0x116);
            *(undefined *)(iVar8 + 0xd) = 1;
          }
          *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803dc074;
          fVar2 = FLOAT_803e7038 + *(float *)(iVar7 + 0xc);
          if (fVar2 <= *(float *)(param_1 + 0x10)) {
            *(float *)(param_1 + 0x10) = fVar2;
            *(undefined2 *)(iVar8 + 4) = 1;
            FUN_8000b7dc(param_1,8);
          }
        }
      }
      else if (-1 < sVar1) {
        *(undefined2 *)(iVar8 + 4) = 2;
        *(undefined2 *)(iVar8 + 10) = 100;
      }
    }
    else if (sVar1 == 4) {
      if (FLOAT_803e7038 + *(float *)(iVar7 + 0xc) <= *(float *)(param_1 + 0x10)) {
        *(undefined2 *)(iVar8 + 4) = 2;
        *(undefined2 *)(iVar8 + 10) = 100;
        FUN_8000b7dc(param_1,8);
        FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
      }
      else {
        *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803dc074;
        fVar3 = fVar3 + *(float *)(iVar7 + 0xc);
        if (fVar3 <= *(float *)(param_1 + 0x10)) {
          *(float *)(param_1 + 0x10) = fVar3;
          *(undefined2 *)(iVar8 + 4) = 2;
          *(undefined2 *)(iVar8 + 10) = 100;
          FUN_8000b7dc(param_1,8);
        }
        FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
      }
    }
    else if (sVar1 < 4) {
      if (*(float *)(param_1 + 0x10) <= *(float *)(iVar7 + 0xc) - FLOAT_803e7040) {
        FUN_8000b7dc(param_1,8);
        FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
        *(undefined2 *)(iVar8 + 4) = 2;
        *(undefined2 *)(iVar8 + 10) = 100;
      }
      else {
        *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - FLOAT_803dc074;
        fVar2 = *(float *)(iVar7 + 0xc) - fVar2;
        if (*(float *)(param_1 + 0x10) <= fVar2) {
          *(float *)(param_1 + 0x10) = fVar2;
          *(undefined2 *)(iVar8 + 4) = 2;
          FUN_8000b7dc(param_1,8);
          *(undefined2 *)(iVar8 + 10) = 100;
        }
        FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8020565c
 * EN v1.0 Address: 0x8020565C
 * EN v1.0 Size: 176b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020565c(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020570c
 * EN v1.0 Address: 0x8020570C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020570c(void)
{
  FUN_8007d858();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80205740
 * EN v1.0 Address: 0x80205740
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80205740(void)
{
  FUN_8007d858();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8020576c
 * EN v1.0 Address: 0x8020576C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020576c(void)
{
  FUN_8007d858();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802057a0
 * EN v1.0 Address: 0x802057A0
 * EN v1.0 Size: 696b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802057a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  int iVar2;
  char cVar4;
  undefined4 uVar3;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  
  iVar2 = FUN_80286840();
  iVar8 = *(int *)(iVar2 + 0xb8);
  iVar7 = *(int *)(iVar2 + 0x4c);
  *(undefined2 *)(param_11 + 0x70) = 0xffff;
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar6 = iVar6 + 1) {
    sVar1 = *(short *)(iVar8 + 8);
    if (sVar1 == 10) {
      if (*(char *)(param_11 + iVar6 + 0x81) == '\x14') {
        if (*(int *)(iVar7 + 0x14) == 0x49de8) {
          *(byte *)(iVar8 + 0xf) = *(byte *)(iVar8 + 0xf) & 0x7f | 0x80;
        }
        else {
          cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar2 + 0xac));
          if ((cVar4 == '\x01') ||
             (cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar2 + 0xac)),
             cVar4 == '\x02')) {
            FUN_80043604(0,0,1);
            uVar3 = FUN_8004832c(0x32);
            FUN_80043658(uVar3,0);
            iVar5 = *DAT_803dd72c;
            uVar9 = (**(code **)(iVar5 + 0x44))(0x32,2);
            FUN_80055464(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x73,'\0',
                         iVar5,param_12,param_13,param_14,param_15,param_16);
          }
        }
      }
    }
    else if (((sVar1 < 10) && (sVar1 == 1)) && (*(char *)(param_11 + iVar6 + 0x81) == '\x01')) {
      cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar2 + 0xac));
      if (cVar4 == '\x01') {
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),5,0);
        (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),6,0);
        param_12 = *DAT_803dd72c;
        (**(code **)(param_12 + 0x50))((int)*(char *)(iVar2 + 0xac),7,0);
      }
      else {
        cVar4 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar2 + 0xac));
        if (cVar4 == '\x02') {
          (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),5,0);
          (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar2 + 0xac),6,0);
          param_12 = *DAT_803dd72c;
          (**(code **)(param_12 + 0x50))((int)*(char *)(iVar2 + 0xac),7,0);
        }
      }
    }
    *(undefined *)(param_11 + iVar6 + 0x81) = 0;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80205a58
 * EN v1.0 Address: 0x80205A58
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80205a58(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80205a8c
 * EN v1.0 Address: 0x80205A8C
 * EN v1.0 Size: 732b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80205a8c(int param_1)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  float *pfVar4;
  double dVar5;
  
  iVar2 = FUN_8002bac4();
  pfVar4 = *(float **)(param_1 + 0xb8);
  if (*(char *)((int)pfVar4 + 0xf) < '\0') {
    FUN_800201ac(0xef7,1);
    *(byte *)((int)pfVar4 + 0xf) = *(byte *)((int)pfVar4 + 0xf) & 0x7f;
  }
  uVar3 = (uint)*(short *)((int)pfVar4 + 6);
  if (uVar3 != 0xffffffff) {
    if (*(char *)((int)pfVar4 + 0xd) != '\0') {
      uVar3 = FUN_80020078(uVar3);
      if (uVar3 != 0) {
        return;
      }
      FUN_800201ac((int)*(short *)((int)pfVar4 + 6),1);
      *(undefined *)((int)pfVar4 + 0xd) = 1;
      return;
    }
    uVar3 = FUN_80020078(uVar3);
    if (uVar3 != 0) {
      *(undefined *)((int)pfVar4 + 0xd) = 1;
      return;
    }
  }
  if (*(char *)((int)pfVar4 + 0xd) == '\0') {
    bVar1 = *(byte *)((int)pfVar4 + 0xe);
    if (bVar1 == 3) {
      dVar5 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
      if (((dVar5 < (double)*pfVar4) && ((int)*(short *)(pfVar4 + 1) != 0xffffffff)) &&
         (uVar3 = FUN_80020078((int)*(short *)(pfVar4 + 1)), uVar3 == 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
        FUN_800201ac((int)*(short *)(pfVar4 + 1),1);
        *(undefined *)((int)pfVar4 + 0xd) = 1;
      }
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        if (((int)*(short *)(pfVar4 + 1) != 0xffffffff) &&
           (uVar3 = FUN_80020078((int)*(short *)(pfVar4 + 1)), uVar3 != 0)) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
      else if (bVar1 == 0) {
        dVar5 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
        if (dVar5 < (double)*pfVar4) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
      else {
        dVar5 = (double)FUN_800217c8((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
        if (((dVar5 < (double)*pfVar4) && ((int)*(short *)(pfVar4 + 1) != 0xffffffff)) &&
           (uVar3 = FUN_80020078((int)*(short *)(pfVar4 + 1)), uVar3 != 0)) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
          *(undefined *)((int)pfVar4 + 0xd) = 1;
        }
      }
    }
    else if (bVar1 == 5) {
      if (((int)*(short *)(pfVar4 + 1) != 0xffffffff) &&
         (uVar3 = FUN_80020078((int)*(short *)(pfVar4 + 1)), uVar3 != 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
      }
    }
    else if (((bVar1 < 5) && ((int)*(short *)(pfVar4 + 1) != 0xffffffff)) &&
            (uVar3 = FUN_80020078((int)*(short *)(pfVar4 + 1)), uVar3 == 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(short *)(pfVar4 + 2),param_1,0xffffffff);
      FUN_800201ac((int)*(short *)(pfVar4 + 1),1);
      *(undefined *)((int)pfVar4 + 0xd) = 1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80205d68
 * EN v1.0 Address: 0x80205D68
 * EN v1.0 Size: 172b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80205d68(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80205e14
 * EN v1.0 Address: 0x80205E14
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80205e14(undefined4 param_1)
{
  (**(code **)(*DAT_803dd6fc + 0x18))();
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80205e68
 * EN v1.0 Address: 0x80205E68
 * EN v1.0 Size: 612b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80205e68(int param_1)
{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  char in_r8;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined4 auStack_78 [2];
  short asStack_70 [4];
  short asStack_68 [4];
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  undefined auStack_3c [12];
  float local_30;
  float local_2c;
  float local_28;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if (in_r8 == '\0') {
    *(undefined2 *)(iVar5 + 4) = 0;
    *(undefined *)(iVar5 + 8) = 0;
  }
  else {
    FUN_8003b9ec(param_1);
    if (*(char *)(iVar5 + 10) != '\0') {
      *(undefined *)(iVar5 + 8) = 1;
      puVar2 = FUN_8000facc();
      local_48 = *(float *)(puVar2 + 6) - *(float *)(param_1 + 0xc);
      local_44 = *(float *)(puVar2 + 8) - *(float *)(param_1 + 0x10);
      local_40 = *(float *)(puVar2 + 10) - *(float *)(param_1 + 0x14);
      dVar6 = FUN_80293900((double)(local_40 * local_40 + local_48 * local_48 + local_44 * local_44)
                          );
      if ((double)FLOAT_803e7064 < dVar6) {
        fVar1 = (float)((double)FLOAT_803e7060 / dVar6);
        local_48 = local_48 * fVar1;
        dVar12 = (double)local_48;
        local_44 = local_44 * fVar1;
        dVar11 = (double)local_44;
        local_40 = local_40 * fVar1;
        dVar10 = (double)local_40;
        dVar6 = (double)FLOAT_803e7068;
        local_54 = (float)(dVar6 * dVar12) + *(float *)(param_1 + 0xc);
        local_50 = (float)(dVar6 * dVar11) + *(float *)(param_1 + 0x10);
        local_4c = (float)(dVar6 * dVar10) + *(float *)(param_1 + 0x14);
        dVar6 = (double)FLOAT_803e706c;
        dVar9 = (double)(float)(dVar6 * dVar12);
        dVar8 = (double)(float)(dVar6 * dVar11);
        local_60 = (float)(dVar9 + (double)*(float *)(puVar2 + 6));
        local_5c = (float)(dVar8 + (double)*(float *)(puVar2 + 8));
        local_58 = (float)(dVar6 * dVar10) + *(float *)(puVar2 + 10);
        FUN_80012d20(&local_54,asStack_68);
        uVar7 = FUN_80012d20(&local_60,asStack_70);
        iVar3 = FUN_800128fc(uVar7,dVar8,dVar9,dVar10,dVar11,dVar12,in_f7,in_f8,asStack_68,
                             asStack_70,auStack_78,(undefined *)0x0,0);
        if (iVar3 == 0) {
          *(undefined *)(iVar5 + 8) = 0;
          (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
        }
      }
      if (*(short *)(iVar5 + 4) < 1) {
        if (*(char *)(iVar5 + 8) != '\0') {
          local_30 = FLOAT_803e7070;
          local_2c = FLOAT_803e7074;
          local_28 = FLOAT_803e7070;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x1f7,auStack_3c,0x12,0xffffffff,0);
        }
        uVar4 = FUN_80022264(0xfffffff6,10);
        *(short *)(iVar5 + 4) = (short)uVar4 + 0x3c;
      }
      else {
        *(short *)(iVar5 + 4) = *(short *)(iVar5 + 4) - (short)(int)FLOAT_803dc074;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_802060cc
 * EN v1.0 Address: 0x802060CC
 * EN v1.0 Size: 888b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802060cc(uint param_1)
{
  int iVar1;
  int *piVar2;
  uint uVar3;
  uint *puVar4;
  undefined4 local_48;
  int local_44;
  int local_40;
  undefined4 local_3c;
  undefined auStack_38 [16];
  float local_28;
  longlong local_20;
  
  puVar4 = *(uint **)(param_1 + 0xb8);
  local_48 = DAT_802c2c90;
  local_44 = DAT_802c2c94;
  local_40 = DAT_802c2c98;
  local_3c = DAT_802c2c9c;
  FUN_8000bb38(param_1,0x72);
  FUN_8005a310(param_1);
  if (*(char *)((int)puVar4 + 9) == '\x01') {
    local_28 = FLOAT_803e7078;
    *(undefined *)(puVar4 + 3) = *(undefined *)((int)puVar4 + 10);
    iVar1 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if ((iVar1 != 0) &&
       (*(char *)((int)puVar4 + 10) = '\x01' - *(char *)((int)puVar4 + 10),
       *(char *)((int)puVar4 + 10) != '\0')) {
      *(undefined2 *)((int)puVar4 + 6) = 2000;
    }
    if ((*(char *)((int)puVar4 + 10) != '\0') && (*(short *)((int)puVar4 + 6) != 0)) {
      local_20 = (longlong)(int)FLOAT_803dc074;
      *(short *)((int)puVar4 + 6) = *(short *)((int)puVar4 + 6) - (short)(int)FLOAT_803dc074;
      if (*(short *)((int)puVar4 + 6) < 1) {
        *(undefined2 *)((int)puVar4 + 6) = 0;
        *(undefined *)((int)puVar4 + 10) = 0;
      }
    }
    if (((*(char *)((int)puVar4 + 10) != '\0') && (*(short *)(puVar4 + 1) < 1)) &&
       (*(char *)((int)puVar4 + 0xb) != '\0')) {
      *(undefined *)((int)puVar4 + 0xb) = 0;
      FUN_8000bb38(param_1,0x80);
    }
    if (*(char *)((int)puVar4 + 10) != *(char *)(puVar4 + 3)) {
      if (*(char *)((int)puVar4 + 10) == '\0') {
        FUN_8000b7dc(param_1,0x40);
        (**(code **)(*DAT_803dd6fc + 0x18))(param_1);
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
        if ((*puVar4 != 0xffffffff) && (uVar3 = FUN_80020078(*puVar4), uVar3 != 0)) {
          FUN_800201ac(*puVar4,0);
        }
        if ((DAT_803de968 == '\x01') && (*(char *)((int)puVar4 + 0xd) == '\0')) {
          DAT_803de968 = '\0';
        }
        if (((DAT_803de968 == '\x02') && (*(char *)((int)puVar4 + 0xd) == '\x01')) &&
           (uVar3 = FUN_80020078(0x5e2), uVar3 == 0)) {
          FUN_800201ac(0x5e2,0);
          DAT_803de968 = '\0';
        }
      }
      else {
        piVar2 = (int *)FUN_80013ee8(0x69);
        local_40 = (uint)*(byte *)((int)puVar4 + 0xd) * 2;
        local_44 = local_40 + 0x19d;
        local_40 = local_40 + 0x19e;
        (**(code **)(*piVar2 + 4))(param_1,1,auStack_38,0x10004,0xffffffff,&local_48);
        FUN_80013e4c((undefined *)piVar2);
        iVar1 = 0;
        do {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x1a3,0,0,0xffffffff,0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < 100);
        if ((*puVar4 != 0xffffffff) && (uVar3 = FUN_80020078(*puVar4), uVar3 == 0)) {
          FUN_800201ac(*puVar4,1);
        }
        if (((DAT_803de968 == '\0') && (*(char *)((int)puVar4 + 0xd) == '\0')) &&
           (uVar3 = FUN_80020078(*puVar4), uVar3 != 0)) {
          DAT_803de968 = '\x01';
        }
        if (((DAT_803de968 == '\x01') && (*(char *)((int)puVar4 + 0xd) == '\x01')) &&
           (uVar3 = FUN_80020078(*puVar4), uVar3 != 0)) {
          FUN_800201ac(0x5e2,1);
          DAT_803de968 = '\x02';
        }
        *(undefined *)((int)puVar4 + 0xb) = 1;
        *(undefined2 *)(puVar4 + 1) = 1;
      }
    }
  }
  return;
}
