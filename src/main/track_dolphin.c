#include "ghidra_import.h"
#include "main/track_dolphin.h"

extern undefined4 ABS();
extern undefined4 FUN_80003494();
extern undefined4 FUN_8000df3c();
extern undefined4 FUN_8000dfc8();
extern undefined4 FUN_8000e054();
extern undefined8 FUN_8000e0c0();
extern undefined4 FUN_8000e338();
extern undefined4 FUN_8000ea98();
extern undefined4 FUN_8000edcc();
extern undefined4 FUN_8000f4a0();
extern undefined4 FUN_8000f56c();
extern undefined4 FUN_8000fb20();
extern undefined4 FUN_80013a84();
extern int FUN_8001fa3c();
extern int FUN_80020800();
extern int FUN_80021884();
extern undefined4 FUN_80021b8c();
extern undefined4 FUN_80022714();
extern undefined4 FUN_80022790();
extern undefined4 FUN_800228f0();
extern undefined4 FUN_80022974();
extern undefined4 FUN_80022a0c();
extern undefined4 FUN_80022a88();
extern uint FUN_80022b0c();
extern uint FUN_80022ee8();
extern int FUN_80023d8c();
extern undefined4 FUN_80028418();
extern undefined4 FUN_80028428();
extern undefined4 FUN_800284d8();
extern ushort FUN_800284f8();
extern undefined4 FUN_8002b270();
extern undefined4 FUN_8002b554();
extern undefined4 FUN_8002bac4();
extern undefined4 FUN_80036800();
extern undefined4 FUN_80036bf4();
extern void* FUN_80037048();
extern undefined4 FUN_80046644();
extern undefined4 FUN_80048d78();
extern undefined4 FUN_800490c4();
extern undefined4 FUN_8004c460();
extern undefined4 FUN_80054620();
extern undefined4 FUN_80056924();
extern int FUN_8005b068();
extern int FUN_8005b094();
extern int FUN_8005b0a8();
extern uint FUN_8005cf38();
extern undefined4 FUN_8005edfc();
extern int FUN_8005f6d4();
extern int FUN_8006c6c8();
extern int FUN_8006c740();
extern undefined4 FUN_8006d764();
extern int FUN_8006ff74();
extern undefined4 FUN_8007048c();
extern undefined4 FUN_80077780();
extern undefined4 FUN_80077a08();
extern undefined4 FUN_80077c54();
extern undefined4 FUN_80078074();
extern undefined4 FUN_80078b28();
extern undefined4 FUN_8007965c();
extern undefined4 FUN_80079980();
extern undefined4 FUN_80079b3c();
extern undefined4 FUN_80079b60();
extern int FUN_800893b8();
extern undefined4 FUN_800893c0();
extern byte FUN_80089428();
extern undefined4 FUN_80089a60();
extern undefined4 FUN_80089b54();
extern char FUN_8011f628();
extern undefined4 FUN_80137c30();
extern undefined4 FUN_80137cd0();
extern undefined4 FUN_80242114();
extern undefined4 FUN_802475e4();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247c4c();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double FUN_80247f3c();
extern double FUN_80247f54();
extern double FUN_80247f90();
extern undefined4 FUN_80247fb0();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_802585d8();
extern undefined4 FUN_80258674();
extern undefined4 FUN_80258944();
extern undefined4 FUN_80259000();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025be54();
extern undefined4 FUN_8025be80();
extern undefined4 FUN_8025c1a4();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c2a8();
extern undefined4 FUN_8025c368();
extern undefined4 FUN_8025c510();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025ca04();
extern undefined4 FUN_8025ca38();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d848();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_8025d8c4();
extern undefined8 FUN_8028680c();
extern undefined4 FUN_80286814();
extern undefined8 FUN_80286824();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286830();
extern int FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286858();
extern undefined4 FUN_80286860();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802925a0();
extern undefined4 FUN_80292d24();
extern double FUN_80293900();
extern undefined4 FUN_802947f8();
extern undefined4 FUN_80294b54();
extern undefined4 FUN_80297614();
extern uint countLeadingZeros();

extern int DAT_8030f1f4;
extern int DAT_80382c98;
extern undefined4 DAT_80382f14;
extern undefined4 DAT_8038859c;
extern undefined4 DAT_803885a0;
extern undefined4 DAT_803885a4;
extern undefined4 DAT_803885a8;
extern undefined4 DAT_80388610;
extern undefined4 DAT_80388614;
extern undefined4 DAT_80388618;
extern undefined4 DAT_8038861c;
extern undefined4 DAT_8038e3dc;
extern undefined4 DAT_8038e3e0;
extern undefined4 DAT_8038e3e4;
extern undefined4 DAT_8038e3e8;
extern undefined4 DAT_8038e3ec;
extern undefined4 DAT_8038e3f0;
extern undefined4 DAT_8038e3f4;
extern undefined4 DAT_8038e3f8;
extern undefined4 DAT_8038e3fc;
extern undefined4 DAT_8038e400;
extern undefined4 DAT_8038e404;
extern undefined4 DAT_8038e408;
extern undefined4 DAT_8038e40c;
extern undefined4 DAT_8038e410;
extern undefined4 DAT_8038e414;
extern undefined4 DAT_8038e418;
extern undefined4 DAT_8038e41c;
extern undefined4 DAT_8038e420;
extern undefined4 DAT_8038e424;
extern undefined4 DAT_8038e428;
extern undefined4 DAT_8038e42c;
extern undefined4 DAT_8038e430;
extern undefined4 DAT_8038e434;
extern undefined4 DAT_8038e438;
extern undefined4 DAT_8038e43c;
extern undefined4 DAT_8038e440;
extern undefined4 DAT_8038e444;
extern undefined4 DAT_8038e448;
extern undefined4 DAT_8038e44c;
extern undefined4 DAT_8038e450;
extern undefined4 DAT_8038e454;
extern undefined4 DAT_8038e458;
extern undefined4 DAT_8038e45c;
extern undefined4 DAT_8038e460;
extern undefined4 DAT_8038e464;
extern undefined4 DAT_8038e468;
extern undefined4 DAT_8038e46c;
extern undefined4 DAT_8038e470;
extern undefined4 DAT_8038e474;
extern undefined4 DAT_8038e478;
extern undefined4 DAT_8038e47c;
extern undefined4 DAT_8038e480;
extern undefined4 DAT_8038e484;
extern undefined4 DAT_8038e488;
extern undefined4 DAT_8038e48c;
extern undefined4 DAT_8038e490;
extern undefined4 DAT_8038e494;
extern undefined4 DAT_8038e498;
extern undefined4 DAT_8038e4a0;
extern undefined4 DAT_8038e4a2;
extern undefined4 DAT_8038e4a4;
extern undefined4 DAT_8038e4a6;
extern undefined4 DAT_8038e4a8;
extern undefined4 DAT_8038e4aa;
extern undefined4 DAT_8038e4ac;
extern undefined4 DAT_8038e4ae;
extern undefined4 DAT_8038e4b0;
extern undefined4 DAT_8038e4b2;
extern undefined4 DAT_8038e4b4;
extern undefined4 DAT_8038e4b6;
extern undefined4 DAT_8038e4b8;
extern undefined4 DAT_8038e4ba;
extern undefined4 DAT_8038e4bc;
extern undefined4 DAT_8038e4be;
extern undefined4 DAT_8038e4c0;
extern undefined4 DAT_8038e4c2;
extern undefined4 DAT_8038e4c4;
extern undefined4 DAT_8038e4c6;
extern undefined4 DAT_8038e4c8;
extern undefined4 DAT_8038e4ca;
extern undefined4 DAT_8038e4cc;
extern undefined4 DAT_8038e4ce;
extern undefined4 DAT_8038e4d0;
extern undefined4 DAT_8038e4d2;
extern undefined4 DAT_8038e4d4;
extern undefined4 DAT_8038e4d6;
extern undefined4 DAT_8038e4d8;
extern undefined4 DAT_8038e4da;
extern undefined4 DAT_8038e4dc;
extern undefined4 DAT_8038e4de;
extern undefined4 DAT_8038e4e0;
extern undefined4 DAT_8038e4e2;
extern undefined4 DAT_8038e4e4;
extern undefined4 DAT_8038e4e6;
extern undefined4 DAT_8038e4e8;
extern undefined4 DAT_8038e4ea;
extern undefined4 DAT_8038e4ec;
extern undefined4 DAT_8038e4ee;
extern undefined4 DAT_8038e4f0;
extern undefined DAT_8038e57c;
extern int DAT_8038e8c4;
extern undefined4 DAT_8038e8c8;
extern int DAT_8038e8dc;
extern int DAT_8038eaa4;
extern undefined4 DAT_8038eaac;
extern undefined4 DAT_80397450;
extern undefined4 DAT_803dc294;
extern undefined4 DAT_803dc2b8;
extern undefined4 DAT_803dc2ba;
extern undefined4 DAT_803dc2bc;
extern undefined4 DAT_803dda48;
extern undefined4 DAT_803dda4c;
extern undefined4 DAT_803dda64;
extern undefined4 DAT_803dda68;
extern undefined4 DAT_803dda86;
extern undefined4 DAT_803dda88;
extern undefined4 DAT_803dda8c;
extern undefined4 DAT_803dda90;
extern undefined4 DAT_803dda94;
extern undefined4 DAT_803ddb00;
extern undefined4 DAT_803ddb18;
extern undefined4 DAT_803ddb1c;
extern undefined4 DAT_803ddb30;
extern undefined4 DAT_803ddb60;
extern undefined4 DAT_803ddb64;
extern undefined4 DAT_803ddb68;
extern undefined4 DAT_803ddb69;
extern undefined4 DAT_803ddb6a;
extern undefined4 DAT_803ddb6b;
extern undefined4 DAT_803ddb6c;
extern undefined4 DAT_803ddb6d;
extern undefined4 DAT_803ddb6e;
extern undefined4 DAT_803ddb70;
extern undefined4 DAT_803ddb72;
extern undefined4 DAT_803ddb74;
extern undefined4 DAT_803ddb76;
extern undefined4 DAT_803ddb78;
extern undefined4 DAT_803ddb7a;
extern undefined4 DAT_803ddb7c;
extern undefined4 DAT_803ddb84;
extern undefined4 DAT_803ddb88;
extern undefined4 DAT_803ddb8c;
extern undefined4 DAT_803ddb90;
extern undefined4 DAT_803ddb94;
extern undefined4 DAT_803ddb98;
extern undefined4 DAT_803ddb9c;
extern undefined4 DAT_803ddba0;
extern undefined4 DAT_803ddba4;
extern undefined4 DAT_803ddbac;
extern undefined4 DAT_803ddbb0;
extern undefined4 DAT_803ddbb4;
extern float* DAT_803ddbb8;
extern undefined4 DAT_803ddbbc;
extern undefined4 DAT_803ddbc0;
extern undefined4 DAT_803ddbc4;
extern int* DAT_803ddbc8;
extern undefined4 DAT_803ddbcc;
extern undefined4 DAT_803ddbcd;
extern undefined4 DAT_803ddbce;
extern undefined4 DAT_803ddbcf;
extern undefined4 DAT_803ddbdc;
extern undefined4 DAT_803ddbde;
extern undefined4 DAT_803ddbe0;
extern undefined4* DAT_803ddbe4;
extern undefined* DAT_803ddbe8;
extern undefined4 DAT_803ddbec;
extern undefined4 DAT_803ddbee;
extern undefined4 DAT_803ddbf0;
extern undefined4 DAT_803ddc00;
extern undefined4 DAT_803ddc38;
extern undefined4 DAT_803e90c0;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803df840;
extern f64 DOUBLE_803df8c8;
extern f64 DOUBLE_803df8e0;
extern f64 DOUBLE_803df908;
extern f64 DOUBLE_803df958;
extern f64 DOUBLE_803df980;
extern f32 FLOAT_803dc2b0;
extern f32 FLOAT_803dc2b4;
extern f32 FLOAT_803dc2c0;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803dda98;
extern f32 FLOAT_803ddb58;
extern f32 FLOAT_803ddb5c;
extern f32 FLOAT_803ddb80;
extern f32 FLOAT_803ddbd0;
extern f32 FLOAT_803ddbd4;
extern f32 FLOAT_803ddbd8;
extern f32 FLOAT_803df84c;
extern f32 FLOAT_803df854;
extern f32 FLOAT_803df858;
extern f32 FLOAT_803df85c;
extern f32 FLOAT_803df864;
extern f32 FLOAT_803df87c;
extern f32 FLOAT_803df8a0;
extern f32 FLOAT_803df8b0;
extern f32 FLOAT_803df8b4;
extern f32 FLOAT_803df8b8;
extern f32 FLOAT_803df8bc;
extern f32 FLOAT_803df8c0;
extern f32 FLOAT_803df8d0;
extern f32 FLOAT_803df8d8;
extern f32 FLOAT_803df8e8;
extern f32 FLOAT_803df8ec;
extern f32 FLOAT_803df8f0;
extern f32 FLOAT_803df8f4;
extern f32 FLOAT_803df8f8;
extern f32 FLOAT_803df8fc;
extern f32 FLOAT_803df900;
extern f32 FLOAT_803df910;
extern f32 FLOAT_803df914;
extern f32 FLOAT_803df918;
extern f32 FLOAT_803df91c;
extern f32 FLOAT_803df920;
extern f32 FLOAT_803df924;
extern f32 FLOAT_803df928;
extern f32 FLOAT_803df92c;
extern f32 FLOAT_803df930;
extern f32 FLOAT_803df934;
extern f32 FLOAT_803df938;
extern f32 FLOAT_803df93c;
extern f32 FLOAT_803df940;
extern f32 FLOAT_803df944;
extern f32 FLOAT_803df948;
extern f32 FLOAT_803df94c;
extern f32 FLOAT_803df950;
extern f32 FLOAT_803df954;
extern f32 FLOAT_803df960;
extern f32 FLOAT_803df964;
extern f32 FLOAT_803df968;
extern f32 FLOAT_803df96c;
extern f32 FLOAT_803df970;
extern f32 FLOAT_803df974;
extern f32 FLOAT_803df978;
extern f32 FLOAT_803df988;
extern char s_NO_FREE_LAST_LINE_8030f428[];
extern char s_trackIntersect__FUNC_OVERFLOW__d_8030f43c[];

/*
 * --INFO--
 *
 * Function: FUN_8005fa9c
 * EN v1.0 Address: 0x8005FA9C
 * EN v1.0 Size: 472b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005fa9c(char param_1,undefined4 param_2,int param_3,int *param_4)
{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  uint3 uVar4;
  int iVar5;
  uint uVar6;
  
  if (param_1 != '\0') {
    FUN_80257b5c();
  }
  uVar6 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar6 >> 3));
  iVar5 = *param_4 + ((int)uVar6 >> 3);
  uVar1 = *(undefined *)(iVar5 + 1);
  uVar2 = *(undefined *)(iVar5 + 2);
  param_4[4] = uVar6 + 1;
  if (param_1 != '\0') {
    if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar6 & 7) & 1) == 0) {
      uVar6 = 2;
    }
    else {
      uVar6 = 3;
    }
    FUN_802570dc(9,uVar6);
  }
  uVar6 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar6 >> 3));
  iVar5 = *param_4 + ((int)uVar6 >> 3);
  uVar1 = *(undefined *)(iVar5 + 1);
  uVar2 = *(undefined *)(iVar5 + 2);
  param_4[4] = uVar6 + 1;
  if (param_1 != '\0') {
    if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar6 & 7) & 1) == 0) {
      uVar6 = 2;
    }
    else {
      uVar6 = 3;
    }
    FUN_802570dc(0xb,uVar6);
  }
  uVar6 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar6 >> 3));
  iVar5 = *param_4 + ((int)uVar6 >> 3);
  uVar1 = *(undefined *)(iVar5 + 1);
  uVar2 = *(undefined *)(iVar5 + 2);
  param_4[4] = uVar6 + 1;
  uVar4 = CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar6 & 7);
  if (param_1 != '\0') {
    if ((param_3 == 0) || ((*(uint *)(param_3 + 0x3c) & 0x80000000) != 0)) {
      if ((uVar4 & 1) == 0) {
        uVar6 = 2;
      }
      else {
        uVar6 = 3;
      }
      FUN_802570dc(0xd,uVar6);
    }
    else {
      for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x41); iVar5 = iVar5 + 1) {
        if ((uVar4 & 1) == 0) {
          uVar6 = 2;
        }
        else {
          uVar6 = 3;
        }
        FUN_802570dc(iVar5 + 0xd,uVar6);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005fc74
 * EN v1.0 Address: 0x8005FC74
 * EN v1.0 Size: 204b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005fc74(int param_1,float *param_2)
{
  float afStack_68 [3];
  float local_5c;
  float local_4c;
  float local_3c;
  float afStack_38 [12];
  
  FUN_8025d80c(param_2,0);
  FUN_802475e4(param_2,afStack_68);
  local_5c = FLOAT_803df84c;
  local_4c = FLOAT_803df84c;
  local_3c = FLOAT_803df84c;
  FUN_8025d848(afStack_68,0);
  FUN_80247618((float *)&DAT_80397450,param_2,afStack_38);
  FUN_8025d8c4(afStack_38,0x24,0);
  FUN_802585d8(9,*(uint *)(param_1 + 0x58),6);
  FUN_802585d8(0xb,*(uint *)(param_1 + 0x5c),2);
  FUN_802585d8(0xd,*(uint *)(param_1 + 0x60),4);
  FUN_802585d8(0xe,*(uint *)(param_1 + 0x60),4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005fd40
 * EN v1.0 Address: 0x8005FD40
 * EN v1.0 Size: 612b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005fd40(void)
{
  bool bVar1;
  uint uVar2;
  uint3 uVar3;
  uint3 uVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  undefined *puVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  undefined4 uVar13;
  undefined8 uVar14;
  int local_78 [4];
  uint local_68;
  float afStack_64 [25];
  
  uVar14 = FUN_80286840();
  iVar6 = (int)((ulonglong)uVar14 >> 0x20);
  iVar12 = 0;
  iVar11 = 0;
  uVar10 = (uint)uVar14 & 0xff;
  if (uVar10 == 1) {
    uVar13 = *(undefined4 *)(iVar6 + 0x7c);
    uVar10 = (uint)*(ushort *)(iVar6 + 0x86);
  }
  else if (uVar10 == 2) {
    uVar13 = *(undefined4 *)(iVar6 + 0x80);
    uVar10 = (uint)*(ushort *)(iVar6 + 0x88);
  }
  else {
    uVar13 = *(undefined4 *)(iVar6 + 0x78);
    uVar10 = (uint)*(ushort *)(iVar6 + 0x84);
    iVar11 = 1;
  }
  if (uVar10 != 0) {
    pfVar7 = (float *)FUN_8000f56c();
    FUN_80247618(pfVar7,(float *)(iVar6 + 0xc),afStack_64);
    if (iVar11 != 0) {
      FUN_8005fc74(iVar6,afStack_64);
    }
    FUN_80013a84(local_78,uVar13,uVar10 << 3,uVar10 << 3);
    bVar1 = false;
    uVar10 = local_68;
    while (local_68 = uVar10, !bVar1) {
      puVar8 = (undefined *)(local_78[0] + ((int)local_68 >> 3));
      uVar10 = local_68 + 4;
      uVar3 = CONCAT12(puVar8[2],CONCAT11(puVar8[1],*puVar8)) >> (local_68 & 7);
      uVar4 = uVar3 & 0xf;
      if (uVar4 == 3) {
        local_68 = uVar10;
        FUN_8005fa9c((char)iVar11,iVar6,iVar12,local_78);
        uVar10 = local_68;
      }
      else if (uVar4 < 3) {
        if (uVar4 == 1) {
          local_68 = uVar10;
          iVar12 = FUN_8005f6d4((char)iVar11,iVar6,local_78);
          uVar10 = local_68;
        }
        else if ((uVar3 & 0xf) != 0) {
          local_68 = uVar10;
          FUN_8005edfc(iVar11,0,iVar6,iVar12,local_78,afStack_64);
          uVar10 = local_68;
        }
      }
      else if (uVar4 == 5) {
        bVar1 = true;
      }
      else if (uVar4 < 5) {
        puVar8 = (undefined *)(local_78[0] + ((int)uVar10 >> 3));
        local_68 = local_68 + 8;
        uVar4 = CONCAT12(puVar8[2],CONCAT11(puVar8[1],*puVar8)) >> (uVar10 & 7);
        uVar2 = uVar4 & 0xf;
        iVar9 = 0;
        uVar10 = local_68;
        if ((uVar4 & 0xf) != 0) {
          if ((8 < uVar2) && (uVar10 = uVar2 - 1 >> 3, 0 < (int)(uVar2 - 8))) {
            do {
              local_68 = local_68 + 0x40;
              iVar9 = iVar9 + 8;
              uVar10 = uVar10 - 1;
            } while (uVar10 != 0);
          }
          iVar5 = uVar2 - iVar9;
          uVar10 = local_68;
          if (iVar9 < (int)uVar2) {
            do {
              local_68 = local_68 + 8;
              iVar5 = iVar5 + -1;
              uVar10 = local_68;
            } while (iVar5 != 0);
          }
        }
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005ffa4
 * EN v1.0 Address: 0x8005FFA4
 * EN v1.0 Size: 1640b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005ffa4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8006060c
 * EN v1.0 Address: 0x8006060C
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006060c(undefined4 *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)
{
  *param_1 = DAT_803dda88;
  *param_2 = DAT_803dda8c;
  *param_3 = DAT_803dda90;
  *param_4 = DAT_803dda94;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80060630
 * EN v1.0 Address: 0x80060630
 * EN v1.0 Size: 216b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80060630(int param_1)
{
  bool bVar1;
  uint uVar2;
  byte bVar3;
  
  if (99 < DAT_803dda86) {
    return;
  }
  bVar3 = 0;
  do {
    if (4 < bVar3) {
      bVar1 = true;
LAB_800606c0:
      if ((!bVar1) && (*(char *)(param_1 + 0x2f9) == '\0')) {
        return;
      }
      if (!bVar1) {
        *(undefined *)(param_1 + 0x2fa) = 0xf0;
      }
      uVar2 = (uint)DAT_803dda86;
      DAT_803dda86 = DAT_803dda86 + 1;
      (&DAT_80382c98)[uVar2] = param_1;
      return;
    }
    uVar2 = (uint)bVar3;
    if (FLOAT_803df84c +
        (float)(&DAT_803885a8)[uVar2 * 5] +
        (float)(&DAT_803885a4)[uVar2 * 5] * (*(float *)(param_1 + 0x18) - FLOAT_803dda5c) +
        *(float *)(param_1 + 0x14) * (float)(&DAT_803885a0)[uVar2 * 5] +
        (float)(&DAT_8038859c)[uVar2 * 5] * (*(float *)(param_1 + 0x10) - FLOAT_803dda58) <
        FLOAT_803df84c) {
      bVar1 = false;
      goto LAB_800606c0;
    }
    bVar3 = bVar3 + 1;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_80060708
 * EN v1.0 Address: 0x80060708
 * EN v1.0 Size: 100b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80060708(undefined2 *param_1,float *param_2)
{
  float fVar1;
  float fVar2;
  
  fVar1 = FLOAT_803df8d0 * param_2[1];
  fVar2 = FLOAT_803df8d0 * param_2[2];
  *param_1 = (short)(int)(FLOAT_803df8d0 * *param_2);
  param_1[1] = (short)(int)fVar1;
  param_1[2] = (short)(int)fVar2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006076c
 * EN v1.0 Address: 0x8006076C
 * EN v1.0 Size: 120b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006076c(short *param_1,float *param_2)
{
  double dVar1;
  float fVar2;
  
  fVar2 = FLOAT_803df8a0;
  dVar1 = DOUBLE_803df840;
  *param_2 = (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) - DOUBLE_803df840) *
             FLOAT_803df8a0;
  param_2[1] = (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) - dVar1) * fVar2;
  param_2[2] = (float)((double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000) - dVar1) * fVar2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800607e4
 * EN v1.0 Address: 0x800607E4
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800607e4(int param_1)
{
  return (*(uint *)(param_1 + 0x10) & 0xff0000) >> 0x10;
}

/*
 * --INFO--
 *
 * Function: FUN_800607f4
 * EN v1.0 Address: 0x800607F4
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800607f4(int param_1)
{
  return *(uint *)(param_1 + 0x10) >> 0x18;
}

/*
 * --INFO--
 *
 * Function: FUN_80060804
 * EN v1.0 Address: 0x80060804
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80060804(int param_1,uint param_2)
{
  uint uVar1;
  ushort *puVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = 0;
  iVar3 = 0;
  for (uVar1 = (uint)*(ushort *)(param_1 + 0x9a); uVar1 != 0; uVar1 = uVar1 - 1) {
    puVar2 = (ushort *)(*(int *)(param_1 + 0x50) + iVar3);
    if (param_2 == *(uint *)(puVar2 + 8) >> 0x18) {
      iVar4 = iVar4 + ((uint)puVar2[10] - (uint)*puVar2);
    }
    iVar3 = iVar3 + 0x14;
  }
  return iVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_80060858
 * EN v1.0 Address: 0x80060858
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80060858(int param_1,int param_2)
{
  return *(int *)(param_1 + 0x4c) + param_2 * 8;
}

/*
 * --INFO--
 *
 * Function: FUN_80060868
 * EN v1.0 Address: 0x80060868
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80060868(int param_1,int param_2)
{
  return *(int *)(param_1 + 0x50) + param_2 * 0x14;
}

/*
 * --INFO--
 *
 * Function: FUN_80060878
 * EN v1.0 Address: 0x80060878
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80060878(int param_1,int param_2)
{
  return *(int *)(param_1 + 0x68) + param_2 * 0x1c;
}

/*
 * --INFO--
 *
 * Function: FUN_80060888
 * EN v1.0 Address: 0x80060888
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80060888(int param_1,int param_2)
{
  return *(int *)(param_1 + 100) + param_2 * 0x44;
}

/*
 * --INFO--
 *
 * Function: FUN_80060898
 * EN v1.0 Address: 0x80060898
 * EN v1.0 Size: 232b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80060898(void)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar1 = FUN_80286834();
  iVar3 = 0;
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(iVar1 + 0xa2); iVar6 = iVar6 + 1) {
    iVar5 = *(int *)(iVar1 + 100) + iVar3;
    iVar4 = iVar5;
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(iVar5 + 0x41); iVar2 = iVar2 + 1) {
      if (*(int *)(iVar4 + 0x24) == -1) {
        *(undefined4 *)(iVar4 + 0x24) = 0;
      }
      else {
        *(undefined4 *)(iVar4 + 0x24) =
             *(undefined4 *)(*(int *)(iVar1 + 0x54) + *(int *)(iVar4 + 0x24) * 4);
        if (*(byte *)(iVar4 + 0x29) != 0) {
          FUN_80056924(*(int *)(iVar4 + 0x24),0,(uint)*(byte *)(iVar4 + 0x29));
        }
      }
      *(undefined *)(iVar4 + 0x2a) = 0xff;
      iVar4 = iVar4 + 8;
    }
    if (*(int *)(iVar5 + 0x34) == -1) {
      *(undefined4 *)(iVar5 + 0x34) = 0;
    }
    else {
      *(undefined4 *)(iVar5 + 0x34) =
           *(undefined4 *)(*(int *)(iVar1 + 0x54) + *(int *)(iVar5 + 0x34) * 4);
    }
    iVar3 = iVar3 + 0x44;
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80060980
 * EN v1.0 Address: 0x80060980
 * EN v1.0 Size: 240b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80060980(int param_1)
{
  int iVar1;
  int iVar2;
  
  if (*(int *)(param_1 + 0x54) != 0) {
    *(int *)(param_1 + 0x54) = param_1 + *(int *)(param_1 + 0x54);
  }
  if (*(int *)(param_1 + 0x4c) != 0) {
    *(int *)(param_1 + 0x4c) = param_1 + *(int *)(param_1 + 0x4c);
  }
  if (*(int *)(param_1 + 0x50) != 0) {
    *(int *)(param_1 + 0x50) = param_1 + *(int *)(param_1 + 0x50);
  }
  *(int *)(param_1 + 0x58) = param_1 + *(int *)(param_1 + 0x58);
  *(int *)(param_1 + 0x5c) = param_1 + *(int *)(param_1 + 0x5c);
  *(int *)(param_1 + 0x60) = param_1 + *(int *)(param_1 + 0x60);
  if (*(int *)(param_1 + 0x78) != 0) {
    *(int *)(param_1 + 0x78) = param_1 + *(int *)(param_1 + 0x78);
  }
  if (*(int *)(param_1 + 0x7c) != 0) {
    *(int *)(param_1 + 0x7c) = param_1 + *(int *)(param_1 + 0x7c);
  }
  if (*(int *)(param_1 + 0x80) != 0) {
    *(int *)(param_1 + 0x80) = param_1 + *(int *)(param_1 + 0x80);
  }
  *(int *)(param_1 + 0x68) = param_1 + *(int *)(param_1 + 0x68);
  if (*(int *)(param_1 + 100) != 0) {
    *(int *)(param_1 + 100) = param_1 + *(int *)(param_1 + 100);
  }
  iVar1 = 0;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_1 + 0xa1); iVar2 = iVar2 + 1) {
    *(int *)(*(int *)(param_1 + 0x68) + iVar1) =
         param_1 + *(int *)(*(int *)(param_1 + 0x68) + iVar1);
    iVar1 = iVar1 + 0x1c;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80060a70
 * EN v1.0 Address: 0x80060A70
 * EN v1.0 Size: 324b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80060a70(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  
  uVar6 = *(uint *)(DAT_803ddb00 + param_10 * 4);
  uVar5 = *(int *)(DAT_803ddb00 + param_10 * 4 + 4) - uVar6;
  if (0 < (int)uVar5) {
    iVar1 = FUN_80023d8c(uVar5,5);
    *(int *)(param_9 + 0x70) = iVar1;
    FUN_800490c4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x28,
                 *(undefined4 *)(param_9 + 0x70),uVar6,uVar5,param_13,param_14,param_15,param_16);
  }
  *(short *)(param_9 + 0x9c) = (short)(uVar5 / 0x14);
  iVar1 = 0;
  for (iVar4 = 0; iVar4 < (int)(uint)*(ushort *)(param_9 + 0x9c); iVar4 = iVar4 + 1) {
    psVar2 = (short *)(*(int *)(param_9 + 0x70) + iVar1);
    if ((((*psVar2 < 0) || (psVar2[1] < 0)) || (0x280 < *psVar2)) || (0x280 < psVar2[1])) {
      *(undefined *)((int)psVar2 + 0xf) = 0x40;
    }
    iVar3 = *(int *)(param_9 + 0x70) + iVar1;
    if (((*(short *)(iVar3 + 8) < 0) || (*(short *)(iVar3 + 10) < 0)) ||
       ((0x280 < *(short *)(iVar3 + 8) || (0x280 < *(short *)(iVar3 + 10))))) {
      *(undefined *)(iVar3 + 0xf) = 0x40;
    }
    iVar1 = iVar1 + 0x14;
  }
  *(undefined4 *)(param_9 + 0x74) = 0;
  *(undefined2 *)(param_9 + 0x9e) = 0;
  *(ushort *)(param_9 + 4) = *(ushort *)(param_9 + 4) & 0xffbf;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80060bb4
 * EN v1.0 Address: 0x80060BB4
 * EN v1.0 Size: 264b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80060bb4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9)
{
  uint uVar1;
  int iVar2;
  undefined4 in_r10;
  uint uVar3;
  int local_18;
  uint local_14 [3];
  
  if (DAT_803ddb30 < param_9) {
    iVar2 = 0;
  }
  else {
    uVar3 = 0;
    if (DAT_803dda64 != 0) {
      uVar1 = *(uint *)(DAT_803dda64 + param_9 * 4);
      if (uVar1 != 0xffffffff) {
        if ((uVar1 == 0) && (*(int *)(DAT_803dda64 + param_9 * 4 + 4) == 0)) {
          return 0;
        }
        param_1 = FUN_80048d78(uVar1,local_14,&local_18);
        uVar3 = uVar1;
      }
    }
    if ((int)local_14[0] < 1) {
      iVar2 = 0;
    }
    else if (local_18 < 0x32001) {
      iVar2 = FUN_80023d8c(local_18,5);
      if (iVar2 == 0) {
        iVar2 = 0;
      }
      else {
        FUN_80046644(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x25,iVar2,
                     uVar3,local_14[0],(uint *)0x0,0,0,in_r10);
      }
    }
    else {
      iVar2 = 0;
    }
  }
  return iVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80060cbc
 * EN v1.0 Address: 0x80060CBC
 * EN v1.0 Size: 80b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80060cbc(void)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  
  iVar3 = 0;
  uVar2 = (uint)DAT_803ddb18;
  if (uVar2 == 0) {
    return;
  }
  if ((8 < uVar2) && (uVar4 = uVar2 - 1 >> 3, 0 < (int)(uVar2 - 8))) {
    do {
      iVar3 = iVar3 + 8;
      uVar4 = uVar4 - 1;
    } while (uVar4 != 0);
  }
  iVar1 = uVar2 - iVar3;
  if ((int)uVar2 <= iVar3) {
    return;
  }
  do {
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80060d0c
 * EN v1.0 Address: 0x80060D0C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80060d0c(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80060d14
 * EN v1.0 Address: 0x80060D14
 * EN v1.0 Size: 24b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80060d14(undefined4 *param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80060d2c
 * EN v1.0 Address: 0x80060D2C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80060d2c(void)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar2 = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)DAT_803ddb18; iVar3 = iVar3 + 1) {
    iVar5 = *(int *)(DAT_803ddb1c + iVar2);
    if (iVar5 != 0) {
      iVar1 = 0;
      for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar5 + 0xa1); iVar4 = iVar4 + 1) {
        *(undefined *)(*(int *)(iVar5 + 0x68) + iVar1 + 0x12) = 0;
        iVar1 = iVar1 + 0x1c;
      }
    }
    iVar2 = iVar2 + 4;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80060d90
 * EN v1.0 Address: 0x80060D90
 * EN v1.0 Size: 1152b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80060d90(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5,float *param_6,undefined4 param_7,undefined4 param_8,int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80061210
 * EN v1.0 Address: 0x80061210
 * EN v1.0 Size: 320b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80061210(double param_1,float *param_2,float *param_3)
{
  int iVar1;
  float *pfVar2;
  double dVar3;
  double dVar4;
  ushort local_48;
  short local_46;
  undefined2 local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  
  local_3c = FLOAT_803df8d8;
  local_38 = FLOAT_803df8d8;
  local_34 = FLOAT_803df8d8;
  local_40 = FLOAT_803df8e8;
  local_44 = 0;
  if (ABS(*param_2) <= ABS(param_2[2])) {
    iVar1 = FUN_80021884();
    local_46 = (short)iVar1;
  }
  else {
    iVar1 = FUN_80021884();
    local_46 = (short)iVar1;
  }
  if (0x2000 < local_46) {
    local_46 = 0x2000;
  }
  iVar1 = FUN_80021884();
  local_48 = (ushort)iVar1;
  iVar1 = 0;
  pfVar2 = (float *)&DAT_8038e43c;
  dVar4 = (double)FLOAT_803df8d8;
  do {
    *param_3 = *pfVar2;
    dVar3 = (double)pfVar2[1];
    if (dVar3 <= dVar4) {
      param_3[1] = (float)(param_1 * dVar3);
    }
    else {
      param_3[1] = pfVar2[1];
    }
    param_3[2] = pfVar2[2];
    FUN_80021b8c(&local_48,param_3);
    pfVar2 = pfVar2 + 3;
    param_3 = param_3 + 3;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80061350
 * EN v1.0 Address: 0x80061350
 * EN v1.0 Size: 392b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80061350(double param_1,float *param_2,float *param_3,uint *param_4)
{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  int iVar5;
  undefined8 local_8;
  
  *param_4 = 0x7fffffff;
  param_4[3] = 0x80000000;
  param_4[1] = 0x7fffffff;
  param_4[4] = 0x80000000;
  param_4[2] = 0x7fffffff;
  param_4[5] = 0x80000000;
  dVar4 = DOUBLE_803df8e0;
  iVar5 = 8;
  do {
    dVar1 = param_1 * (double)*param_2 + (double)*param_3;
    dVar2 = param_1 * (double)param_2[1] + (double)param_3[1];
    dVar3 = param_1 * (double)param_2[2] + (double)param_3[2];
    local_8 = (double)CONCAT44(0x43300000,*param_4 ^ 0x80000000);
    if ((float)dVar1 < (float)(local_8 - dVar4)) {
      *param_4 = (int)dVar1;
    }
    local_8 = (double)CONCAT44(0x43300000,param_4[3] ^ 0x80000000);
    if ((float)(local_8 - dVar4) < (float)dVar1) {
      param_4[3] = (int)dVar1;
    }
    local_8 = (double)CONCAT44(0x43300000,param_4[1] ^ 0x80000000);
    if ((float)dVar2 < (float)(local_8 - dVar4)) {
      param_4[1] = (int)dVar2;
    }
    local_8 = (double)CONCAT44(0x43300000,param_4[4] ^ 0x80000000);
    if ((float)(local_8 - dVar4) < (float)dVar2) {
      param_4[4] = (int)dVar2;
    }
    local_8 = (double)CONCAT44(0x43300000,param_4[2] ^ 0x80000000);
    if ((float)dVar3 < (float)(local_8 - dVar4)) {
      param_4[2] = (int)dVar3;
    }
    local_8 = (double)CONCAT44(0x43300000,param_4[5] ^ 0x80000000);
    if ((float)(local_8 - dVar4) < (float)dVar3) {
      param_4[5] = (int)dVar3;
    }
    param_2 = param_2 + 3;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800614d8
 * EN v1.0 Address: 0x800614D8
 * EN v1.0 Size: 760b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800614d8(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800617d0
 * EN v1.0 Address: 0x800617D0
 * EN v1.0 Size: 768b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800617d0(ushort *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80061ad0
 * EN v1.0 Address: 0x80061AD0
 * EN v1.0 Size: 1156b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80061ad0(undefined4 param_1,float *param_2,float *param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float local_18;
  float local_14;
  float local_10;
  
  fVar1 = param_2[6] - param_2[9];
  fVar3 = param_2[7] - param_2[10];
  fVar5 = param_2[8] - param_2[0xb];
  fVar2 = param_2[0x15] - param_2[9];
  fVar4 = param_2[0x16] - param_2[10];
  fVar6 = param_2[0x17] - param_2[0xb];
  local_18 = fVar4 * fVar5 - fVar6 * fVar3;
  local_14 = -(fVar2 * fVar5 - fVar6 * fVar1);
  local_10 = fVar2 * fVar3 - fVar4 * fVar1;
  FUN_80247ef8(&local_18,&local_18);
  *param_3 = -local_18;
  param_3[1] = -local_14;
  param_3[2] = -local_10;
  param_3[3] = -(param_3[2] * param_2[0xb] + *param_3 * param_2[9] + param_3[1] * param_2[10]);
  fVar1 = param_2[0x12] - param_2[0xf];
  fVar3 = param_2[0x13] - param_2[0x10];
  fVar5 = param_2[0x14] - param_2[0x11];
  fVar2 = param_2[3] - param_2[0xf];
  fVar4 = param_2[4] - param_2[0x10];
  fVar6 = param_2[5] - param_2[0x11];
  local_18 = fVar4 * fVar5 - fVar6 * fVar3;
  local_14 = -(fVar2 * fVar5 - fVar6 * fVar1);
  local_10 = fVar2 * fVar3 - fVar4 * fVar1;
  FUN_80247ef8(&local_18,&local_18);
  param_3[5] = -local_18;
  param_3[6] = -local_14;
  param_3[7] = -local_10;
  param_3[8] = -(param_3[7] * param_2[0x11] + param_3[5] * param_2[0xf] + param_3[6] * param_2[0x10]
                );
  fVar1 = param_2[0xf] - param_2[0xc];
  fVar3 = param_2[0x10] - param_2[0xd];
  fVar5 = param_2[0x11] - param_2[0xe];
  fVar2 = *param_2 - param_2[0xc];
  fVar4 = param_2[1] - param_2[0xd];
  fVar6 = param_2[2] - param_2[0xe];
  local_18 = fVar4 * fVar5 - fVar6 * fVar3;
  local_14 = -(fVar2 * fVar5 - fVar6 * fVar1);
  local_10 = fVar2 * fVar3 - fVar4 * fVar1;
  FUN_80247ef8(&local_18,&local_18);
  param_3[10] = -local_18;
  param_3[0xb] = -local_14;
  param_3[0xc] = -local_10;
  param_3[0xd] = -(param_3[0xc] * param_2[0xe] +
                  param_3[10] * param_2[0xc] + param_3[0xb] * param_2[0xd]);
  fVar1 = param_2[9] - *param_2;
  fVar3 = param_2[10] - param_2[1];
  fVar5 = param_2[0xb] - param_2[2];
  fVar2 = param_2[0xc] - *param_2;
  fVar4 = param_2[0xd] - param_2[1];
  fVar6 = param_2[0xe] - param_2[2];
  local_18 = fVar4 * fVar5 - fVar6 * fVar3;
  local_14 = -(fVar2 * fVar5 - fVar6 * fVar1);
  local_10 = fVar2 * fVar3 - fVar4 * fVar1;
  FUN_80247ef8(&local_18,&local_18);
  param_3[0xf] = -local_18;
  param_3[0x10] = -local_14;
  param_3[0x11] = -local_10;
  param_3[0x12] =
       -(param_3[0x11] * param_2[2] + param_3[0xf] * *param_2 + param_3[0x10] * param_2[1]);
  fVar1 = param_2[0x12] - param_2[0x15];
  fVar3 = param_2[0x13] - param_2[0x16];
  fVar5 = param_2[0x14] - param_2[0x17];
  fVar2 = param_2[0xc] - param_2[0x15];
  fVar4 = param_2[0xd] - param_2[0x16];
  fVar6 = param_2[0xe] - param_2[0x17];
  local_18 = fVar4 * fVar5 - fVar6 * fVar3;
  local_14 = -(fVar2 * fVar5 - fVar6 * fVar1);
  local_10 = fVar2 * fVar3 - fVar4 * fVar1;
  FUN_80247ef8(&local_18,&local_18);
  param_3[0x14] = -local_18;
  param_3[0x15] = -local_14;
  param_3[0x16] = -local_10;
  param_3[0x17] =
       -(param_3[0x16] * param_2[0x17] +
        param_3[0x14] * param_2[0x15] + param_3[0x15] * param_2[0x16]);
  fVar1 = param_2[3] - *param_2;
  fVar3 = param_2[4] - param_2[1];
  fVar5 = param_2[5] - param_2[2];
  fVar2 = param_2[9] - *param_2;
  fVar4 = param_2[10] - param_2[1];
  fVar6 = param_2[0xb] - param_2[2];
  local_18 = fVar4 * fVar5 - fVar6 * fVar3;
  local_14 = -(fVar2 * fVar5 - fVar6 * fVar1);
  local_10 = fVar2 * fVar3 - fVar4 * fVar1;
  FUN_80247ef8(&local_18,&local_18);
  param_3[0x19] = -local_18;
  param_3[0x1a] = -local_14;
  param_3[0x1b] = -local_10;
  param_3[0x1c] =
       -(param_3[0x1b] * param_2[2] + param_3[0x19] * *param_2 + param_3[0x1a] * param_2[1]);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80061f54
 * EN v1.0 Address: 0x80061F54
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80061f54(int param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5,
                 undefined4 *param_6,float *param_7,int param_8)
{
  float fVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  fVar1 = FLOAT_803df8d8;
  iVar4 = 0;
  iVar5 = 0;
  iVar6 = *(int *)(param_1 + 100);
  DAT_803ddb72 = 0;
  if (0 < param_4) {
    do {
      iVar2 = 1;
      if (*(float *)(iVar6 + 0x1c) * param_7[2] +
          *(float *)(iVar6 + 0x14) * *param_7 + *(float *)(iVar6 + 0x18) * param_7[1] < fVar1) {
        iVar2 = -1;
      }
      if (iVar2 == 1) {
        DAT_803ddb72 = DAT_803ddb72 + 1;
        puVar3 = (undefined4 *)(param_5 + iVar4 * 0xc);
        *param_6 = *puVar3;
        param_6[1] = puVar3[1];
        param_6[2] = puVar3[2];
        if (param_8 <= iVar5 + 1) {
          return 0;
        }
        puVar3 = (undefined4 *)(param_5 + (iVar4 + 1) * 0xc);
        param_6[3] = *puVar3;
        param_6[4] = puVar3[1];
        param_6[5] = puVar3[2];
        if (param_8 <= iVar5 + 2) {
          return 0;
        }
        puVar3 = (undefined4 *)(param_5 + (iVar4 + 2) * 0xc);
        param_6[6] = *puVar3;
        param_6[7] = puVar3[1];
        param_6[8] = puVar3[2];
        param_6 = param_6 + 9;
        iVar5 = iVar5 + 3;
        if (param_8 <= iVar5) {
          return 0;
        }
      }
      iVar4 = iVar4 + 3;
      param_7 = param_7 + 5;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  return (uint)(-(int)DAT_803ddb72 & ~(int)DAT_803ddb72) >> 0x1f;
}

/*
 * --INFO--
 *
 * Function: FUN_80062088
 * EN v1.0 Address: 0x80062088
 * EN v1.0 Size: 1132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80062088(undefined4 param_1,undefined4 param_2,ushort *param_3,int param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800624f4
 * EN v1.0 Address: 0x800624F4
 * EN v1.0 Size: 288b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800624f4(int param_1,uint param_2)
{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  double dVar5;
  undefined8 local_28;
  
  if ((*(byte *)(*(int *)(param_1 + 0x50) + 0x5f) & 4) == 0) {
    uVar4 = 400;
    iVar3 = 500;
  }
  else {
    uVar4 = 1000;
    iVar3 = 2000;
  }
  dVar5 = (double)FUN_8000f4a0((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c)
                               ,(double)*(float *)(param_1 + 0x20));
  local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
  fVar1 = (float)(dVar5 - (double)(float)(local_28 - DOUBLE_803df8e0)) /
          (float)((double)CONCAT44(0x43300000,iVar3 - uVar4 ^ 0x80000000) - DOUBLE_803df8e0);
  fVar2 = FLOAT_803df8d8;
  if ((FLOAT_803df8d8 <= fVar1) && (fVar2 = fVar1, FLOAT_803df8e8 < fVar1)) {
    fVar2 = FLOAT_803df8e8;
  }
  return (int)((int)((float)((double)CONCAT44(0x43300000,param_2 & 0xff) - DOUBLE_803df908) *
                    (FLOAT_803df8e8 - fVar2)) * (*(byte *)(param_1 + 0x37) + 1)) >> 8;
}

/*
 * --INFO--
 *
 * Function: FUN_80062614
 * EN v1.0 Address: 0x80062614
 * EN v1.0 Size: 560b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80062614(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80062844
 * EN v1.0 Address: 0x80062844
 * EN v1.0 Size: 320b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
ushort FUN_80062844(int param_1,int param_2)
{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 100);
  if ((*(uint *)(iVar3 + 0x30) & 0x1000) == 0) {
    if (((*(uint *)(iVar3 + 0x30) & 0x10000) == 0) &&
       (*(short *)(iVar3 + 0x36) = *(short *)(iVar3 + 0x36) + (short)(param_2 << 9),
       0x3fff < *(short *)(iVar3 + 0x36))) {
      *(undefined2 *)(iVar3 + 0x36) = 0x4000;
    }
  }
  else {
    *(short *)(iVar3 + 0x36) = *(short *)(iVar3 + 0x36) - (short)(param_2 << 9);
    if (*(short *)(iVar3 + 0x36) < 1) {
      *(undefined2 *)(iVar3 + 0x36) = 0;
    }
    if (*(short *)(iVar3 + 0x36) == 0) {
      *(undefined4 *)(iVar3 + 0xc) = 0;
      return 0;
    }
  }
  dVar4 = (double)(FLOAT_803dc2b4 *
                  FLOAT_803df910 *
                  (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar3 + 0x36) ^ 0x80000000) -
                         DOUBLE_803df8e0));
  uVar2 = FUN_800624f4(param_1,(uint)*(byte *)(iVar3 + 0x3a));
  uVar1 = (ushort)(int)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                       DOUBLE_803df8e0) * dVar4);
  if ((short)uVar1 < 0x100) {
    if ((short)uVar1 < 0) {
      uVar1 = 0;
    }
  }
  else {
    uVar1 = 0xff;
  }
  return uVar1 & 0xff;
}

/*
 * --INFO--
 *
 * Function: FUN_80062984
 * EN v1.0 Address: 0x80062984
 * EN v1.0 Size: 140b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80062984(void)
{
  if (DAT_803dc2b8 == '\0') {
    return;
  }
  DAT_803ddb78 = 0;
  DAT_803ddb7c = 0;
  DAT_803ddb6c = '\x01' - DAT_803ddb6c;
  DAT_803ddb6d = '\x01' - DAT_803ddb6d;
  DAT_803ddb6e = '\x01' - DAT_803ddb6e;
  DAT_803ddb88 = *(undefined4 *)(&DAT_803ddba4 + DAT_803ddb6c * 4);
  DAT_803ddb74 = 0;
  DAT_803ddb90 = DAT_803ddba0;
  DAT_803ddb98 = DAT_803ddb9c;
  DAT_803ddb84 = *(undefined4 *)(&DAT_803ddba4 + DAT_803ddb6c * 4);
  DAT_803ddb94 = DAT_803ddb9c;
  DAT_803ddb8c = DAT_803ddba0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80062a10
 * EN v1.0 Address: 0x80062A10
 * EN v1.0 Size: 56b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80062a10(void)
{
  DAT_803ddb76 = 0;
  DAT_803ddb7a = 0;
  DAT_803ddb6a = '\x01' - DAT_803ddb6a;
  DAT_803ddb6b = '\x01' - DAT_803ddb6b;
  DAT_803ddb69 = 0;
  DAT_803ddb68 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80062a48
 * EN v1.0 Address: 0x80062A48
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80062a48(void)
{
  DAT_803dc2b8 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80062a54
 * EN v1.0 Address: 0x80062A54
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80062a54(undefined param_1)
{
  DAT_803dc2b8 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80062a60
 * EN v1.0 Address: 0x80062A60
 * EN v1.0 Size: 332b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80062a60(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,uint param_10)
{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  
  uVar1 = FUN_80022ee8(param_10);
  *(uint *)(param_9 + 100) = uVar1;
  puVar4 = *(undefined4 **)(param_9 + 100);
  iVar2 = *(int *)(param_9 + 0x50);
  if ((*(short *)(iVar2 + 0x4a) == -1) || (*(short *)(iVar2 + 0x48) == 2)) {
    if ((*(byte *)(iVar2 + 0x5f) & 4) == 0) {
      if ((*(byte *)(iVar2 + 0x5f) & 2) == 0) {
        uVar3 = FUN_8006c740();
        puVar4[1] = uVar3;
      }
      else {
        puVar4[1] = 0;
        puVar4[2] = 0;
      }
    }
    else {
      iVar2 = FUN_8006c6c8();
      puVar4[1] = iVar2;
    }
  }
  else {
    uVar3 = FUN_80054620(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    puVar4[1] = uVar3;
  }
  if (*(short *)(*(int *)(param_9 + 0x50) + 0x48) == 1) {
    puVar4[4] = 0;
  }
  else {
    puVar4[4] = 0xffffffff;
  }
  *puVar4 = **(undefined4 **)(param_9 + 0x50);
  puVar4[0xb] = *(undefined4 *)(*(int *)(param_9 + 0x50) + 0x88);
  puVar4[5] = FLOAT_803ddb58;
  puVar4[6] = FLOAT_803dc2b0;
  puVar4[7] = FLOAT_803ddb5c;
  *(undefined2 *)((int)puVar4 + 0x36) = 0x4000;
  puVar4[0xc] = 4;
  *(undefined *)(puVar4 + 0xe) = 0x19;
  *(undefined *)((int)puVar4 + 0x39) = 0x4b;
  *(undefined *)((int)puVar4 + 0x3a) = 0x96;
  *(undefined *)((int)puVar4 + 0x3b) = 100;
  DAT_803dc2b8 = 1;
  return uVar1 + 0x44;
}

/*
 * --INFO--
 *
 * Function: FUN_80062bac
 * EN v1.0 Address: 0x80062BAC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80062bac(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 100);
  if (iVar1 == 0) {
    return;
  }
  *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) & 0xffffdfdf;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80062bcc
 * EN v1.0 Address: 0x80062BCC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80062bcc(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80062bd0
 * EN v1.0 Address: 0x80062BD0
 * EN v1.0 Size: 480b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80062bd0(double param_1,double param_2,double param_3,uint param_4)
{
  double dVar1;
  double dVar2;
  double dVar3;
  float local_68;
  float local_64;
  float local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  
  local_68 = (float)param_1;
  local_64 = (float)param_2;
  local_60 = (float)param_3;
  FUN_80247ef8(&local_68,&local_68);
  DAT_803dc2ba = (undefined2)param_4;
  uStack_54 = param_4 ^ 0x80000000;
  local_58 = 0x43300000;
  FLOAT_803ddb58 =
       (float)(param_1 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803df8e0));
  local_50 = 0x43300000;
  FLOAT_803dc2b0 =
       (float)(param_2 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803df8e0));
  FLOAT_803dc2b4 = FLOAT_803df8e8;
  if (FLOAT_803dc2b0 < FLOAT_803df914) {
    FLOAT_803dc2b0 = FLOAT_803df914;
  }
  uStack_44 = param_4 ^ 0x80000000;
  local_48 = 0x43300000;
  FLOAT_803ddb5c =
       (float)(param_3 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803df8e0));
  dVar3 = (double)(local_60 * DAT_80388618 + local_68 * DAT_80388610 + local_64 * DAT_80388614);
  dVar2 = (double)(DAT_80388618 * DAT_80388618 +
                  DAT_80388610 * DAT_80388610 + DAT_80388614 * DAT_80388614);
  dVar1 = (double)(float)((double)(local_60 * local_60 + local_68 * local_68 + local_64 * local_64)
                         * dVar2);
  if (dVar1 != (double)FLOAT_803df8d8) {
    uStack_4c = uStack_54;
    dVar2 = FUN_80293900(dVar1);
  }
  dVar1 = (double)FLOAT_803df8d8;
  if (dVar2 != dVar1) {
    dVar1 = (double)(float)(dVar3 / dVar2);
  }
  FLOAT_803ddb80 = (float)dVar1;
  if ((float)dVar1 < FLOAT_803df8d8) {
    FLOAT_803ddb80 = (float)dVar1 * FLOAT_803df918;
  }
  if (FLOAT_803ddb80 <= FLOAT_803df91c) {
    DAT_803dc2bc = 1;
  }
  if (DAT_803dc2bc != 0) {
    DAT_80388610 = local_68;
    DAT_80388614 = local_64;
    DAT_80388618 = local_60;
    DAT_803dc2bc = 0;
    DAT_803dc2b8 = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80062db0
 * EN v1.0 Address: 0x80062DB0
 * EN v1.0 Size: 300b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80062db0(void)
{
  DAT_803dc2b8 = 10;
  DAT_803ddbac = FUN_80023d8c(0xa8c0,0x18);
  DAT_8038e3dc = FLOAT_803df918;
  DAT_8038e43c = FLOAT_803df918;
  DAT_8038e3e0 = FLOAT_803df918;
  DAT_8038e440 = FLOAT_803df918;
  DAT_8038e3e4 = FLOAT_803df918;
  DAT_8038e444 = FLOAT_803df918;
  DAT_8038e3e8 = FLOAT_803df918;
  DAT_8038e448 = FLOAT_803df918;
  DAT_8038e3ec = FLOAT_803df8d8;
  DAT_8038e44c = FLOAT_803df8d8;
  DAT_8038e3f0 = FLOAT_803df918;
  DAT_8038e450 = FLOAT_803df918;
  DAT_8038e3f4 = FLOAT_803df8e8;
  DAT_8038e454 = FLOAT_803df8e8;
  DAT_8038e3f8 = FLOAT_803df8d8;
  DAT_8038e458 = FLOAT_803df8d8;
  DAT_8038e3fc = FLOAT_803df918;
  DAT_8038e45c = FLOAT_803df918;
  DAT_8038e400 = FLOAT_803df8e8;
  DAT_8038e460 = FLOAT_803df8e8;
  DAT_8038e404 = FLOAT_803df918;
  DAT_8038e464 = FLOAT_803df918;
  DAT_8038e408 = FLOAT_803df918;
  DAT_8038e468 = FLOAT_803df918;
  DAT_8038e46c = FLOAT_803df918;
  DAT_8038e470 = FLOAT_803df918;
  DAT_8038e474 = FLOAT_803df8e8;
  DAT_8038e478 = FLOAT_803df918;
  DAT_8038e47c = FLOAT_803df8d8;
  DAT_8038e480 = FLOAT_803df8e8;
  DAT_8038e484 = FLOAT_803df8e8;
  DAT_8038e488 = FLOAT_803df8d8;
  DAT_8038e48c = FLOAT_803df8e8;
  DAT_8038e490 = FLOAT_803df8e8;
  DAT_8038e494 = FLOAT_803df918;
  DAT_8038e498 = FLOAT_803df8e8;
  DAT_8038e40c = FLOAT_803df920;
  DAT_8038e410 = FLOAT_803df8d8;
  DAT_8038e414 = FLOAT_803df924;
  DAT_8038e418 = FLOAT_803df920;
  DAT_8038e41c = FLOAT_803df928;
  DAT_8038e420 = FLOAT_803df924;
  DAT_8038e424 = FLOAT_803df92c;
  DAT_8038e428 = FLOAT_803df928;
  DAT_8038e42c = FLOAT_803df924;
  DAT_8038e430 = FLOAT_803df92c;
  DAT_8038e434 = FLOAT_803df8d8;
  DAT_8038e438 = FLOAT_803df924;
  FUN_8006d764();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80062edc
 * EN v1.0 Address: 0x80062EDC
 * EN v1.0 Size: 292b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80062edc(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5,
                float *param_6,undefined4 *param_7)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80063000
 * EN v1.0 Address: 0x80063000
 * EN v1.0 Size: 596b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80063000(short *param_1,short *param_2,int param_3)
{
  int iVar1;
  short *psVar2;
  int iVar3;
  float local_28;
  float local_24;
  float afStack_20 [4];
  
  psVar2 = *(short **)(param_1 + 0x18);
  if (psVar2 != param_2) {
    if (psVar2 != (short *)0x0) {
      FUN_8000e338();
    }
    if (param_2 != (short *)0x0) {
      FUN_8000e338();
    }
    if (param_1[0x22] == 1) {
      FUN_80297614();
    }
    else {
      *(short **)(param_1 + 0x18) = param_2;
      iVar1 = *(int *)(param_1 + 0x2a);
      if (psVar2 == (short *)0x0) {
        local_24 = *(float *)(param_1 + 0x12);
        local_28 = *(float *)(param_1 + 0x16);
        iVar3 = (int)*param_1;
      }
      else {
        FUN_8000e0c0((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                     (double)*(float *)(param_1 + 10),(float *)(param_1 + 0xc),
                     (float *)(param_1 + 0xe),(float *)(param_1 + 0x10),(int)psVar2);
        FUN_8000e0c0((double)*(float *)(param_1 + 0x40),(double)*(float *)(param_1 + 0x42),
                     (double)*(float *)(param_1 + 0x44),(float *)(param_1 + 0x46),
                     (float *)(param_1 + 0x48),(float *)(param_1 + 0x4a),(int)psVar2);
        FUN_8000df3c((double)*(float *)(param_1 + 0x12),(double)FLOAT_803df934,
                     (double)*(float *)(param_1 + 0x16),&local_24,afStack_20,&local_28,(int)psVar2);
        iVar3 = (int)*psVar2 + (int)*param_1;
      }
      if (param_3 != 0) {
        if (*(int *)(param_1 + 0x18) == 0) {
          *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_1 + 0xc);
          *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_1 + 0xe);
          *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_1 + 0x10);
          *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 0x46);
          *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 0x48);
          *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 0x4a);
          *(float *)(param_1 + 0x12) = local_24;
          *(float *)(param_1 + 0x16) = local_28;
          *param_1 = (short)iVar3;
        }
        else {
          FUN_8000e054((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                       (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),
                       (float *)(param_1 + 8),(float *)(param_1 + 10),*(int *)(param_1 + 0x18));
          FUN_8000e054((double)*(float *)(param_1 + 0x46),(double)*(float *)(param_1 + 0x48),
                       (double)*(float *)(param_1 + 0x4a),(float *)(param_1 + 0x40),
                       (float *)(param_1 + 0x42),(float *)(param_1 + 0x44),*(int *)(param_1 + 0x18))
          ;
          FUN_8000dfc8((double)local_24,(double)FLOAT_803df934,(double)local_28,
                       (float *)(param_1 + 0x12),afStack_20,(float *)(param_1 + 0x16),
                       *(int *)(param_1 + 0x18));
          iVar3 = iVar3 - **(short **)(param_1 + 0x18);
          if (0x8000 < iVar3) {
            iVar3 = iVar3 + -0xffff;
          }
          if (iVar3 < -0x8000) {
            iVar3 = iVar3 + 0xffff;
          }
          *param_1 = (short)iVar3;
        }
      }
      if (iVar1 != 0) {
        *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_1 + 6);
        *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(param_1 + 8);
        *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(param_1 + 10);
        *(undefined4 *)(iVar1 + 0x1c) = *(undefined4 *)(param_1 + 0xc);
        *(undefined4 *)(iVar1 + 0x20) = *(undefined4 *)(param_1 + 0xe);
        *(undefined4 *)(iVar1 + 0x24) = *(undefined4 *)(param_1 + 0x10);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80063254
 * EN v1.0 Address: 0x80063254
 * EN v1.0 Size: 656b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80063254(double param_1,double param_2,double param_3,float *param_4,float *param_5,char param_6
            )
{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  
  dVar2 = (double)FLOAT_803df934;
  if (dVar2 != param_3) {
    dVar5 = (double)*param_4;
    dVar4 = (double)(float)(dVar5 - param_1);
    dVar3 = (double)(float)((double)*param_5 - param_2);
    dVar6 = -(double)(float)(param_3 * param_3 -
                            (double)((float)(dVar4 * dVar4) + (float)(dVar3 * dVar3)));
    if (dVar2 <= dVar6) {
      dVar8 = (double)(float)((double)param_4[1] - dVar5);
      dVar7 = (double)(float)((double)param_5[1] - (double)*param_5);
      dVar5 = (double)(float)(dVar8 * dVar8 + (double)(float)(dVar7 * dVar7));
      if (dVar2 < dVar5) {
        dVar4 = (double)(FLOAT_803df938 * (float)(dVar8 * dVar4 + (double)(float)(dVar7 * dVar3)));
        dVar3 = (double)(float)(dVar4 * dVar4 -
                               (double)(float)((double)(float)((double)FLOAT_803df93c * dVar5) *
                                              dVar6));
        if (dVar2 <= dVar3) {
          dVar3 = FUN_80293900(dVar3);
          dVar2 = (double)((float)(-dVar4 + dVar3) / (float)((double)FLOAT_803df938 * dVar5));
          dVar3 = (double)((float)(-dVar4 - dVar3) / (float)((double)FLOAT_803df938 * dVar5));
          if (dVar2 < (double)FLOAT_803df934) {
            dVar2 = (double)FLOAT_803df940;
          }
          if (dVar3 < (double)FLOAT_803df934) {
            dVar3 = (double)FLOAT_803df940;
          }
          if (dVar3 < dVar2) {
            dVar2 = dVar3;
          }
          if (((double)FLOAT_803df934 <= dVar2) && (dVar2 <= (double)FLOAT_803df944)) {
            FLOAT_803ddbd8 = (float)dVar2;
            if (param_6 != '\0') {
              dVar3 = (double)(float)(dVar2 * dVar8 + (double)*param_4);
              dVar2 = (double)(float)(dVar2 * dVar7 + (double)*param_5);
              dVar4 = (double)(float)((double)(float)(dVar3 - param_1) / param_3);
              dVar5 = (double)(float)((double)(float)(dVar2 - param_2) / param_3);
              fVar1 = -(float)(dVar3 * dVar4 + (double)(float)(dVar2 * dVar5));
              dVar2 = (double)(fVar1 + (float)(dVar4 * (double)param_4[1] +
                                              (double)(float)(dVar5 * (double)param_5[1])));
              param_4[1] = -(float)(dVar2 * dVar4 - (double)param_4[1]);
              param_5[1] = -(float)(dVar2 * dVar5 - (double)param_5[1]);
              dVar2 = (double)FLOAT_803df948;
              while ((double)(fVar1 + (float)((double)param_4[1] * dVar4 +
                                             (double)(float)((double)param_5[1] * dVar5))) < dVar2)
              {
                param_4[1] = param_4[1] + (float)(dVar2 * dVar4);
                param_5[1] = param_5[1] + (float)(dVar2 * dVar5);
              }
            }
            return 1;
          }
        }
      }
    }
    else if (param_6 != '\0') {
      param_4[1] = (float)(dVar5 + (double)FLOAT_803ddbd4);
      param_5[1] = *param_5 + FLOAT_803ddbd0;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800634e4
 * EN v1.0 Address: 0x800634E4
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800634e4(int param_1)
{
  int iVar1;
  short sVar2;
  
  iVar1 = 0;
  for (sVar2 = 0; sVar2 < 0x40; sVar2 = sVar2 + 1) {
    if (*(int *)(DAT_803ddbc8 + iVar1) == param_1) {
      *(undefined *)((int *)(DAT_803ddbc8 + iVar1) + 5) = 0;
    }
    iVar1 = iVar1 + 0x18;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80063524
 * EN v1.0 Address: 0x80063524
 * EN v1.0 Size: 3144b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80063524(undefined4 param_1,undefined4 param_2,uint param_3,int *param_4,int param_5,
                 char param_6,char param_7,char param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8006416c
 * EN v1.0 Address: 0x8006416C
 * EN v1.0 Size: 220b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8006416c(double param_1,double param_2,double param_3,undefined2 param_4,int param_5)
{
  int iVar1;
  float *pfVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = 0;
  iVar1 = (int)DAT_803ddbdc;
  pfVar2 = DAT_803ddbb8;
  iVar4 = iVar1;
  if (0 < iVar1) {
    do {
      if (((param_1 == (double)*pfVar2) && (param_2 == (double)pfVar2[1])) &&
         (param_3 == (double)pfVar2[2])) {
        *(undefined2 *)(param_5 + iVar3 * 4 + 2) = param_4;
        return iVar3;
      }
      pfVar2 = pfVar2 + 3;
      iVar3 = iVar3 + 1;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  DAT_803ddbb8[iVar1 * 3] = (float)param_1;
  DAT_803ddbb8[DAT_803ddbdc * 3 + 1] = (float)param_2;
  DAT_803ddbb8[DAT_803ddbdc * 3 + 2] = (float)param_3;
  *(undefined2 *)(param_5 + DAT_803ddbdc * 4) = param_4;
  *(undefined2 *)(param_5 + DAT_803ddbdc * 4 + 2) = 0xffff;
  DAT_803ddbdc = DAT_803ddbdc + 1;
  return DAT_803ddbdc + -1;
}

/*
 * --INFO--
 *
 * Function: FUN_80064248
 * EN v1.0 Address: 0x80064248
 * EN v1.0 Size: 1656b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80064248(undefined4 param_1,undefined4 param_2,float *param_3,int *param_4,int *param_5,
                 undefined4 param_6,undefined4 param_7,uint param_8,byte param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800648c0
 * EN v1.0 Address: 0x800648C0
 * EN v1.0 Size: 1352b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800648c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  short sVar8;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  ushort uVar9;
  short *psVar10;
  ushort uVar11;
  int iVar12;
  undefined2 uVar13;
  short *psVar14;
  double extraout_f1;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps31_1;
  short asStack_1ad8 [3400];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  float fStack_8;
  float fStack_4;
  
  fStack_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar2 = FUN_80286834();
  DAT_803ddbce = 1;
  DAT_803ddbde = 0;
  DAT_803ddbdc = 0;
  bVar1 = *(byte *)(iVar2 + 0x5c);
  psVar14 = *(short **)(iVar2 + 0x30);
  dVar15 = extraout_f1;
  for (iVar12 = 0; iVar12 < (int)(uint)bVar1; iVar12 = iVar12 + 1) {
    if (DAT_803ddbde < 0x5dc) {
      puVar4 = (undefined *)(DAT_803ddbb4 + DAT_803ddbde * 0x10);
      *puVar4 = *(undefined *)(psVar14 + 6);
      puVar4[1] = *(undefined *)((int)psVar14 + 0xd);
      puVar4[3] = *(undefined *)((int)psVar14 + 0xf);
      if ((puVar4[3] & 0x3f) == 0x11) {
        puVar4[3] = puVar4[3] & 0xc0;
        puVar4[3] = puVar4[3] | 2;
      }
      puVar4[2] = *(undefined *)(psVar14 + 7);
      puVar4[2] = puVar4[2] ^ 0x10;
      *(short *)(puVar4 + 0xc) = psVar14[8];
      iVar5 = 0;
      psVar10 = psVar14;
      dVar16 = DOUBLE_803df958;
      do {
        uStack_44 = (int)*psVar10 ^ 0x80000000;
        local_48 = 0x43300000;
        dVar15 = (double)(float)((double)CONCAT44(0x43300000,uStack_44) - dVar16);
        uStack_3c = (int)psVar10[2] ^ 0x80000000;
        local_40 = 0x43300000;
        param_2 = (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - dVar16);
        uStack_34 = (int)psVar10[4] ^ 0x80000000;
        local_38 = 0x43300000;
        param_3 = (double)(float)((double)CONCAT44(0x43300000,uStack_34) - dVar16);
        if (DAT_803ddbdc < 0x6a4) {
          iVar3 = FUN_8006416c(dVar15,param_2,param_3,DAT_803ddbde,(int)asStack_1ad8);
          *(short *)(puVar4 + 4) = (short)iVar3;
        }
        psVar10 = psVar10 + 1;
        puVar4 = puVar4 + 2;
        iVar5 = iVar5 + 1;
      } while (iVar5 < 2);
      DAT_803ddbde = DAT_803ddbde + 1;
    }
    psVar14 = psVar14 + 10;
  }
  iVar12 = 0;
  for (iVar5 = 0; iVar5 < DAT_803ddbde; iVar5 = iVar5 + 1) {
    iVar3 = DAT_803ddbb4 + iVar12;
    sVar8 = asStack_1ad8[*(short *)(iVar3 + 4) * 2];
    if ((sVar8 < 0) || (sVar8 == iVar5)) {
      sVar8 = asStack_1ad8[*(short *)(iVar3 + 4) * 2 + 1];
      if ((sVar8 < 0) || (sVar8 == iVar5)) {
        *(undefined2 *)(iVar3 + 8) = 0xffff;
      }
      else {
        *(short *)(iVar3 + 8) = sVar8;
      }
    }
    else {
      *(short *)(iVar3 + 8) = sVar8;
    }
    sVar8 = asStack_1ad8[*(short *)(iVar3 + 6) * 2];
    if ((sVar8 < 0) || (sVar8 == iVar5)) {
      sVar8 = asStack_1ad8[*(short *)(iVar3 + 6) * 2 + 1];
      if ((sVar8 < 0) || (sVar8 == iVar5)) {
        *(undefined2 *)(iVar3 + 10) = 0xffff;
      }
      else {
        *(short *)(iVar3 + 10) = sVar8;
      }
    }
    else {
      *(short *)(iVar3 + 10) = sVar8;
    }
    iVar12 = iVar12 + 0x10;
  }
  iVar12 = DAT_803ddbde * 0x10 + DAT_803ddbdc * 0xc + 0x28;
  if (iVar12 != 0) {
    iVar12 = FUN_80023d8c(iVar12,-0xff01);
    *(int *)(iVar2 + 0x34) = iVar12;
    *(int *)(iVar2 + 0x3c) = *(int *)(iVar2 + 0x34) + DAT_803ddbde * 0x10;
    *(int *)(iVar2 + 0x38) = *(int *)(iVar2 + 0x3c) + DAT_803ddbdc * 0xc;
    iVar12 = 0;
    iVar5 = 5;
    do {
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 1) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 2) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 3) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 4) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 5) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 6) = 0xff;
      *(undefined *)(*(int *)(iVar2 + 0x38) + iVar12 + 7) = 0xff;
      iVar12 = iVar12 + 8;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    uVar11 = 0xffff;
    iVar5 = 0;
    for (iVar12 = 0; iVar3 = (int)DAT_803ddbde, iVar12 < iVar3; iVar12 = iVar12 + 1) {
      sVar8 = 0;
      iVar7 = 0;
      iVar6 = DAT_803ddbb4;
      if (0 < iVar3) {
        do {
          if ((*(byte *)(iVar6 + 3) & 0x3f) < (*(byte *)(DAT_803ddbb4 + sVar8 * 0x10 + 3) & 0x3f)) {
            sVar8 = (short)iVar7;
          }
          iVar6 = iVar6 + 0x10;
          iVar7 = iVar7 + 1;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
      iVar3 = sVar8 * 0x10;
      uVar9 = (short)*(char *)(DAT_803ddbb4 + iVar3 + 3) & 0x3f;
      if (0x13 < uVar9) {
        uVar9 = 1;
        FUN_80137c30(dVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     s_trackIntersect__FUNC_OVERFLOW__d_8030f43c,1,iVar6,DAT_803ddbb4,iVar7,in_r8,
                     in_r9,in_r10);
      }
      iVar6 = (int)(short)uVar11;
      if ((short)uVar9 != iVar6) {
        *(char *)(*(int *)(iVar2 + 0x38) + (short)uVar9 * 2) = (char)iVar12;
        uVar11 = uVar9;
        if (iVar6 != -1) {
          *(char *)(*(int *)(iVar2 + 0x38) + iVar6 * 2 + 1) = (char)iVar12;
        }
      }
      iVar7 = 0;
      uVar13 = (undefined2)iVar12;
      iVar6 = iVar12;
      if (0 < iVar12) {
        do {
          if (sVar8 == *(short *)(*(int *)(iVar2 + 0x34) + iVar7 + 8)) {
            *(undefined2 *)(*(int *)(iVar2 + 0x34) + iVar7 + 8) = uVar13;
          }
          if (sVar8 == *(short *)(*(int *)(iVar2 + 0x34) + iVar7 + 10)) {
            *(undefined2 *)(*(int *)(iVar2 + 0x34) + iVar7 + 10) = uVar13;
          }
          iVar7 = iVar7 + 0x10;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      iVar6 = 0;
      for (in_r8 = 0; in_r8 < DAT_803ddbde; in_r8 = in_r8 + 1) {
        iVar7 = DAT_803ddbb4 + iVar6;
        if (*(char *)(iVar7 + 3) != '\x14') {
          if (sVar8 == *(short *)(iVar7 + 8)) {
            *(undefined2 *)(iVar7 + 8) = uVar13;
          }
          if (sVar8 == *(short *)(DAT_803ddbb4 + iVar6 + 10)) {
            *(undefined2 *)(DAT_803ddbb4 + iVar6 + 10) = uVar13;
          }
        }
        iVar6 = iVar6 + 0x10;
      }
      dVar15 = (double)FUN_80003494(*(int *)(iVar2 + 0x34) + iVar5,DAT_803ddbb4 + iVar3,0x10);
      *(undefined *)(DAT_803ddbb4 + iVar3 + 3) = 0x14;
      iVar5 = iVar5 + 0x10;
    }
    if ((short)uVar11 != -1) {
      *(char *)(*(int *)(iVar2 + 0x38) + (short)uVar11 * 2 + 1) = (char)DAT_803ddbde;
    }
    FUN_80003494(*(uint *)(iVar2 + 0x3c),DAT_803ddbb8,DAT_803ddbdc * 0xc);
    DAT_803ddbde = 0;
    DAT_803ddbdc = 0;
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80064e08
 * EN v1.0 Address: 0x80064E08
 * EN v1.0 Size: 2280b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80064e08(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  short sVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  int in_r9;
  int in_r10;
  undefined *puVar7;
  ushort uVar8;
  ushort uVar9;
  uint uVar10;
  uint uVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  undefined *puVar16;
  char *pcVar17;
  int iVar18;
  double dVar19;
  double in_f25;
  double dVar20;
  double in_f26;
  double dVar21;
  double in_f27;
  double dVar22;
  double in_f28;
  double dVar23;
  double in_f29;
  double dVar24;
  double in_f30;
  double dVar25;
  double in_f31;
  double dVar26;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  short local_1be8 [70];
  short local_1b5c [2];
  short asStack_1b58 [3400];
  undefined4 local_c8;
  uint uStack_c4;
  undefined4 local_c0;
  uint uStack_bc;
  undefined4 local_b8;
  uint uStack_b4;
  float fStack_68;
  float fStack_64;
  float fStack_58;
  float fStack_54;
  float fStack_48;
  float fStack_44;
  float fStack_38;
  float fStack_34;
  float fStack_28;
  float fStack_24;
  float fStack_18;
  float fStack_14;
  float fStack_8;
  float fStack_4;
  
  fStack_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  fStack_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  fStack_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  fStack_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  fStack_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  fStack_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  fStack_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  dVar19 = (double)FUN_80286814();
  DAT_803ddbc4 = 0;
  if ((DAT_803ddbcd != '\0') && (iVar3 = FUN_80020800(), iVar3 == 0)) {
    DAT_803ddbcd = DAT_803ddbcd + -1;
  }
  if (DAT_803ddbce == '\x01') {
    DAT_803ddbcf = '\x01';
    DAT_803ddbce = '\0';
  }
  else if (DAT_803ddbcf != '\0') {
    DAT_803ddbcf = '\0';
    iVar3 = FUN_80020800();
    if (iVar3 != 0) {
      DAT_803ddbcd = '\x02';
    }
    iVar3 = 0;
    psVar6 = local_1be8;
    iVar18 = 2;
    do {
      *psVar6 = 0;
      psVar6[1] = 0;
      psVar6[2] = 0;
      psVar6[3] = 0;
      psVar6[4] = 0;
      psVar6[5] = 0;
      psVar6[6] = 0;
      psVar6[7] = 0;
      psVar6[8] = 0;
      psVar6[9] = 0;
      psVar6[10] = 0;
      psVar6[0xb] = 0;
      psVar6[0xc] = 0;
      psVar6[0xd] = 0;
      psVar6[0xe] = 0;
      psVar6[0xf] = 0;
      psVar6[0x10] = 0;
      psVar6[0x11] = 0;
      psVar6[0x12] = 0;
      psVar6[0x13] = 0;
      psVar6[0x14] = 0;
      psVar6[0x15] = 0;
      psVar6[0x16] = 0;
      psVar6[0x17] = 0;
      psVar6[0x18] = 0;
      psVar6[0x19] = 0;
      psVar6[0x1a] = 0;
      psVar6[0x1b] = 0;
      psVar6[0x1c] = 0;
      psVar6[0x1d] = 0;
      psVar6[0x1e] = 0;
      psVar6[0x1f] = 0;
      psVar6 = psVar6 + 0x20;
      iVar3 = iVar3 + 0x20;
      iVar18 = iVar18 + -1;
    } while (iVar18 != 0);
    psVar6 = local_1be8 + iVar3;
    iVar18 = 0x47 - iVar3;
    if (iVar3 < 0x47) {
      do {
        *psVar6 = 0;
        psVar6 = psVar6 + 1;
        iVar18 = iVar18 + -1;
      } while (iVar18 != 0);
    }
    DAT_803ddbde = 0;
    DAT_803ddbdc = 0;
    iVar3 = 0;
    dVar25 = (double)FLOAT_803df960;
    dVar26 = DOUBLE_803df958;
    do {
      iVar18 = FUN_8005b094(iVar3);
      uVar10 = 0;
      iVar14 = 0;
      do {
        uVar11 = 0;
        uStack_c4 = uVar10 ^ 0x80000000;
        local_c8 = 0x43300000;
        dVar24 = (double)(float)(dVar25 * (double)(float)((double)CONCAT44(0x43300000,uStack_c4) -
                                                         dVar26));
        pcVar17 = (char *)(iVar18 + iVar14);
        do {
          if (-1 < *pcVar17) {
            iVar4 = FUN_8005b068((int)*pcVar17);
            iVar15 = 0;
            param_2 = (double)FLOAT_803df960;
            uStack_c4 = uVar11 ^ 0x80000000;
            local_c8 = 0x43300000;
            dVar22 = (double)(float)(param_2 *
                                    (double)(float)((double)CONCAT44(0x43300000,uStack_c4) -
                                                   DOUBLE_803df958));
            dVar19 = DOUBLE_803df958;
            for (iVar13 = 0; iVar13 < (int)(uint)*(ushort *)(iVar4 + 0x9c); iVar13 = iVar13 + 1) {
              if (DAT_803ddbde < 0x5dc) {
                psVar6 = (short *)(*(int *)(iVar4 + 0x70) + iVar15);
                puVar7 = (undefined *)(DAT_803ddbb4 + DAT_803ddbde * 0x10);
                *puVar7 = *(undefined *)(psVar6 + 6);
                puVar7[1] = *(undefined *)((int)psVar6 + 0xd);
                puVar7[3] = *(undefined *)((int)psVar6 + 0xf);
                if ((puVar7[3] & 0x3f) == 0x11) {
                  puVar7[3] = puVar7[3] & 0xc0;
                  puVar7[3] = puVar7[3] | 2;
                }
                puVar7[2] = *(undefined *)(psVar6 + 7);
                puVar7[2] = puVar7[2] ^ 0x10;
                *(short *)(puVar7 + 0xc) = psVar6[8];
                dVar21 = (double)(float)(dVar22 + (double)FLOAT_803dda58);
                dVar20 = (double)(float)(dVar24 + (double)FLOAT_803dda5c);
                iVar12 = 0;
                puVar16 = puVar7;
                dVar23 = DOUBLE_803df958;
                do {
                  uStack_c4 = (int)*psVar6 ^ 0x80000000;
                  local_c8 = 0x43300000;
                  dVar19 = (double)(float)(dVar21 + (double)(float)((double)CONCAT44(0x43300000,
                                                                                     uStack_c4) -
                                                                   dVar23));
                  uStack_bc = (int)psVar6[2] ^ 0x80000000;
                  local_c0 = 0x43300000;
                  param_2 = (double)(float)((double)CONCAT44(0x43300000,uStack_bc) - dVar23);
                  uStack_b4 = (int)psVar6[4] ^ 0x80000000;
                  local_b8 = 0x43300000;
                  param_3 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_b4) -
                                                           dVar23) + dVar20);
                  if (DAT_803ddbdc < 0x6a4) {
                    iVar5 = FUN_8006416c(dVar19,param_2,param_3,DAT_803ddbde,(int)asStack_1b58);
                    *(short *)(puVar16 + 4) = (short)iVar5;
                  }
                  psVar6 = psVar6 + 1;
                  puVar16 = puVar16 + 2;
                  iVar12 = iVar12 + 1;
                } while (iVar12 < 2);
                local_1be8[(int)(char)puVar7[3] & 0x3fU] =
                     local_1be8[(int)(char)puVar7[3] & 0x3fU] + 1;
                DAT_803ddbde = DAT_803ddbde + 1;
              }
              iVar15 = iVar15 + 0x14;
            }
          }
          pcVar17 = pcVar17 + 1;
          uVar11 = uVar11 + 1;
        } while ((int)uVar11 < 0x10);
        iVar14 = iVar14 + 0x10;
        uVar10 = uVar10 + 1;
      } while ((int)uVar10 < 0x10);
      iVar3 = iVar3 + 1;
    } while (iVar3 < 5);
    iVar3 = 0;
    for (iVar18 = 0; iVar18 < DAT_803ddbde; iVar18 = iVar18 + 1) {
      iVar14 = DAT_803ddbb4 + iVar3;
      sVar1 = asStack_1b58[*(short *)(iVar14 + 4) * 2];
      if ((sVar1 < 0) || (sVar1 == iVar18)) {
        sVar1 = asStack_1b58[*(short *)(iVar14 + 4) * 2 + 1];
        if ((sVar1 < 0) || (sVar1 == iVar18)) {
          *(undefined2 *)(iVar14 + 8) = 0xffff;
        }
        else {
          *(short *)(iVar14 + 8) = sVar1;
        }
      }
      else {
        *(short *)(iVar14 + 8) = sVar1;
      }
      sVar1 = asStack_1b58[*(short *)(iVar14 + 6) * 2];
      if ((sVar1 < 0) || (sVar1 == iVar18)) {
        sVar1 = asStack_1b58[*(short *)(iVar14 + 6) * 2 + 1];
        if ((sVar1 < 0) || (sVar1 == iVar18)) {
          *(undefined2 *)(iVar14 + 10) = 0xffff;
        }
        else {
          *(short *)(iVar14 + 10) = sVar1;
        }
      }
      else {
        *(short *)(iVar14 + 10) = sVar1;
      }
      iVar3 = iVar3 + 0x10;
    }
    if (DAT_803ddbc0 != 0) {
      iVar3 = 0;
      for (iVar18 = 0; iVar18 < DAT_803ddbde; iVar18 = iVar18 + 1) {
        *(short *)(DAT_803ddbc0 + iVar3) = (short)iVar18;
        iVar3 = iVar3 + 2;
      }
      bVar2 = false;
      while (!bVar2) {
        bVar2 = true;
        iVar3 = 0;
        for (in_r10 = 0; in_r10 < DAT_803ddbde + -1; in_r10 = in_r10 + 1) {
          psVar6 = (short *)(DAT_803ddbc0 + iVar3);
          sVar1 = *psVar6;
          in_r9 = (int)psVar6[1];
          if ((*(byte *)(DAT_803ddbb4 + sVar1 * 0x10 + 3) & 0x3f) <
              (*(byte *)(DAT_803ddbb4 + in_r9 * 0x10 + 3) & 0x3f)) {
            *psVar6 = psVar6[1];
            *(short *)(DAT_803ddbc0 + iVar3 + 2) = sVar1;
            bVar2 = false;
          }
          iVar3 = iVar3 + 2;
        }
      }
    }
    psVar6 = local_1b5c;
    iVar3 = 7;
    do {
      psVar6[-1] = psVar6[-1] + *psVar6;
      psVar6[-2] = psVar6[-2] + psVar6[-1];
      psVar6[-3] = psVar6[-3] + psVar6[-2];
      psVar6[-4] = psVar6[-4] + psVar6[-3];
      psVar6[-5] = psVar6[-5] + psVar6[-4];
      psVar6[-6] = psVar6[-6] + psVar6[-5];
      psVar6[-7] = psVar6[-7] + psVar6[-6];
      psVar6[-8] = psVar6[-8] + psVar6[-7];
      psVar6[-9] = psVar6[-9] + psVar6[-8];
      psVar6[-10] = psVar6[-10] + psVar6[-9];
      psVar6 = psVar6 + -10;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    iVar3 = 0;
    psVar6 = local_1be8;
    for (iVar18 = 0; iVar14 = (int)DAT_803ddbde, iVar18 < iVar14; iVar18 = iVar18 + 1) {
      iVar14 = ((int)*(char *)(DAT_803ddbb4 + iVar3 + 3) & 0x3fU) + 1;
      sVar1 = psVar6[iVar14];
      psVar6[iVar14] = sVar1 + 1;
      *(short *)(DAT_803ddbbc + sVar1 * 2) = (short)iVar18;
      iVar3 = iVar3 + 0x10;
    }
    iVar13 = 0;
    iVar4 = iVar14 + -1;
    if (0 < iVar4) {
      if ((8 < iVar4) && (uVar10 = iVar14 - 2U >> 3, 0 < iVar14 + -9)) {
        do {
          iVar13 = iVar13 + 8;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
      iVar14 = iVar4 - iVar13;
      if (iVar13 < iVar4) {
        do {
          iVar14 = iVar14 + -1;
        } while (iVar14 != 0);
      }
    }
    DAT_8038e4a0 = 0xffff;
    DAT_8038e4a2 = 0xffff;
    DAT_8038e4a4 = 0xffff;
    DAT_8038e4a6 = 0xffff;
    DAT_8038e4a8 = 0xffff;
    DAT_8038e4aa = 0xffff;
    DAT_8038e4ac = 0xffff;
    DAT_8038e4ae = 0xffff;
    DAT_8038e4b0 = 0xffff;
    DAT_8038e4b2 = 0xffff;
    DAT_8038e4b4 = 0xffff;
    DAT_8038e4b6 = 0xffff;
    DAT_8038e4b8 = 0xffff;
    DAT_8038e4ba = 0xffff;
    DAT_8038e4bc = 0xffff;
    DAT_8038e4be = 0xffff;
    DAT_8038e4c0 = 0xffff;
    DAT_8038e4c2 = 0xffff;
    DAT_8038e4c4 = 0xffff;
    DAT_8038e4c6 = 0xffff;
    DAT_8038e4c8 = 0xffff;
    DAT_8038e4ca = 0xffff;
    DAT_8038e4cc = 0xffff;
    DAT_8038e4ce = 0xffff;
    DAT_8038e4d0 = 0xffff;
    DAT_8038e4d2 = 0xffff;
    DAT_8038e4d4 = 0xffff;
    DAT_8038e4d6 = 0xffff;
    DAT_8038e4d8 = 0xffff;
    DAT_8038e4da = 0xffff;
    DAT_8038e4dc = 0xffff;
    DAT_8038e4de = 0xffff;
    DAT_8038e4e0 = 0xffff;
    DAT_8038e4e2 = 0xffff;
    DAT_8038e4e4 = 0xffff;
    DAT_8038e4e6 = 0xffff;
    DAT_8038e4e8 = 0xffff;
    DAT_8038e4ea = 0xffff;
    DAT_8038e4ec = 0xffff;
    DAT_8038e4ee = 0xffff;
    uVar8 = 0xffff;
    iVar14 = 0;
    for (iVar4 = 0; iVar4 < DAT_803ddbde; iVar4 = iVar4 + 1) {
      uVar9 = (short)*(char *)(DAT_803ddbb4 + *(short *)(DAT_803ddbbc + iVar14) * 0x10 + 3) & 0x3f;
      if (0x13 < uVar9) {
        uVar9 = 1;
        dVar19 = (double)FUN_80137c30(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      ,s_trackIntersect__FUNC_OVERFLOW__d_8030f43c,1,iVar13,psVar6,
                                      iVar3,iVar18,in_r9,in_r10);
      }
      iVar13 = (int)(short)uVar8;
      if (iVar13 != (short)uVar9) {
        (&DAT_8038e4a0)[(short)uVar9 * 2] = (short)iVar4;
        uVar8 = uVar9;
        if (iVar13 != -1) {
          (&DAT_8038e4a2)[iVar13 * 2] = (short)iVar4;
        }
      }
      iVar14 = iVar14 + 2;
    }
    if ((short)uVar8 != -1) {
      (&DAT_8038e4a2)[(short)uVar8 * 2] = DAT_803ddbde;
    }
    DAT_803ddbc4 = 1;
  }
  FUN_80286860();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800656f0
 * EN v1.0 Address: 0x800656F0
 * EN v1.0 Size: 144b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800656f0(int param_1,int param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  
  if (param_2 == 0) {
    uVar1 = (uint)DAT_803ddbde;
    iVar2 = DAT_803ddbb4;
  }
  else {
    uVar1 = (uint)*(byte *)(*(int *)(param_2 + 0x50) + 0x5c);
    iVar2 = *(int *)(*(int *)(param_2 + 0x50) + 0x34);
  }
  if (param_3 != 0) {
    if ((int)uVar1 < 1) {
      return;
    }
    do {
      if (*(short *)(iVar2 + 0xc) == param_1) {
        *(byte *)(iVar2 + 3) = *(byte *)(iVar2 + 3) & 0xbf;
      }
      iVar2 = iVar2 + 0x10;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
    return;
  }
  if ((int)uVar1 < 1) {
    return;
  }
  do {
    if (*(short *)(iVar2 + 0xc) == param_1) {
      *(byte *)(iVar2 + 3) = *(byte *)(iVar2 + 3) | 0x40;
    }
    iVar2 = iVar2 + 0x10;
    uVar1 = uVar1 - 1;
  } while (uVar1 != 0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80065780
 * EN v1.0 Address: 0x80065780
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80065780(void)
{
  char cVar1;
  int iVar2;
  short sVar3;
  
  sVar3 = 0;
  iVar2 = 0;
  do {
    cVar1 = *(char *)(DAT_803ddbc8 + iVar2 + 0x14);
    if (cVar1 != '\0') {
      *(char *)(DAT_803ddbc8 + iVar2 + 0x14) = cVar1 + -1;
    }
    iVar2 = iVar2 + 0x18;
    sVar3 = sVar3 + 1;
  } while (sVar3 < 0x40);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800657bc
 * EN v1.0 Address: 0x800657BC
 * EN v1.0 Size: 56b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800657bc(void)
{
  if (((DAT_803ddbce == '\0') && (DAT_803ddbcf == '\0')) && (DAT_803ddbcd == '\0')) {
    return 0;
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_800657f4
 * EN v1.0 Address: 0x800657F4
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800657f4(void)
{
  DAT_803ddbce = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80065800
 * EN v1.0 Address: 0x80065800
 * EN v1.0 Size: 228b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80065800(undefined8 param_1,double param_2,double param_3,undefined4 param_4,float *param_5,
            uint param_6)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800658e4
 * EN v1.0 Address: 0x800658E4
 * EN v1.0 Size: 316b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800658e4(undefined8 param_1,double param_2,double param_3,undefined4 param_4,float *param_5,
            undefined4 *param_6,uint param_7)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80065a20
 * EN v1.0 Address: 0x80065A20
 * EN v1.0 Size: 260b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80065a20(undefined8 param_1,double param_2,double param_3,undefined4 param_4,float *param_5,
            uint param_6)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80065b24
 * EN v1.0 Address: 0x80065B24
 * EN v1.0 Size: 1192b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80065b24(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int *param_5,int param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80065fcc
 * EN v1.0 Address: 0x80065FCC
 * EN v1.0 Size: 632b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80065fcc(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,uint param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80066244
 * EN v1.0 Address: 0x80066244
 * EN v1.0 Size: 1076b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80066244(double param_1,double param_2,float *param_3,float *param_4,float *param_5,
            float *param_6,byte param_7)
{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  if (param_7 == 3) {
    *param_4 = *param_5;
    param_4[1] = param_5[1];
    param_4[2] = param_5[2];
    local_2c = *param_4 - *param_3;
    local_28 = param_4[1] - param_3[1];
    local_24 = param_4[2] - param_3[2];
    FUN_800228f0(&local_2c);
    fVar1 = (float)((double)(param_6[3] +
                            param_4[2] * param_6[2] + *param_4 * *param_6 + param_4[1] * param_6[1])
                   - param_2);
    fVar2 = (float)((double)(param_6[3] +
                            param_3[2] * param_6[2] + *param_3 * *param_6 + param_3[1] * param_6[1])
                   - param_2);
    fVar3 = FLOAT_803df934;
    if (fVar2 != fVar1) {
      fVar3 = fVar2 / (fVar2 - fVar1);
    }
    fVar1 = param_3[1];
    fVar2 = param_3[2];
    *param_4 = (*param_4 - *param_3) * fVar3;
    param_4[1] = (param_4[1] - fVar1) * fVar3;
    param_4[2] = (param_4[2] - fVar2) * fVar3;
    *param_4 = *param_4 + *param_3;
    param_4[1] = param_4[1] + param_3[1];
    param_4[2] = param_4[2] + param_3[2];
    return 1;
  }
  if ((FLOAT_803df930 <= param_6[1]) || (param_6[1] <= FLOAT_803df96c)) {
    if ((param_7 != 8) && ((7 < param_7 || (param_7 != 5)))) {
      fVar1 = param_6[2];
      fVar2 = *param_6;
      dVar5 = (double)(float)(param_2 -
                             (double)(param_6[3] +
                                     param_4[2] * fVar1 + *param_4 * fVar2 + param_4[1] * param_6[1]
                                     ));
      if (dVar5 <= (double)FLOAT_803df934) {
        return 1;
      }
      FUN_80293900((double)(fVar2 * fVar2 + fVar1 * fVar1));
      FUN_80292d24();
      dVar4 = (double)FUN_802947f8();
      param_4[1] = param_4[1] + (float)(dVar5 / dVar4);
      return 1;
    }
    *param_4 = -(float)(param_1 * (double)*param_6 - (double)*param_4);
    param_4[1] = -(float)(param_1 * (double)param_6[1] - (double)param_4[1]);
    param_4[2] = -(float)(param_1 * (double)param_6[2] - (double)param_4[2]);
    fVar1 = (float)(param_2 -
                   (double)(param_6[3] +
                           param_4[2] * param_6[2] + *param_4 * *param_6 + param_4[1] * param_6[1]))
    ;
    *param_4 = fVar1 * *param_6 + *param_4;
    param_4[1] = fVar1 * param_6[1] + param_4[1];
    param_4[2] = fVar1 * param_6[2] + param_4[2];
    return 1;
  }
  if (param_7 == 8) {
LAB_800663f8:
    fVar1 = param_6[2];
    fVar2 = *param_6;
    dVar5 = (double)(float)(param_2 -
                           (double)(param_6[3] +
                                   param_4[2] * fVar1 + *param_4 * fVar2 + param_4[1] * param_6[1]))
    ;
    if ((double)FLOAT_803df934 < dVar5) {
      FUN_80293900((double)(fVar2 * fVar2 + fVar1 * fVar1));
      FUN_80292d24();
      dVar4 = (double)FUN_80294b54();
      if ((double)FLOAT_803df934 != dVar4) {
        dVar5 = (double)(float)(dVar5 / dVar4);
      }
      local_38 = *param_6;
      local_34 = FLOAT_803df934;
      local_30 = param_6[2];
      FUN_800228f0(&local_38);
      *param_4 = (float)(dVar5 * (double)local_38 + (double)*param_4);
      param_4[2] = (float)(dVar5 * (double)local_30 + (double)param_4[2]);
    }
  }
  else {
    if (param_7 < 8) {
      if (param_7 == 1) goto LAB_800663f8;
    }
    else if (param_7 == 10) goto LAB_800663f8;
    *param_4 = -(float)(param_1 * (double)*param_6 - (double)*param_4);
    param_4[1] = -(float)(param_1 * (double)param_6[1] - (double)param_4[1]);
    param_4[2] = -(float)(param_1 * (double)param_6[2] - (double)param_4[2]);
    fVar1 = (float)(param_2 -
                   (double)(param_6[3] +
                           param_4[2] * param_6[2] + *param_4 * *param_6 + param_4[1] * param_6[1]))
    ;
    *param_4 = fVar1 * *param_6 + *param_4;
    param_4[1] = fVar1 * param_6[1] + param_4[1];
    param_4[2] = fVar1 * param_6[2] + param_4[2];
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80066678
 * EN v1.0 Address: 0x80066678
 * EN v1.0 Size: 752b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80066678(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4,float *param_5
                 ,float *param_6)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float *pfVar4;
  float *pfVar5;
  double extraout_f1;
  double dVar6;
  double dVar7;
  double dVar8;
  double in_f29;
  double dVar9;
  double in_f30;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
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
  uVar11 = FUN_8028683c();
  pfVar4 = (float *)((ulonglong)uVar11 >> 0x20);
  pfVar5 = (float *)uVar11;
  dVar7 = extraout_f1;
  FUN_80022974(param_3,pfVar4 + 6,&local_54);
  dVar6 = (double)FUN_800228f0(&local_54);
  if ((double)FLOAT_803df934 != dVar6) {
    local_60 = *pfVar5 - *pfVar4;
    local_5c = pfVar5[1] - pfVar4[1];
    local_58 = pfVar5[2] - pfVar4[2];
    fVar1 = local_4c * local_58 + local_54 * local_60 + local_50 * local_5c;
    dVar9 = (double)(fVar1 * fVar1);
    if (dVar9 <= (double)pfVar4[10]) {
      FUN_80022974(&local_60,pfVar4 + 6,&local_6c);
      dVar10 = (double)(float)(-(double)(local_64 * local_4c +
                                        local_6c * local_54 + local_68 * local_50) / dVar6);
      FUN_80022974(&local_54,pfVar4 + 6,&local_6c);
      FUN_800228f0(&local_6c);
      dVar6 = FUN_80293900((double)(float)((double)pfVar4[10] - dVar9));
      dVar6 = (double)(float)(dVar6 / (double)(param_3[2] * local_64 +
                                              (float)((double)*param_3 * (double)local_6c +
                                                     (double)(param_3[1] * local_68))));
      if (dVar6 < (double)FLOAT_803df934) {
        dVar6 = -dVar6;
      }
      dVar6 = (double)(float)(dVar10 - dVar6);
      if (((double)FLOAT_803df934 <= dVar6) && (dVar6 <= dVar7)) {
        fVar1 = *pfVar5 + (float)((double)*param_3 * dVar6);
        fVar2 = pfVar5[1] + (float)((double)param_3[1] * dVar6);
        fVar3 = pfVar5[2] + (float)((double)param_3[2] * dVar6);
        dVar7 = (double)pfVar4[7];
        dVar9 = (double)pfVar4[6];
        dVar10 = (double)pfVar4[8];
        dVar8 = (double)((float)((double)fVar3 * dVar10 +
                                (double)(float)((double)fVar1 * dVar9 +
                                               (double)(float)((double)fVar2 * dVar7))) -
                        (float)(dVar10 * (double)pfVar4[2] +
                               (double)(float)(dVar9 * (double)*pfVar4 +
                                              (double)(float)(dVar7 * (double)pfVar4[1]))));
        if (((double)FLOAT_803df934 <= dVar8) && (dVar8 <= (double)pfVar4[0xb])) {
          local_6c = (float)((double)*pfVar4 + (double)(float)(dVar9 * dVar8));
          local_68 = (float)((double)pfVar4[1] + (double)(float)(dVar7 * dVar8));
          local_64 = (float)((double)pfVar4[2] + (double)(float)(dVar10 * dVar8));
          *param_5 = (float)((double)fVar1 - (double)local_6c);
          param_5[1] = (float)((double)fVar2 - (double)local_68);
          param_5[2] = (float)((double)fVar3 - (double)local_64);
          FUN_800228f0(param_5);
          param_5[3] = pfVar4[9] - (fVar3 * param_5[2] + fVar1 * *param_5 + fVar2 * param_5[1]);
          *param_4 = fVar1;
          param_4[1] = fVar2;
          param_4[2] = fVar3;
          *param_6 = (float)dVar6;
        }
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80066968
 * EN v1.0 Address: 0x80066968
 * EN v1.0 Size: 4460b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80066968(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80067ad4
 * EN v1.0 Address: 0x80067AD4
 * EN v1.0 Size: 556b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80067ad4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80067d00
 * EN v1.0 Address: 0x80067D00
 * EN v1.0 Size: 2632b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80067d00(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,double param_7,undefined4 param_8,undefined4 param_9,int *param_10,
                 uint param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80068748
 * EN v1.0 Address: 0x80068748
 * EN v1.0 Size: 3060b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80068748(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5,
                 int param_6,int param_7,uint param_8,char param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8006933c
 * EN v1.0 Address: 0x8006933C
 * EN v1.0 Size: 1116b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006933c(undefined4 param_1,undefined4 param_2,uint param_3,char param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80069798
 * EN v1.0 Address: 0x80069798
 * EN v1.0 Size: 808b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80069798(uint *param_1,float *param_2,float *param_3,float *param_4,int param_5)
{
  double dVar1;
  undefined8 local_8;
  
  *param_1 = 1000000;
  param_1[3] = 0xfff0bdc0;
  param_1[1] = 1000000;
  param_1[4] = 0xfff0bdc0;
  param_1[2] = 1000000;
  param_1[5] = 0xfff0bdc0;
  dVar1 = DOUBLE_803df958;
  if (param_5 != 0) {
    do {
      local_8 = (double)CONCAT44(0x43300000,*param_1 ^ 0x80000000);
      if (*param_2 - *param_4 < (float)(local_8 - dVar1)) {
        *param_1 = (int)(*param_2 - *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[3] ^ 0x80000000);
      if ((float)(local_8 - dVar1) < *param_2 + *param_4) {
        param_1[3] = (int)(*param_2 + *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[1] ^ 0x80000000);
      if (param_2[1] - *param_4 < (float)(local_8 - dVar1)) {
        param_1[1] = (int)(param_2[1] - *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[4] ^ 0x80000000);
      if ((float)(local_8 - dVar1) < param_2[1] + *param_4) {
        param_1[4] = (int)(param_2[1] + *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[2] ^ 0x80000000);
      if (param_2[2] - *param_4 < (float)(local_8 - dVar1)) {
        param_1[2] = (int)(param_2[2] - *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[5] ^ 0x80000000);
      if ((float)(local_8 - dVar1) < param_2[2] + *param_4) {
        param_1[5] = (int)(param_2[2] + *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,*param_1 ^ 0x80000000);
      if (*param_3 - *param_4 < (float)(local_8 - dVar1)) {
        *param_1 = (int)(*param_3 - *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[3] ^ 0x80000000);
      if ((float)(local_8 - dVar1) < *param_3 + *param_4) {
        param_1[3] = (int)(*param_3 + *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[1] ^ 0x80000000);
      if (param_3[1] - *param_4 < (float)(local_8 - dVar1)) {
        param_1[1] = (int)(param_3[1] - *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[4] ^ 0x80000000);
      if ((float)(local_8 - dVar1) < param_3[1] + *param_4) {
        param_1[4] = (int)(param_3[1] + *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[2] ^ 0x80000000);
      if (param_3[2] - *param_4 < (float)(local_8 - dVar1)) {
        param_1[2] = (int)(param_3[2] - *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[5] ^ 0x80000000);
      if ((float)(local_8 - dVar1) < param_3[2] + *param_4) {
        param_1[5] = (int)(param_3[2] + *param_4);
      }
      param_2 = param_2 + 3;
      param_3 = param_3 + 3;
      param_4 = param_4 + 1;
      param_5 = param_5 + -1;
    } while (param_5 != 0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80069ac0
 * EN v1.0 Address: 0x80069AC0
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 * FUN_80069ac0(uint *param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80069ad4
 * EN v1.0 Address: 0x80069AD4
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80069ad4(undefined4 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80069ae4
 * EN v1.0 Address: 0x80069AE4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80069ae4(int *param_1,undefined4 *param_2)
{
  *param_1 = (int)(short)(&DAT_8038e8c8)[(uint)DAT_803ddbec * 0xc];
  *param_2 = DAT_803ddbb0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80069b0c
 * EN v1.0 Address: 0x80069B0C
 * EN v1.0 Size: 396b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80069b0c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80069c98
 * EN v1.0 Address: 0x80069C98
 * EN v1.0 Size: 924b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80069c98(undefined4 param_1,undefined4 param_2,int param_3)
{
  char cVar1;
  ushort uVar2;
  ushort uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  uint uVar15;
  uint uVar16;
  double extraout_f1;
  undefined8 uVar17;
  
  uVar17 = FUN_80286834();
  iVar10 = (int)((ulonglong)uVar17 >> 0x20);
  iVar11 = (int)uVar17;
  if ((((((iVar10 != 0) && (iVar11 != 0)) && (param_3 != 0)) &&
       ((cVar1 = *(char *)(iVar10 + 0x16), cVar1 == '\x04' || (cVar1 == '\x06')))) &&
      ((*(char *)(iVar11 + 0x16) == cVar1 &&
       ((*(char *)(param_3 + 0x16) == cVar1 && (*(short *)(iVar10 + 10) == *(short *)(iVar11 + 10)))
       )))) && ((*(short *)(iVar10 + 0xc) == *(short *)(iVar11 + 0xc) &&
                ((*(short *)(iVar10 + 10) == *(short *)(param_3 + 10) &&
                 (*(short *)(iVar10 + 0xc) == *(short *)(param_3 + 0xc))))))) {
    uVar7 = (int)((double)FLOAT_803df988 * extraout_f1) & 0xff;
    uVar8 = 0xff - uVar7 & 0xff;
    if (cVar1 == '\x04') {
      for (uVar15 = 0; (int)uVar15 < (int)(uint)*(ushort *)(iVar10 + 0xc); uVar15 = uVar15 + 1) {
        iVar5 = (uVar15 & 3) * 8;
        for (uVar16 = 0; (int)uVar16 < (int)(uint)*(ushort *)(iVar10 + 10); uVar16 = uVar16 + 1) {
          iVar6 = (uVar16 & 3) * 2;
          iVar4 = ((int)uVar16 >> 2) * 0x20;
          iVar12 = (uint)*(ushort *)(iVar10 + 10) * (uVar15 & 0xfffffffc) * 2;
          uVar2 = *(ushort *)(iVar10 + iVar6 + iVar4 + iVar5 + iVar12 + 0x60);
          uVar3 = *(ushort *)(iVar11 + iVar6 + iVar4 + iVar5 + iVar12 + 0x60);
          *(ushort *)(param_3 + iVar6 + iVar4 + iVar5 + iVar12 + 0x60) =
               (ushort)((int)(((int)(uVar7 * ((uVar2 & 0x1f) << 3 | (int)(uVar2 & 0x1c) >> 2)) >> 8)
                              + ((int)(uVar8 * ((uVar3 & 0x1f) << 3 | (int)(uVar3 & 0x1c) >> 2)) >>
                                8) & 0xf8U) >> 3) |
               (ushort)((((int)(((int)(uVar2 & 0xf800) >> 8 | (int)(uVar2 & 0xe000) >> 0xd) * uVar7)
                         >> 8) + ((int)(((int)(uVar3 & 0xf800) >> 8 | (int)(uVar3 & 0xe000) >> 0xd)
                                       * uVar8) >> 8) & 0xf8U) << 8) |
               (ushort)((((int)(uVar7 * ((int)(uVar2 & 0x7e0) >> 3 | (int)(uVar2 & 0x600) >> 9)) >>
                         8) + ((int)(uVar8 * ((int)(uVar3 & 0x7e0) >> 3 | (int)(uVar3 & 0x600) >> 9)
                                    ) >> 8) & 0xfcU) << 3);
        }
      }
    }
    else {
      for (uVar15 = 0; (int)uVar15 < (int)(uint)*(ushort *)(iVar10 + 0xc); uVar15 = uVar15 + 1) {
        iVar5 = ((int)uVar15 >> 2) * 8;
        iVar4 = (uVar15 & 3) * 8;
        for (uVar16 = 0; (int)uVar16 < (int)(uint)*(ushort *)(iVar10 + 10); uVar16 = uVar16 + 1) {
          iVar9 = (uVar16 & 3) * 2;
          iVar12 = ((int)uVar16 >> 2) * 0x40;
          iVar6 = (uint)*(ushort *)(iVar10 + 10) * iVar5 * 2;
          iVar13 = iVar10 + iVar9 + iVar12 + iVar4 + iVar6;
          iVar14 = iVar11 + iVar9 + iVar12 + iVar4 + iVar6;
          uVar2 = *(ushort *)(iVar13 + 0x80);
          uVar3 = *(ushort *)(iVar14 + 0x80);
          iVar12 = param_3 + iVar9 + iVar12 + iVar4 + 0x60;
          *(ushort *)(iVar12 + iVar6) =
               (short)((*(ushort *)(iVar13 + 0x60) & 0xff) * uVar7 >> 8) +
               (short)((*(ushort *)(iVar14 + 0x60) & 0xff) * uVar8 >> 8) & 0xff;
          *(ushort *)(iVar12 + (uint)*(ushort *)(iVar10 + 10) * iVar5 * 2 + 0x20) =
               (ushort)((((int)(((int)(uVar2 & 0xff00) >> 8) * uVar7) >> 8) +
                         ((int)(((int)(uVar3 & 0xff00) >> 8) * uVar8) >> 8) & 0xffU) << 8) |
               (short)(uVar7 * (uVar2 & 0xff) >> 8) + (short)(uVar8 * (uVar3 & 0xff) >> 8) & 0xffU;
        }
      }
    }
    FUN_80242114(param_3 + 0x60,*(int *)(param_3 + 0x44));
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006a034
 * EN v1.0 Address: 0x8006A034
 * EN v1.0 Size: 368b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006a034(int param_1)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  
  uVar4 = FUN_80022b0c();
  uVar8 = 0;
  do {
    uVar6 = 0;
    iVar1 = (uVar8 >> 2) * 0x100;
    iVar2 = (uVar8 & 3) * 8;
    uVar5 = (uVar8 + param_1) * 0xff;
    iVar9 = 0x10;
    do {
      uVar3 = uVar5;
      if (0x3fc0 < uVar5) {
        uVar3 = 0x3fc0;
      }
      *(char *)(uVar4 + (uVar6 & 7) + (uVar6 >> 3) * 0x20 + iVar2 + iVar1) =
           (char)(uVar3 * uVar6 >> 0xc);
      uVar7 = uVar6 + 1;
      uVar3 = uVar5;
      if (0x3fc0 < uVar5) {
        uVar3 = 0x3fc0;
      }
      *(char *)(uVar4 + (uVar7 & 7) + (uVar7 >> 3) * 0x20 + iVar2 + iVar1) =
           (char)(uVar3 * uVar7 >> 0xc);
      uVar7 = uVar6 + 2;
      uVar3 = uVar5;
      if (0x3fc0 < uVar5) {
        uVar3 = 0x3fc0;
      }
      *(char *)(uVar4 + (uVar7 & 7) + (uVar7 >> 3) * 0x20 + iVar2 + iVar1) =
           (char)(uVar3 * uVar7 >> 0xc);
      uVar7 = uVar6 + 3;
      uVar3 = uVar5;
      if (0x3fc0 < uVar5) {
        uVar3 = 0x3fc0;
      }
      *(char *)(uVar4 + (uVar7 & 7) + (uVar7 >> 3) * 0x20 + iVar2 + iVar1) =
           (char)(uVar3 * uVar7 >> 0xc);
      uVar6 = uVar6 + 4;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    uVar8 = uVar8 + 1;
  } while (uVar8 < 0x40);
  FUN_80022a0c(DAT_803ddc38 + 0x60,uVar4,0);
  DAT_803ddc00 = (char)param_1;
  return;
}
