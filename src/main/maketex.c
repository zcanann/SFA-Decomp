#include "ghidra_import.h"
#include "main/maketex.h"

extern int FUN_800033a8();
extern undefined4 FUN_80003494();
extern undefined8 FUN_80006868();
extern char FUN_80006884();
extern undefined4 FUN_8000689c();
extern undefined4 FUN_80006b58();
extern undefined4 FUN_80006c1c();
extern undefined8 FUN_80006c30();
extern undefined8 FUN_80006c84();
extern undefined4 FUN_80017434();
extern undefined8 FUN_80017484();
extern int FUN_800174a0();
extern undefined4 FUN_800174b8();
extern undefined4 FUN_800174e8();
extern undefined4 FUN_800174f0();
extern undefined4 FUN_800174f4();
extern uint FUN_80017658();
extern int FUN_80017730();
extern uint FUN_80017760();
extern undefined4 FUN_80017810();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017830();
extern int FUN_80017a98();
extern undefined4 FUN_8002f6ac();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern int Obj_GetYawDeltaToObject();
extern int FUN_8003964c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80045c4c();
extern undefined4 FUN_8004600c();
extern int newshadows_getShadowRenderTexture(void);
extern undefined4 FUN_800709dc();
extern undefined4 FUN_800709e4();
extern int FUN_8007284c();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_802420e0();
extern int FUN_80249300();
extern undefined4 FUN_802493c8();
extern int FUN_8026218c();
extern int FUN_80262b10();
extern undefined4 FUN_80262bf4();
extern int FUN_80263710();
extern undefined4 FUN_80263888();
extern int FUN_80263c34();
extern int FUN_802640ac();
extern int FUN_80264428();
extern undefined4 FUN_80264624();
extern int FUN_80264864();
extern int FUN_80264b04();
extern int FUN_80264b4c();
extern ulonglong FUN_80286830();
extern undefined8 FUN_80286834();
extern char FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_8028688c();
extern undefined8 FUN_8028fde8();
extern double FUN_80293900();
extern uint countLeadingZeros();

extern undefined4 DAT_8030f8b8;
extern undefined4 DAT_80397560;
extern undefined4 DAT_80397564;
extern undefined4 DAT_8039ae0c;
extern undefined4 DAT_8039b010;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc360;
extern undefined4 DAT_803dc364;
extern undefined4 DAT_803dc368;
extern undefined4 DAT_803dc374;
extern undefined4 DAT_803dc378;
extern undefined4 DAT_803dc37c;
extern undefined4 DAT_803dc380;
extern undefined4 DAT_803dc384;
extern undefined4 DAT_803dc388;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4 DAT_803ddcc0;
extern undefined4 DAT_803ddcc4;
extern undefined4 DAT_803ddcc8;
extern undefined4 DAT_803ddccc;
extern undefined4 DAT_803ddcd0;
extern undefined4 DAT_803ddcd4;
extern undefined4 DAT_803ddcd9;
extern undefined4 DAT_803ddcda;
extern undefined* DAT_803ddcdc;
extern undefined4 DAT_803ddd0c;
extern undefined4 DAT_803ddd14;
extern undefined4 DAT_803ddd64;
extern undefined4 DAT_803ddd66;
extern undefined4 DAT_803ddd68;
extern undefined4 DAT_803ddd78;
extern undefined4 DAT_803ddd7c;
extern f64 DOUBLE_803dfc28;
extern f64 DOUBLE_803dfc38;
extern f64 DOUBLE_803dfc60;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803ddcf4;
extern f32 FLOAT_803ddd60;
extern f32 FLOAT_803ddd6c;
extern f32 FLOAT_803ddd70;
extern f32 FLOAT_803ddd74;
extern f32 FLOAT_803dfc18;
extern f32 FLOAT_803dfc20;
extern f32 FLOAT_803dfc30;
extern f32 FLOAT_803dfc40;
extern f32 FLOAT_803dfc44;
extern f32 FLOAT_803dfc48;
extern f32 FLOAT_803dfc4c;
extern f32 FLOAT_803dfc50;
extern f32 FLOAT_803dfc54;
extern f32 FLOAT_803dfc58;
extern void* PTR_LAB_80310000;
extern char s_Dinosaur_Planet_8030f7b0[];
extern char s_STARFOX_ADVENTURES_8030f79c[];
extern char s_Star_Fox_Adventures_8030f678[];
extern char s_card_memcardicon0_img_8030f724[];
extern char s_card_memcardicon0_pal_8030f784[];
extern char s_card_memcardicon1_img_8030f73c[];
extern char s_card_memcardicon2_img_8030f754[];
extern char s_card_memcardicon3_img_8030f76c[];
extern char s_opening_bnr_8030f718[];

/*
 * --INFO--
 *
 * Function: FUN_8007e77c
 * EN v1.0 Address: 0x8007E77C
 * EN v1.0 Size: 672b
 * EN v1.1 Address: 0x8007E7A0
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007e77c(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  char cVar3;
  uint uVar1;
  undefined4 uVar2;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  undefined4 local_28;
  int local_24 [9];
  
  cVar3 = FUN_80286840();
  FUN_80017434(0);
  iVar5 = 0;
  do {
    FUN_80006c1c();
    FUN_80017810();
    FUN_8004600c();
    uVar1 = FUN_80017658(local_24);
    if ((uVar1 & 0xff) == 0) {
      local_28 = DAT_803dc368;
      uVar2 = newshadows_getShadowRenderTexture();
      FUN_800709e4(uVar2,0,0,&local_28,0x200,0);
    }
    else {
      (**(code **)(*DAT_803dd6cc + 4))(0,0,0);
      param_2 = (double)FLOAT_803dfc18;
      FUN_800709dc(param_2,param_2,0x280,0x1e0);
      iVar6 = 0;
      for (iVar4 = 0; iVar4 < (int)(uVar1 & 0xff); iVar4 = iVar4 + 1) {
        FUN_8003b818(*(int *)(local_24[0] + iVar6));
        iVar6 = iVar6 + 4;
      }
      FUN_80006b58();
    }
    uVar7 = FUN_80017484(0xff,0xff,0xff,0xff);
    if (cVar3 == '\x01') {
      uVar7 = FUN_80006c84(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x323,0,200
                          );
    }
    else if (cVar3 == '\x02') {
      uVar7 = FUN_80006c84(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x573,0,200
                          );
    }
    else {
      uVar7 = FUN_80006c84(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x56c,0,200
                          );
    }
    FUN_800174b8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80045c4c('\x01');
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x3c);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007ea1c
 * EN v1.0 Address: 0x8007EA1C
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x8007E928
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007ea1c(uint param_1,undefined4 param_2,uint param_3,uint param_4)
{
  int iVar1;
  
  FUN_80003494(DAT_803ddcc4 + (param_1 & 0xff) * 0x6ec + 0xa50,param_3,0x6ec);
  FUN_80003494(DAT_803ddcc4 + 0x1f14,param_4,0xe4);
  iVar1 = FUN_8007eb04(2);
  if (iVar1 == 0) {
    FUN_8007eb04(1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007ea90
 * EN v1.0 Address: 0x8007EA90
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8007E99C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8007ea90(undefined4 param_1,undefined4 param_2,uint param_3)
{
  FUN_80003494(param_3,DAT_803ddcc4 + 0x1f14,0xe4);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8007eac4
 * EN v1.0 Address: 0x8007EAC4
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x8007E9D0
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8007eac4(uint param_1,undefined4 param_2,uint param_3)
{
  FUN_80003494(param_3,DAT_803ddcc4 + (param_1 & 0xff) * 0x6ec + 0xa50,0x6ec);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8007eb04
 * EN v1.0 Address: 0x8007EB04
 * EN v1.0 Size: 1288b
 * EN v1.1 Address: 0x8007EA14
 * EN v1.1 Size: 900b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8007eb04(uint param_1)
{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  ushort uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  int iVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint *puVar23;
  uint uVar24;
  bool bVar25;
  
  uVar7 = DAT_803ddcc4;
  uVar2 = 0;
  uVar1 = 0;
  uVar6 = 1;
  iVar13 = 0;
  for (uVar4 = 0; uVar4 < 0x3f7; uVar4 = uVar4 + 8) {
    puVar23 = (uint *)(DAT_803ddcc4 + (uint)uVar4 * 8);
    uVar12 = puVar23[1];
    bVar25 = CARRY4(uVar6,uVar12);
    uVar3 = uVar6 + uVar12;
    uVar15 = puVar23[3];
    uVar5 = uVar3 + uVar15;
    uVar16 = puVar23[5];
    uVar24 = uVar5 + uVar16;
    uVar17 = puVar23[7];
    uVar8 = uVar24 + uVar17;
    uVar18 = puVar23[9];
    uVar9 = uVar8 + uVar18;
    uVar19 = puVar23[0xb];
    uVar10 = uVar9 + uVar19;
    uVar20 = puVar23[0xd];
    uVar11 = uVar10 + uVar20;
    uVar21 = puVar23[0xf];
    uVar2 = uVar2 ^ uVar12 ^ uVar15 ^ uVar16 ^ uVar17 ^ uVar18 ^ uVar19 ^ uVar20 ^ uVar21;
    uVar1 = uVar1 ^ *puVar23 ^ puVar23[2] ^ puVar23[4] ^ puVar23[6] ^ puVar23[8] ^ puVar23[10] ^
            puVar23[0xc] ^ puVar23[0xe];
    uVar6 = uVar11 + uVar21;
    iVar13 = iVar13 + *puVar23 + (uint)bVar25 + puVar23[2] + (uint)CARRY4(uVar3,uVar15) +
             puVar23[4] + (uint)CARRY4(uVar5,uVar16) + puVar23[6] + (uint)CARRY4(uVar24,uVar17) +
             puVar23[8] + (uint)CARRY4(uVar8,uVar18) + puVar23[10] + (uint)CARRY4(uVar9,uVar19) +
             puVar23[0xc] + (uint)CARRY4(uVar10,uVar20) + puVar23[0xe] + (uint)CARRY4(uVar11,uVar21)
    ;
  }
  for (; uVar4 < 0x3ff; uVar4 = uVar4 + 1) {
    puVar23 = (uint *)(DAT_803ddcc4 + (uint)uVar4 * 8);
    uVar3 = *puVar23;
    uVar5 = puVar23[1];
    uVar2 = uVar2 ^ uVar5;
    uVar1 = uVar1 ^ uVar3;
    bVar25 = CARRY4(uVar6,uVar5);
    uVar6 = uVar6 + uVar5;
    iVar13 = iVar13 + uVar3 + bVar25;
  }
  uVar2 = uVar2 ^ uVar6 + 0xd;
  uVar1 = uVar1 ^ iVar13 + (uint)(0xfffffff2 < uVar6);
  *(uint *)(DAT_803ddcc4 + 0x1ffc) = uVar2;
  *(uint *)(uVar7 + 0x1ff8) = uVar1;
  FUN_802420e0(DAT_803ddcc4,0x2000);
  uVar7 = (param_1 & 0xff) << 0xd;
  iVar13 = FUN_80264428((int *)&DAT_80397560,DAT_803ddcc4,0x2000,uVar7);
  if (iVar13 == -5) {
    FUN_80264624(0,DAT_803dc364);
  }
  uVar6 = DAT_803ddcd0;
  uVar3 = DAT_803ddcd4;
  if (iVar13 == 0) {
    FUN_802420b0(DAT_803ddcc4,0x2000);
    iVar13 = FUN_802640ac((int *)&DAT_80397560,DAT_803ddcc4,0x2000,uVar7);
    uVar6 = DAT_803ddcd0;
    uVar3 = DAT_803ddcd4;
    if (iVar13 == 0) {
      uVar3 = 0;
      uVar6 = 0;
      uVar7 = 1;
      iVar14 = 0;
      for (uVar4 = 0; uVar4 < 0x3f7; uVar4 = uVar4 + 8) {
        puVar23 = (uint *)(DAT_803ddcc4 + (uint)uVar4 * 8);
        uVar15 = puVar23[1];
        bVar25 = CARRY4(uVar7,uVar15);
        uVar5 = uVar7 + uVar15;
        uVar16 = puVar23[3];
        uVar24 = uVar5 + uVar16;
        uVar17 = puVar23[5];
        uVar8 = uVar24 + uVar17;
        uVar18 = puVar23[7];
        uVar9 = uVar8 + uVar18;
        uVar19 = puVar23[9];
        uVar10 = uVar9 + uVar19;
        uVar20 = puVar23[0xb];
        uVar11 = uVar10 + uVar20;
        uVar21 = puVar23[0xd];
        uVar12 = uVar11 + uVar21;
        uVar22 = puVar23[0xf];
        uVar3 = uVar3 ^ uVar15 ^ uVar16 ^ uVar17 ^ uVar18 ^ uVar19 ^ uVar20 ^ uVar21 ^ uVar22;
        uVar6 = uVar6 ^ *puVar23 ^ puVar23[2] ^ puVar23[4] ^ puVar23[6] ^ puVar23[8] ^ puVar23[10] ^
                puVar23[0xc] ^ puVar23[0xe];
        uVar7 = uVar12 + uVar22;
        iVar14 = iVar14 + *puVar23 + (uint)bVar25 + puVar23[2] + (uint)CARRY4(uVar5,uVar16) +
                 puVar23[4] + (uint)CARRY4(uVar24,uVar17) + puVar23[6] + (uint)CARRY4(uVar8,uVar18)
                 + puVar23[8] + (uint)CARRY4(uVar9,uVar19) +
                 puVar23[10] + (uint)CARRY4(uVar10,uVar20) +
                 puVar23[0xc] + (uint)CARRY4(uVar11,uVar21) +
                 puVar23[0xe] + (uint)CARRY4(uVar12,uVar22);
      }
      for (; uVar4 < 0x3ff; uVar4 = uVar4 + 1) {
        puVar23 = (uint *)(DAT_803ddcc4 + (uint)uVar4 * 8);
        uVar5 = *puVar23;
        uVar24 = puVar23[1];
        uVar3 = uVar3 ^ uVar24;
        uVar6 = uVar6 ^ uVar5;
        bVar25 = CARRY4(uVar7,uVar24);
        uVar7 = uVar7 + uVar24;
        iVar14 = iVar14 + uVar5 + bVar25;
      }
      uVar3 = uVar3 ^ uVar7 + 0xd;
      uVar6 = uVar6 ^ iVar14 + (uint)(0xfffffff2 < uVar7);
      if (uVar2 != uVar3 || uVar1 != uVar6) {
        iVar13 = -0x55;
        DAT_803dc360 = 10;
        uVar6 = DAT_803ddcd0;
        uVar3 = DAT_803ddcd4;
      }
    }
  }
  DAT_803ddcd4 = uVar3;
  DAT_803ddcd0 = uVar6;
  return iVar13;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f00c
 * EN v1.0 Address: 0x8007F00C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8007ED98
 * EN v1.1 Size: 1956b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007f00c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined *param_14,uint param_15,uint param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007f010
 * EN v1.0 Address: 0x8007F010
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8007F53C
 * EN v1.1 Size: 988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007f010(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8007f014
 * EN v1.0 Address: 0x8007F014
 * EN v1.0 Size: 828b
 * EN v1.1 Address: 0x8007F918
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007f014(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined *puVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = FUN_800174a0();
  if (iVar2 == 4) {
    *DAT_803ddcdc = 0x83;
    DAT_803ddcdc[1] = 0x58;
    DAT_803ddcdc[2] = 0x83;
    DAT_803ddcdc[3] = 0x5e;
    DAT_803ddcdc[4] = 0x81;
    DAT_803ddcdc[5] = 0x5b;
    DAT_803ddcdc[6] = 0x83;
    DAT_803ddcdc[7] = 0x74;
    DAT_803ddcdc[8] = 0x83;
    DAT_803ddcdc[9] = 0x48;
    DAT_803ddcdc[10] = 0x83;
    DAT_803ddcdc[0xb] = 0x62;
    DAT_803ddcdc[0xc] = 0x83;
    DAT_803ddcdc[0xd] = 0x4e;
    DAT_803ddcdc[0xe] = 0x83;
    DAT_803ddcdc[0xf] = 0x58;
    DAT_803ddcdc[0x10] = 0x83;
    DAT_803ddcdc[0x11] = 0x41;
    DAT_803ddcdc[0x12] = 0x83;
    DAT_803ddcdc[0x13] = 0x68;
    DAT_803ddcdc[0x14] = 0x83;
    DAT_803ddcdc[0x15] = 0x78;
    DAT_803ddcdc[0x16] = 0x83;
    DAT_803ddcdc[0x17] = 0x93;
    DAT_803ddcdc[0x18] = 0x83;
    DAT_803ddcdc[0x19] = 0x60;
    DAT_803ddcdc[0x1a] = 0x83;
    puVar1 = DAT_803ddcdc;
    DAT_803ddcdc[0x1b] = 0x83;
    DAT_803ddcdc[0x1c] = 0x81;
    DAT_803ddcdc[0x1d] = 0x5b;
    DAT_803ddcdc[0x1e] = 0;
    DAT_803ddcdc[0x1f] = 0;
    FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)(DAT_803ddcdc + 0x20),s_STARFOX_ADVENTURES_8030f79c,puVar1,0x60,0x58,param_14,
                 param_15,param_16);
  }
  else {
    uVar3 = FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)DAT_803ddcdc,s_Star_Fox_Adventures_8030f678,param_11,param_12,param_13
                         ,param_14,param_15,param_16);
    FUN_8028fde8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)(DAT_803ddcdc + 0x20),s_Dinosaur_Planet_8030f7b0,param_11,param_12,param_13,
                 param_14,param_15,param_16);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f350
 * EN v1.0 Address: 0x8007F350
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8007FAC8
 * EN v1.1 Size: 1480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8007f350(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,char param_9
            ,undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f358
 * EN v1.0 Address: 0x8007F358
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80080090
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8007f358(int *param_1,int *param_2,int param_3)
{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  iVar4 = *param_2;
  iVar2 = 0;
  piVar3 = param_1;
  iVar5 = iVar4;
  if (0 < iVar4) {
    do {
      iVar1 = *piVar3;
      piVar3 = piVar3 + 1;
      if (iVar1 == param_3) goto LAB_800800c8;
      iVar2 = iVar2 + 1;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  iVar2 = -1;
LAB_800800c8:
  if (iVar2 != -1) {
    param_1[iVar2] = param_1[iVar4 + -1];
    *param_2 = *param_2 + -1;
    return iVar2;
  }
  return -1;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f3c8
 * EN v1.0 Address: 0x8007F3C8
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80080100
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8007f3c8(int *param_1,int param_2,int param_3)
{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  if (0 < param_2) {
    do {
      iVar1 = *param_1;
      param_1 = param_1 + 1;
      if (iVar1 == param_3) {
        return iVar2;
      }
      iVar2 = iVar2 + 1;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return -1;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f400
 * EN v1.0 Address: 0x8007F400
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x80080138
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007f400(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  int *piVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  uint uVar12;
  
  iVar1 = (param_2 + -1) / 9 + (param_2 + -1 >> 0x1f);
  for (iVar4 = 1; iVar4 <= iVar1 - (iVar1 >> 0x1f); iVar4 = iVar4 * 3 + 1) {
  }
  do {
    if (iVar4 < 1) {
      iVar4 = 1;
      if (1 < param_2) {
        if ((8 < param_2 + -1) && (uVar12 = param_2 - 2U >> 3, 1 < param_2 + -8)) {
          do {
            iVar4 = iVar4 + 8;
            uVar12 = uVar12 - 1;
          } while (uVar12 != 0);
        }
        iVar1 = param_2 - iVar4;
        if (iVar4 < param_2) {
          do {
            iVar1 = iVar1 + -1;
          } while (iVar1 != 0);
        }
      }
      return;
    }
    iVar10 = iVar4 + 1;
    iVar1 = iVar10 * 8;
    piVar8 = (int *)(param_1 + iVar1);
    iVar2 = param_2 - iVar10;
    if (iVar10 < param_2) {
      do {
        iVar5 = *piVar8;
        iVar6 = piVar8[1];
        piVar7 = (int *)(param_1 + iVar1);
        for (iVar9 = iVar10; iVar4 < iVar9; iVar9 = iVar9 - iVar4) {
          piVar11 = (int *)(param_1 + (iVar9 - iVar4) * 8);
          iVar3 = *piVar11;
          if (iVar3 <= iVar5) break;
          *piVar7 = iVar3;
          piVar7[1] = piVar11[1];
          piVar7 = piVar7 + iVar4 * -2;
        }
        piVar7 = (int *)(param_1 + iVar9 * 8);
        *piVar7 = iVar5;
        piVar7[1] = iVar6;
        piVar8 = piVar8 + 2;
        iVar10 = iVar10 + 1;
        iVar1 = iVar1 + 8;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    iVar4 = iVar4 / 3;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_8007f56c
 * EN v1.0 Address: 0x8007F56C
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x80080284
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8007f56c(int *param_1,int param_2,int param_3)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (0x10 < param_2) {
    iVar1 = 0;
    while( true ) {
      iVar3 = param_2 + iVar1 >> 1;
      iVar2 = iVar3;
      if ((param_3 <= param_1[iVar3 * 2]) &&
         (param_2 = iVar3, iVar2 = iVar1, param_3 == param_1[iVar3 * 2])) break;
      iVar1 = iVar2;
      if (iVar2 < param_2) {
        return 0;
      }
    }
    return param_1[iVar3 * 2 + 1];
  }
  if (param_2 != 0) {
    do {
      if (*param_1 == param_3) {
        return param_1[1];
      }
      param_1 = param_1 + 2;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f5ec
 * EN v1.0 Address: 0x8007F5EC
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x80080304
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007f5ec(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  for (iVar2 = 0; iVar2 < param_2; iVar2 = iVar2 + 1) {
    iVar3 = 0;
    if (0 < param_2) {
      if ((8 < param_2) && (uVar4 = param_2 - 1U >> 3, 0 < param_2 + -8)) {
        do {
          iVar3 = iVar3 + 8;
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
      }
      iVar1 = param_2 - iVar3;
      if (iVar3 < param_2) {
        do {
          iVar1 = iVar1 + -1;
        } while (iVar1 != 0);
      }
    }
  }
  if (0x10 < param_2) {
    FUN_8007f400(param_1,param_2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f66c
 * EN v1.0 Address: 0x8007F66C
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x8008038C
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8007f66c(int param_1)
{
  int iVar1;
  uint uVar2;
  
  iVar1 = (param_1 * 0x3c) / 0x3c + (param_1 * 0x3c >> 0x1f);
  uVar2 = FUN_80017760(0,iVar1 - (iVar1 >> 0x1f));
  uVar2 = countLeadingZeros(uVar2);
  return uVar2 >> 5;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f6c8
 * EN v1.0 Address: 0x8007F6C8
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x800803DC
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8007f6c8(float *param_1)
{
  return ((uint)(byte)((FLOAT_803dfc20 == *param_1) << 1) << 0x1c) >> 0x1d ^ 1;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f6e4
 * EN v1.0 Address: 0x8007F6E4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x800803F8
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007f6e4(undefined4 *param_1)
{
  *param_1 = FLOAT_803dfc20;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f718
 * EN v1.0 Address: 0x8007F718
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x80080404
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007f718(float *param_1,short param_2)
{
  *param_1 = (float)((double)CONCAT44(0x43300000,(int)param_2 ^ 0x80000000) - DOUBLE_803dfc28);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f764
 * EN v1.0 Address: 0x8007F764
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80080434
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8007f764(float *param_1)
{
  float fVar1;
  
  fVar1 = FLOAT_803dfc20;
  if (*param_1 != FLOAT_803dfc20) {
    *param_1 = *param_1 - FLOAT_803dc074;
    if (*param_1 <= fVar1) {
      *param_1 = fVar1;
      return 1;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f7a4
 * EN v1.0 Address: 0x8007F7A4
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80080474
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007f7a4(void)
{
  DAT_803dc374 = 0xffffffff;
  DAT_803dc37c = 0xffffffff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f7b4
 * EN v1.0 Address: 0x8007F7B4
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80080484
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007f7b4(void)
{
  DAT_803ddd0c = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f7c0
 * EN v1.0 Address: 0x8007F7C0
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80080490
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_8007f7c0(void)
{
  return DAT_803ddd0c;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f7cc
 * EN v1.0 Address: 0x8007F7CC
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x80080498
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007f7cc(double param_1,double param_2,double param_3,double param_4,undefined2 param_5,
                 undefined2 param_6,undefined2 param_7)
{
  DAT_803ddd78 = 1;
  FLOAT_803ddd74 = (float)param_1;
  FLOAT_803ddd70 = (float)param_2;
  FLOAT_803ddd6c = (float)param_3;
  DAT_803ddd68 = param_5;
  DAT_803ddd66 = param_6;
  DAT_803ddd64 = param_7;
  FLOAT_803ddd60 = (float)param_4;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f810
 * EN v1.0 Address: 0x8007F810
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800804C0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8007f810(void)
{
  return DAT_803ddd7c;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f818
 * EN v1.0 Address: 0x8007F818
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x800804C8
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8007f818(int param_1)
{
  int iVar1;
  char cVar3;
  undefined4 uVar2;
  
  iVar1 = (int)(short)(&DAT_8039b010)[param_1];
  if ((DAT_803ddd14 == 0) && (cVar3 = FUN_80006884(), cVar3 == '\0')) {
    FLOAT_803ddcf4 =
         (float)(&DAT_8039ae0c)[param_1] -
         (float)((double)CONCAT44(0x43300000,DAT_803dc388 ^ 0x80000000) - DOUBLE_803dfc38);
    if (FLOAT_803dfc30 != FLOAT_803ddcf4) {
      DAT_803dc384 = param_1;
    }
    DAT_803dc388 = 0xffffffff;
    if ((((iVar1 == 0x54c) || (iVar1 - 0x551U < 2)) || (iVar1 == 0x575)) ||
       ((iVar1 == 0x57a || (iVar1 == 0x57b)))) {
      FLOAT_803ddcf4 = FLOAT_803dfc30;
      DAT_803dc384 = -1;
    }
    DAT_803dc380 = 0xffffffff;
    FUN_8000689c();
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f924
 * EN v1.0 Address: 0x8007F924
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x800805CC
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8007f924(int param_1)
{
  return (short)(&DAT_8039b010)[*(char *)(param_1 + 0x57)] + -1;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f944
 * EN v1.0 Address: 0x8007F944
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x800805EC
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8007f944(int param_1,undefined2 param_2)
{
  *(undefined2 *)(&DAT_8030f8b8 + *(char *)(param_1 + 0x57) * 2) = param_2;
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_8007f960
 * EN v1.0 Address: 0x8007F960
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x80080610
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007f960(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined8 uVar1;
  
  FUN_80006884();
  uVar1 = FUN_80006868();
  if (DAT_803dc37c == 0xffffffff) {
    if (DAT_803dc378 != -1) {
      FUN_800174e8(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_800174f0(DAT_803dc378);
      DAT_803dc378 = -1;
    }
  }
  else {
    FUN_800174f4(uVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dc37c);
    DAT_803dc37c = 0xffffffff;
    DAT_803dc374 = 0xffffffff;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007fa8c
 * EN v1.0 Address: 0x8007FA8C
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x800806F8
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007fa8c(int param_1,int param_2)
{
  int iVar1;
  undefined4 *puVar2;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined local_c;
  
  iVar1 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if (iVar1 != 0x4d) {
    puVar2 = *(undefined4 **)(param_2 + 0x74);
    if (((puVar2 == (undefined4 *)0x0) || (param_1 == 7)) || (param_1 == 6)) {
      local_18 = *(undefined4 *)(param_2 + 0x18);
      local_14 = *(undefined4 *)(param_2 + 0x1c);
      local_10 = *(undefined4 *)(param_2 + 0x20);
    }
    else {
      local_18 = *puVar2;
      local_14 = puVar2[1];
      local_10 = puVar2[2];
    }
    local_c = (undefined)param_1;
    DAT_803ddd7c = param_2;
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x4d,1,0,0x10,&local_18,0,0xff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007fb48
 * EN v1.0 Address: 0x8007FB48
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x800807D4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007fb48(int param_1)
{
  undefined2 *puVar1;
  
  puVar1 = (undefined2 *)FUN_8003964c(param_1,0);
  if (puVar1 != (undefined2 *)0x0) {
    puVar1[1] = 0;
    *puVar1 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8007fb80
 * EN v1.0 Address: 0x8007FB80
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8008080C
 * EN v1.1 Size: 1564b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8007fb80(undefined4 param_1,undefined4 param_2,short param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
}

/* sda21 accessors. */
extern u8 lbl_803DD08C;
extern u32 lbl_803DD0FC;
extern s16 lbl_803DD06E;
extern s16 lbl_803DD06C;
extern u8 lbl_803DD080;
u8 fn_80080204(void) { return lbl_803DD08C; }
u32 fn_80080234(void) { return lbl_803DD0FC; }
void fn_80080B9C(s16 x) { lbl_803DD06E = x; }
s16 fn_80080BA4(void) { return lbl_803DD06E; }
void fn_80080BAC(s16 x) { lbl_803DD06C = x; }
s16 fn_80080BB4(void) { return lbl_803DD06C; }
void fn_80080BBC(u8 x) { lbl_803DD080 = x; }
u8 fn_80080BC4(void) { return lbl_803DD080; }

/* Pattern wrappers. */
extern u32 lbl_803DB700;
void fn_8007FDF8(void) { lbl_803DB700 = 0x3; }

/* lbl = N (byte) */
void fn_800801F8(void) { lbl_803DD08C = 0x0; }

extern f32 lbl_803DEFA0;
void fn_8008016C(f32 *p) { *p = lbl_803DEFA0; }
