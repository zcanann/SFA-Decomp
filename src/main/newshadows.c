#include "ghidra_import.h"
#include "main/newshadows.h"

extern float ABS();
extern undefined4 FUN_800033a8();
extern undefined4 FUN_80003494();
extern undefined4 FUN_8000693c();
extern undefined4 FUN_8000694c();
extern undefined4 FUN_80006954();
extern undefined4 FUN_80006974();
extern void* FUN_8000697c();
extern undefined4 FUN_80006984();
extern undefined4 FUN_80006988();
extern void* FUN_800069a8();
extern undefined4 FUN_800069b8();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_800069d4();
extern undefined4 FUN_800069f4();
extern double FUN_800069f8();
extern undefined4 FUN_80006a00();
extern int FUN_800176d0();
extern uint FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern uint FUN_800177bc();
extern undefined4 FUN_80017814();
extern int FUN_80017970();
extern undefined4 FUN_80017a50();
extern int FUN_80017a54();
extern undefined4 FUN_8003b7dc();
extern undefined4 FUN_8003b878();
extern undefined4 FUN_80040cd0();
extern undefined4 FUN_80045be8();
extern undefined4 FUN_80048048();
extern char FUN_80048094();
extern int FUN_800537a0();
extern undefined4 FUN_8005398c();
extern uint FUN_8005d00c();
extern uint FUN_8005d06c();
extern undefined4 FUN_800606a4();
extern undefined4 FUN_800606a8();
extern undefined4 FUN_80060710();
extern ushort FUN_80061198();
extern undefined4 FUN_80064384();
extern undefined4 FUN_8006ef38();
extern undefined4 FUN_8006f788();
extern undefined4 FUN_8006f790();
extern undefined4 FUN_8006f8fc();
extern undefined4 FUN_800709e8();
extern undefined4 FUN_80080f6c();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_802475e4();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247b70();
extern undefined4 FUN_80247dfc();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double FUN_80247f54();
extern double FUN_80247f90();
extern undefined4 FUN_80258c24();
extern undefined4 FUN_80258c48();
extern undefined4 FUN_80259400();
extern undefined4 FUN_80259504();
extern undefined4 FUN_80259858();
extern undefined4 FUN_80259c0c();
extern undefined4 FUN_8025aeac();
extern undefined4 FUN_8025b054();
extern undefined4 FUN_8025b210();
extern undefined4 FUN_8025b280();
extern undefined4 FUN_8025d6ac();
extern undefined4 FUN_8025da64();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_8028680c();
extern undefined4 FUN_80286820();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286858();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802947f8();
extern undefined4 FUN_802949e8();
extern undefined4 SQRT();

extern undefined2 DAT_8030f470;
extern undefined2 DAT_8030f484;
extern undefined2 DAT_8030f498;
extern undefined2 DAT_8030f4ac;
extern undefined2 DAT_8030f4c0;
extern undefined2 DAT_8030f4d4;
extern undefined2 DAT_8030f4e8;
extern undefined2 DAT_8030f4fc;
extern undefined2 DAT_8030f510;
extern undefined4 DAT_8030f524;
extern undefined DAT_8038eba8;
extern undefined4 DAT_8038ebb8;
extern undefined4 DAT_8038ee3c;
extern undefined4 DAT_8038ee40;
extern undefined4 DAT_8038ee44;
extern undefined4 DAT_8038ee48;
extern int DAT_8038eec8;
extern int DAT_8038ef08;
extern undefined4 DAT_8038ef0c;
extern undefined4 DAT_8038ef10;
extern undefined4 DAT_8038fd18;
extern undefined4 DAT_8038fd48;
extern undefined4 DAT_8038fd50;
extern undefined4 DAT_8038fd54;
extern undefined4 DAT_8038fd74;
extern undefined4 DAT_8038fd78;
extern undefined4 DAT_8038fd7c;
extern undefined4 DAT_8038fd7d;
extern int DAT_803925b8;
extern undefined4 DAT_803925bc;
extern undefined4 DAT_803925c0;
extern undefined4 DAT_803925c4;
extern undefined4 DAT_803925c8;
extern undefined4 DAT_803925cc;
extern undefined4 DAT_803925d0;
extern undefined4 DAT_803925d4;
extern undefined4 DAT_803925d8;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc2c8;
extern undefined4 DAT_803dd970;
extern undefined4 DAT_803ddbf8;
extern undefined4 DAT_803ddbfc;
extern undefined4 DAT_803ddc00;
extern undefined4 DAT_803ddc04;
extern undefined4 DAT_803ddc08;
extern undefined4 DAT_803ddc0c;
extern undefined4 DAT_803ddc10;
extern undefined4 DAT_803ddc14;
extern undefined4 DAT_803ddc18;
extern undefined4 DAT_803ddc1c;
extern undefined4 DAT_803ddc20;
extern undefined4 DAT_803ddc30;
extern undefined4 DAT_803ddc34;
extern undefined4 DAT_803ddc38;
extern undefined4 DAT_803ddc3c;
extern undefined4 DAT_803ddc40;
extern undefined4 DAT_803ddc44;
extern undefined4 DAT_803ddc48;
extern undefined4 DAT_803ddc4c;
extern undefined4 DAT_803ddc50;
extern undefined4 DAT_803ddc54;
extern undefined4 DAT_803ddc58;
extern undefined4 DAT_803ddc5c;
extern undefined4 DAT_803ddc60;
extern undefined4 DAT_803ddc64;
extern undefined4 DAT_803ddc68;
extern f64 DOUBLE_803df9d8;
extern f64 DOUBLE_803df9e0;
extern f64 DOUBLE_803dfa08;
extern f64 DOUBLE_803dfa48;
extern f32 lbl_803DC074;
extern f32 lbl_803DC2D0;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DDB4C;
extern f32 lbl_803DDB50;
extern f32 lbl_803DDC24;
extern f32 lbl_803DDC28;
extern f32 lbl_803DDC2C;
extern f32 lbl_803DF988;
extern f32 lbl_803DF98C;
extern f32 lbl_803DF990;
extern f32 lbl_803DF994;
extern f32 lbl_803DF998;
extern f32 lbl_803DF99C;
extern f32 lbl_803DF9A0;
extern f32 lbl_803DF9A4;
extern f32 lbl_803DF9A8;
extern f32 lbl_803DF9AC;
extern f32 lbl_803DF9B0;
extern f32 lbl_803DF9B4;
extern f32 lbl_803DF9B8;
extern f32 lbl_803DF9BC;
extern f32 lbl_803DF9C0;
extern f32 lbl_803DF9C4;
extern f32 lbl_803DF9C8;
extern f32 lbl_803DF9CC;
extern f32 lbl_803DF9D0;
extern f32 lbl_803DF9E8;
extern f32 lbl_803DF9EC;
extern f32 lbl_803DF9F0;
extern f32 lbl_803DF9F4;
extern f32 lbl_803DF9F8;
extern f32 lbl_803DF9FC;
extern f32 lbl_803DFA00;
extern f32 lbl_803DFA10;
extern f32 lbl_803DFA14;
extern f32 lbl_803DFA18;
extern f32 lbl_803DFA1C;
extern f32 lbl_803DFA20;
extern f32 lbl_803DFA2C;
extern f32 lbl_803DFA30;
extern f32 lbl_803DFA34;
extern f32 lbl_803DFA38;
extern f32 lbl_803DFA3C;
extern f32 lbl_803DFA40;
extern f32 lbl_803DFA50;
extern f32 lbl_803DFA54;
extern f32 lbl_803DFA58;
extern f32 lbl_803DFA5C;
extern f32 lbl_803DFA60;
extern f32 lbl_803DFA6C;
extern f32 lbl_803DFA70;
extern f32 lbl_803DFA74;
extern f32 lbl_803DFA78;
extern f32 lbl_803DFA7C;
extern f32 lbl_803DFA84;
extern f32 lbl_803DFA88;
extern f32 lbl_803DFA8C;
extern f32 lbl_803DFA90;
extern f32 lbl_803DFA94;
extern f32 lbl_803DFA98;
extern f32 lbl_803DFA9C;

/*
 * --INFO--
 *
 * Function: FUN_8006a028
 * EN v1.0 Address: 0x8006A028
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8006A1A4
 * EN v1.1 Size: 5424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006a028(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8006a02c
 * EN v1.0 Address: 0x8006A02C
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x8006B6D4
 * EN v1.1 Size: 728b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_captureProjectedShadow(ushort *object)
{
  float fVar1;
  int iVar2;
  float *pfVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  float fStack_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float afStack_90 [15];
  
  FUN_80017a50(object,afStack_90,'\0');
  FUN_8000693c((double)(*(float *)(object + 6) - lbl_803DDA58),(double)*(float *)(object + 8),
               (double)(*(float *)(object + 10) - lbl_803DDA5C),
               (double)(lbl_803DF98C * *(float *)(object + 0x54) * *(float *)(object + 4)),
               &local_94,&local_98,&local_9c,&local_a0,&local_a4,&fStack_a8);
  local_a0 = lbl_803DF994 * local_a0 + lbl_803DF990;
  local_a4 = lbl_803DF998 * local_a4 + lbl_803DF990;
  fVar1 = local_a4;
  if (local_a4 < local_a0) {
    fVar1 = local_a0;
  }
  dVar7 = (double)(lbl_803DF99C / fVar1);
  dVar6 = (double)(float)((double)*(float *)(object + 4) * dVar7);
  dVar4 = -(double)local_94;
  dVar8 = (double)local_98;
  FUN_8025da64((double)(float)((double)lbl_803DF994 * dVar4),
               (double)(float)((double)lbl_803DF998 * dVar8),(double)lbl_803DF9A0,
               (double)lbl_803DF9A4,(double)lbl_803DF9A8,(double)lbl_803DF9AC);
  if (lbl_803DF9A8 <= local_9c) {
    **(float **)(object + 0x32) = lbl_803DF9A8;
  }
  else {
    dVar5 = (double)*(float *)(object + 4);
    *(float *)(object + 4) = (float)dVar6;
    FUN_80040cd0(1);
    FUN_8003b878(0,0,0,0,(int)object,1);
    FUN_80040cd0(0);
    *(float *)(object + 4) = (float)dVar5;
    iVar2 = FUN_80017a54((int)object);
    *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
    FUN_8006f8fc(1,3,1);
    FUN_80259400(0x100,0xb0,0x80,0x80);
    FUN_80259504(0x80,0x80,0x2a,0);
    FUN_80259c0c((&DAT_8038ee3c)[DAT_803ddc0c] + 0x60,1);
    FUN_8006a028((&DAT_8038ee3c)[(DAT_803ddc0c + 1) % 3],0x80,0x10,0);
    **(float **)(object + 0x32) = (float)((double)lbl_803DF9AC / dVar7);
  }
  FUN_80006988();
  dVar6 = (double)lbl_803DF994;
  *(float *)(*(int *)(object + 0x32) + 0x14) = (float)(dVar6 * -dVar4);
  dVar4 = (double)lbl_803DF998;
  *(float *)(*(int *)(object + 0x32) + 0x18) = (float)(dVar4 * -dVar8);
  *(float *)(*(int *)(object + 0x32) + 0x14) =
       (float)((double)*(float *)(*(int *)(object + 0x32) + 0x14) + dVar6);
  *(float *)(*(int *)(object + 0x32) + 0x18) =
       (float)((double)*(float *)(*(int *)(object + 0x32) + 0x18) + dVar4);
  fVar1 = lbl_803DF99C;
  pfVar3 = *(float **)(object + 0x32);
  pfVar3[5] = -(lbl_803DF99C * *pfVar3 - pfVar3[5]);
  pfVar3 = *(float **)(object + 0x32);
  pfVar3[6] = -(fVar1 * *pfVar3 - pfVar3[6]);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006a2d0
 * EN v1.0 Address: 0x8006A2D0
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x8006B9AC
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_sortQueuedShadowCasters(int queueBase,int casterCount)
{
  int iVar1;
  float fVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 *puVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  
  iVar1 = (casterCount + -1) / 9 + (casterCount + -1 >> 0x1f);
  for (iVar5 = 1; iVar5 <= iVar1 - (iVar1 >> 0x1f); iVar5 = iVar5 * 3 + 1) {
  }
  for (; 0 < iVar5; iVar5 = iVar5 / 3) {
    iVar13 = iVar5 + 1;
    iVar9 = iVar13 * 0xc;
    iVar10 = queueBase + iVar9;
    iVar1 = (casterCount + 1) - iVar13;
    if (iVar13 <= casterCount) {
      do {
        uVar6 = *(undefined4 *)(iVar10 + -0xc);
        fVar2 = *(float *)(iVar10 + -8);
        uVar3 = *(undefined4 *)(iVar10 + -4);
        iVar7 = queueBase + iVar9;
        iVar12 = iVar13;
        while ((iVar5 < iVar12 &&
               (iVar11 = queueBase + (iVar12 - iVar5) * 0xc, *(float *)(iVar11 + -8) < fVar2))) {
          uVar4 = *(undefined4 *)(iVar11 + -8);
          *(undefined4 *)(iVar7 + -0xc) = *(undefined4 *)(iVar11 + -0xc);
          *(undefined4 *)(iVar7 + -8) = uVar4;
          *(undefined4 *)(iVar7 + -4) = *(undefined4 *)(iVar11 + -4);
          iVar7 = iVar7 + iVar5 * -0xc;
          iVar12 = iVar12 - iVar5;
        }
        puVar8 = (undefined4 *)(queueBase + iVar12 * 0xc + -0xc);
        *puVar8 = uVar6;
        puVar8[1] = fVar2;
        puVar8[2] = uVar3;
        iVar10 = iVar10 + 0xc;
        iVar13 = iVar13 + 1;
        iVar9 = iVar9 + 0xc;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006a410
 * EN v1.0 Address: 0x8006A410
 * EN v1.0 Size: 2448b
 * EN v1.1 Address: 0x8006BADC
 * EN v1.1 Size: 2596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_renderQueuedShadowCasters(void)
{
  undefined2 uVar1;
  undefined2 uVar2;
  uint uVar3;
  int iVar4;
  undefined2 *puVar5;
  ushort uVar10;
  uint uVar6;
  int *piVar7;
  int iVar8;
  float *pfVar9;
  float *pfVar11;
  float *pfVar12;
  int iVar13;
  uint uVar14;
  uint uVar15;
  char cVar16;
  byte bVar17;
  uint uVar18;
  int *piVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  double in_f21;
  double in_f22;
  double in_f23;
  double dVar23;
  double in_f24;
  double in_f25;
  double dVar24;
  double in_f26;
  double dVar25;
  double in_f27;
  double dVar26;
  double in_f28;
  double dVar27;
  double in_f29;
  double in_f30;
  double dVar28;
  double in_f31;
  double dVar29;
  double in_ps21_1;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 uStack_260;
  undefined4 uStack_25c;
  float local_258;
  float local_254;
  float local_250;
  float local_24c;
  float local_248;
  float local_244;
  float local_240;
  float local_23c;
  float local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined auStack_228 [12];
  undefined auStack_21c [12];
  float afStack_210 [16];
  float local_1d0;
  float local_1cc;
  float local_1c8;
  float local_1c4;
  float local_1c0;
  float local_1bc;
  float local_1b8;
  float local_1b4;
  float local_1b0;
  float local_1ac;
  float local_1a8;
  float local_1a4;
  float afStack_1a0 [12];
  float afStack_170 [24];
  undefined4 local_110;
  uint uStack_10c;
  undefined4 local_108;
  uint uStack_104;
  int local_100;
  float local_a8;
  float fStack_a4;
  float local_98;
  float fStack_94;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
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
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  local_98 = (float)in_f22;
  fStack_94 = (float)in_ps22_1;
  local_a8 = (float)in_f21;
  fStack_a4 = (float)in_ps21_1;
  FUN_8028680c();
  if (DAT_803ddbf8 != 0) {
    FUN_800069b8();
    newshadows_sortQueuedShadowCasters(-0x7fc710f8,(uint)DAT_803ddbf8);
    FUN_80006954(1);
    puVar5 = FUN_800069a8();
    dVar21 = FUN_800069f8();
    FUN_80006a00((double)lbl_803DF9B0);
    FUN_800069f4((double)lbl_803DF9AC);
    dVar26 = (double)*(float *)(puVar5 + 6);
    dVar25 = (double)*(float *)(puVar5 + 8);
    dVar24 = (double)*(float *)(puVar5 + 10);
    local_100 = (int)(short)puVar5[1];
    uVar1 = *puVar5;
    uVar2 = puVar5[2];
    puVar5[1] = 0;
    local_240 = lbl_803DF9A8;
    local_23c = lbl_803DF9AC;
    local_238 = lbl_803DF9A8;
    FUN_80060710((double)lbl_803DF9B4,&local_240,afStack_170);
    FUN_800606a4(&uStack_25c,&uStack_260);
    bVar17 = 0;
    uVar18 = 0;
    piVar19 = &DAT_8038ef08;
    for (cVar16 = '\0'; ((int)cVar16 < (int)(uint)DAT_803ddbf8 && (cVar16 < 100));
        cVar16 = cVar16 + '\x01') {
      iVar13 = *piVar19;
      pfVar12 = *(float **)(iVar13 + 100);
      FUN_80006954(0);
      uVar10 = FUN_80061198(iVar13,(uint)DAT_803dc070);
      FUN_80006954(1);
      if (4 < (uVar10 & 0xff)) {
        if (((uint)pfVar12[0xc] & 0x20) != 0) {
          FUN_80003494((uint)auStack_228,iVar13 + 0xc,0xc);
          FUN_80003494((uint)auStack_21c,iVar13 + 0x18,0xc);
          FUN_80003494(iVar13 + 0xc,(uint)(pfVar12 + 8),0xc);
          FUN_80003494(iVar13 + 0x18,(uint)(pfVar12 + 8),0xc);
        }
        uVar3 = uVar18 & 0xff;
        iVar4 = uVar3 * 0x68;
        pfVar11 = (float *)(&DAT_8038fd18 + iVar4);
        (&DAT_8038fd7c)[iVar4] = (char)uVar10;
        if ((bVar17 < 8) && (*(char *)(piVar19 + 2) != '\0')) {
          if (bVar17 < 3) {
            uVar14 = 0x100;
            dVar23 = (double)lbl_803DF9B8;
          }
          else if (bVar17 < 5) {
            uVar14 = 0x80;
            dVar23 = (double)lbl_803DF9BC;
          }
          else {
            uVar14 = 0x40;
            dVar23 = (double)lbl_803DF9C0;
          }
          uVar15 = uVar14;
          if (bVar17 == 0) {
            uVar15 = uVar14 << 1;
          }
          if (*(char *)(piVar19 + 2) == '\x02') {
            uVar15 = (uint)*(ushort *)(*(int *)(*(int *)(iVar13 + 100) + 4) + 10);
            uVar14 = uVar15;
          }
          FUN_80080f6c(iVar13,&local_234,&local_230,&local_22c);
          local_24c = -pfVar12[5];
          local_248 = -pfVar12[6];
          local_244 = -pfVar12[7];
          dVar22 = FUN_80247f90(&local_24c,&local_234);
          if ((dVar22 < (double)lbl_803DF9AC) && ((double)lbl_803DF9C4 < dVar22)) {
            local_258 = lbl_803DF9C8 * local_24c + lbl_803DF9CC * local_234;
            local_254 = lbl_803DF9C8 * local_248 + lbl_803DF9CC * local_230;
            local_250 = lbl_803DF9C8 * local_244 + lbl_803DF9CC * local_22c;
            dVar22 = FUN_80247f54(&local_258);
            if ((double)lbl_803DF9A8 < dVar22) {
              FUN_80247edc((double)(float)((double)lbl_803DF9AC / dVar22),&local_258,&local_234);
            }
          }
          if (lbl_803DF9D0 < local_230) {
            local_230 = lbl_803DF9D0;
            FUN_80247ef8(&local_234,&local_234);
          }
          dVar27 = -(double)local_234;
          dVar29 = -(double)local_230;
          dVar28 = -(double)local_22c;
          uVar6 = FUN_80017730();
          DAT_803ddc04 = uVar6 & 0xffff;
          uVar6 = FUN_80017730();
          DAT_803ddc08 = (uVar6 & 0xffff) - 0x3fc8;
          puVar5[1] = (short)DAT_803ddc08;
          *puVar5 = (short)DAT_803ddc04;
          dVar22 = (double)(float)(dVar28 * dVar28 +
                                  (double)(float)(dVar27 * dVar27 + (double)(float)(dVar29 * dVar29)
                                                 ));
          if ((double)lbl_803DF9A8 < dVar22) {
            dVar20 = 1.0 / SQRT(dVar22);
            dVar20 = DOUBLE_803df9d8 * dVar20 * -(dVar22 * dVar20 * dVar20 - DOUBLE_803df9e0);
            dVar20 = DOUBLE_803df9d8 * dVar20 * -(dVar22 * dVar20 * dVar20 - DOUBLE_803df9e0);
            dVar22 = (double)(float)(dVar22 * DOUBLE_803df9d8 * dVar20 *
                                              -(dVar22 * dVar20 * dVar20 - DOUBLE_803df9e0));
          }
          if ((double)lbl_803DF9A8 < dVar22) {
            dVar22 = (double)(float)((double)lbl_803DF9E8 / dVar22);
            dVar27 = (double)(float)(dVar27 * dVar22);
            dVar29 = (double)(float)(dVar29 * dVar22);
            dVar28 = (double)(float)(dVar28 * dVar22);
          }
          *(undefined4 *)(puVar5 + 0x20) = 0;
          pfVar12[5] = -local_234;
          pfVar12[6] = -local_230;
          pfVar12[7] = -local_22c;
          FUN_8006f788(uVar15);
          piVar7 = (int *)FUN_80017a54(iVar13);
          iVar8 = FUN_80017970(piVar7,0);
          *(float *)(puVar5 + 6) = (float)(dVar27 + (double)*(float *)(iVar8 + 0xc));
          *(float *)(puVar5 + 8) = (float)(dVar29 + (double)*(float *)(iVar8 + 0x1c));
          *(float *)(puVar5 + 10) = (float)(dVar28 + (double)*(float *)(iVar8 + 0x2c));
          if (*(int *)(iVar13 + 0x30) == 0) {
            *(float *)(puVar5 + 6) = *(float *)(puVar5 + 6) + lbl_803DDB50;
            *(float *)(puVar5 + 10) = *(float *)(puVar5 + 10) + lbl_803DDB4C;
          }
          dVar22 = (double)*pfVar12;
          dVar27 = -dVar22;
          if (*(int *)(iVar13 + 0x30) != 0) {
            *(float *)(puVar5 + 6) = *(float *)(puVar5 + 6) + lbl_803DDA58;
            *(float *)(puVar5 + 10) = *(float *)(puVar5 + 10) + lbl_803DDA5C;
          }
          FUN_8025da88(2,2,uVar15 - 4,uVar15 - 4);
          dVar28 = (double)lbl_803DF9A8;
          local_110 = 0x43300000;
          local_108 = 0x43300000;
          uStack_10c = uVar15;
          uStack_104 = uVar15;
          FUN_8025da64(dVar28,dVar28,
                       (double)(float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803dfa08),
                       (double)(float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803dfa08),dVar28
                       ,(double)lbl_803DF9AC);
          FUN_80247dfc(dVar27,dVar22,dVar27,dVar22,(double)lbl_803DF9AC,(double)lbl_803DF9EC,
                       afStack_210);
          FUN_8025d6ac(afStack_210,1);
          FUN_80006984();
          FUN_80247b70(dVar22,dVar27,dVar27,dVar22,dVar23,dVar23,dVar23,dVar23,pfVar11);
          pfVar9 = (float *)FUN_80006974();
          FUN_802475e4(pfVar9,(float *)(&DAT_8038fd48 + iVar4));
          FUN_80247618(pfVar11,pfVar9,pfVar11);
          *(float **)(*(int *)(iVar13 + 100) + 0xc) = pfVar11;
          piVar7 = &DAT_803925b8 + bVar17;
          (&DAT_8038fd78)[uVar3 * 0x1a] = *piVar7;
          (&DAT_8038fd7d)[iVar4] = (&DAT_803dc2c8)[bVar17];
          FUN_8003b7dc(iVar13);
          if (*(char *)(piVar19 + 2) == '\x02') {
            FUN_8006f8fc(1,3,1);
            dVar23 = (double)lbl_803DF9A8;
            FUN_80247a7c(dVar23,dVar23,dVar23,(float *)(&DAT_8038fd48 + iVar4));
            (&DAT_8038fd50)[uVar3 * 0x1a] = lbl_803DF9F0;
            (&DAT_8038fd54)[uVar3 * 0x1a] = lbl_803DF9F4;
            (&DAT_8038fd74)[uVar3 * 0x1a] = lbl_803DF9AC;
            FUN_80247618((float *)(&DAT_8038fd48 + iVar4),pfVar9,(float *)(&DAT_8038fd48 + iVar4));
            FUN_80259400(0,0,uVar15,uVar15);
            FUN_80259504((ushort)uVar15,(ushort)uVar15,0x11,0);
            FUN_80259858('\0',(byte *)(DAT_803dd970 + 0x1a),'\0',(byte *)(DAT_803dd970 + 0x32));
            FUN_80259c0c(*(int *)(*(int *)(iVar13 + 100) + 4) + 0x60,1);
            FUN_80045be8();
            (&DAT_8038fd78)[uVar3 * 0x1a] = *(undefined4 *)(*(int *)(iVar13 + 100) + 4);
          }
          else {
            if (bVar17 == 0) {
              FUN_8006f8fc(1,3,1);
              FUN_80259400(0,0,uVar15,uVar15);
              FUN_80259504((ushort)uVar14,(ushort)uVar14,0x20,1);
              FUN_80259c0c(*piVar7 + 0x60,1);
              (&DAT_8038fd78)[uVar3 * 0x1a] = *piVar7;
            }
            bVar17 = bVar17 + 1;
          }
        }
        else {
          (&DAT_8038fd78)[uVar3 * 0x1a] = *(undefined4 *)(*(int *)(iVar13 + 100) + 4);
          dVar23 = (double)*(float *)(iVar13 + 0xc);
          dVar22 = (double)*(float *)(iVar13 + 0x14);
          if (*(int *)(iVar13 + 0x30) == 0) {
            dVar23 = (double)(float)(dVar23 - (double)lbl_803DDA58);
            dVar22 = (double)(float)(dVar22 - (double)lbl_803DDA5C);
          }
          FUN_80247a48(-dVar23,-(double)*(float *)(iVar13 + 0x10),-dVar22,afStack_1a0);
          local_1d0 = lbl_803DF9B8 / *pfVar12;
          local_1cc = lbl_803DF9A8;
          local_1c8 = lbl_803DF9A8;
          local_1c4 = lbl_803DF9B8;
          local_1c0 = lbl_803DF9A8;
          local_1bc = lbl_803DF9A8;
          local_1b4 = lbl_803DF9B8;
          local_1b0 = lbl_803DF9A8;
          local_1ac = lbl_803DF9A8;
          local_1a8 = lbl_803DF9A8;
          local_1a4 = lbl_803DF9AC;
          local_1b8 = local_1d0;
          FUN_80247618(&local_1d0,afStack_1a0,pfVar11);
          pfVar12[5] = local_240;
          pfVar12[6] = local_23c;
          pfVar12[7] = local_238;
          *(float **)(*(int *)(iVar13 + 100) + 0xc) = pfVar11;
        }
        uVar18 = uVar18 + 1;
        if (((uint)pfVar12[0xc] & 0x20) != 0) {
          FUN_80003494(iVar13 + 0xc,(uint)auStack_228,0xc);
          FUN_80003494(iVar13 + 0x18,(uint)auStack_21c,0xc);
        }
      }
      piVar19 = piVar19 + 3;
    }
    if (1 < bVar17) {
      FUN_8006f8fc(1,3,1);
      FUN_80259858('\0',(byte *)(DAT_803dd970 + 0x1a),'\0',(byte *)(DAT_803dd970 + 0x32));
      FUN_80259400(0,0,0x100,0x100);
      FUN_80259504(0x100,0x100,0x28,0);
      FUN_80259c0c(DAT_803925bc + 0x60,1);
      FUN_80258c24();
      FUN_80045be8();
    }
    FUN_8006f790();
    *(float *)(puVar5 + 6) = (float)dVar26;
    *(float *)(puVar5 + 8) = (float)dVar25;
    *(float *)(puVar5 + 10) = (float)dVar24;
    puVar5[1] = (short)local_100;
    *puVar5 = uVar1;
    puVar5[2] = uVar2;
    uVar18 = FUN_8005d00c();
    if (uVar18 == 0) {
      uVar18 = FUN_8005d06c();
      if (uVar18 == 0) {
        FUN_80006954(0);
        FUN_80006a00(dVar21);
        FUN_800069f4((double)lbl_803DC2D0);
        FUN_8000694c();
      }
      else {
        FUN_80006954(0);
        FUN_80006a00(dVar21);
        FUN_800069f4((double)lbl_803DFA00);
        FUN_8000694c();
      }
    }
    else {
      FUN_80006954(0);
      FUN_80006a00(dVar21);
      uVar18 = FUN_8005d06c();
      if (uVar18 == 0) {
        FUN_800069f4((double)lbl_803DF9FC);
      }
      else {
        FUN_800069f4((double)lbl_803DF9F8);
      }
      FUN_8000694c();
    }
    FUN_80006984();
    FUN_800069d4();
    FUN_80006988();
    FUN_800069bc();
  }
  FUN_80286858();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006ada0
 * EN v1.0 Address: 0x8006ADA0
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x8006C500
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_queueShadowCaster(int object)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  
  if (DAT_803ddbf8 < 300) {
    (&DAT_8038ef08)[(uint)DAT_803ddbf8 * 3] = object;
    fVar1 = *(float *)(object + 0x18) - *(float *)(DAT_803ddc68 + 0xc);
    fVar2 = *(float *)(object + 0x1c) - *(float *)(DAT_803ddc68 + 0x10);
    fVar3 = *(float *)(object + 0x20) - *(float *)(DAT_803ddc68 + 0x14);
    dVar6 = (double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2);
    if ((double)lbl_803DF9A8 < dVar6) {
      dVar5 = 1.0 / SQRT(dVar6);
      dVar5 = DOUBLE_803df9d8 * dVar5 * -(dVar6 * dVar5 * dVar5 - DOUBLE_803df9e0);
      dVar5 = DOUBLE_803df9d8 * dVar5 * -(dVar6 * dVar5 * dVar5 - DOUBLE_803df9e0);
      dVar6 = (double)(float)(dVar6 * DOUBLE_803df9d8 * dVar5 *
                                      -(dVar6 * dVar5 * dVar5 - DOUBLE_803df9e0));
    }
    iVar4 = (uint)DAT_803ddbf8 * 0xc;
    *(float *)(&DAT_8038ef0c + iVar4) = (float)((double)**(float **)(object + 100) / dVar6);
    if (*(short *)(*(int *)(object + 0x50) + 0x48) == 2) {
      (&DAT_8038ef10)[iVar4] = 1;
      if ((*(byte *)(*(int *)(object + 0x50) + 0x5f) & 4) != 0) {
        (&DAT_8038ef10)[iVar4] = 2;
        *(float *)(&DAT_8038ef0c + iVar4) = lbl_803DFA10;
      }
    }
    else {
      (&DAT_8038ef10)[iVar4] = 0;
    }
    DAT_803ddbf8 = DAT_803ddbf8 + 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af14
 * EN v1.0 Address: 0x8006AF14
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x8006C63C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowTextureTable4x8(int *tableOut,int *columnsOut,int *rowsOut)
{
  *tableOut = (int)&DAT_8038ee48;
  *columnsOut = 4;
  *rowsOut = 8;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af30
 * EN v1.0 Address: 0x8006AF30
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x8006C65C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowTextureTable16(int *tableOut,int *countOut)
{
  *tableOut = (int)&DAT_8038eec8;
  *countOut = 0x10;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af44
 * EN v1.0 Address: 0x8006AF44
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C674
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006af44(undefined4 *param_1)
{
  *param_1 = DAT_803ddc44;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af50
 * EN v1.0 Address: 0x8006AF50
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C680
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006af50(undefined4 *param_1)
{
  *param_1 = DAT_803ddc48;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af5c
 * EN v1.0 Address: 0x8006AF5C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C68C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowTexture(int *textureOut)
{
  *textureOut = DAT_803ddc30;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af68
 * EN v1.0 Address: 0x8006AF68
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C698
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006af68(undefined4 *param_1)
{
  *param_1 = DAT_803ddc34;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af74
 * EN v1.0 Address: 0x8006AF74
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C6A4
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getBlankShadowTexture(int *textureOut)
{
  *textureOut = DAT_803ddc38;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af80
 * EN v1.0 Address: 0x8006AF80
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C6B0
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowDirectionTexture(int *textureOut)
{
  *textureOut = DAT_803ddc3c;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af8c
 * EN v1.0 Address: 0x8006AF8C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C6BC
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getSoftShadowTexture(int *textureOut)
{
  *textureOut = DAT_803ddc40;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af98
 * EN v1.0 Address: 0x8006AF98
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x8006C6C8
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8006af98(void)
{
  int iVar1;
  
  iVar1 = FUN_800537a0(0x200,0x200,1,'\0',0,0,0,0,0);
  *(undefined2 *)(iVar1 + 0xe) = 1;
  FUN_802420e0(iVar1 + 0x60,*(int *)(iVar1 + 0x44));
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b004
 * EN v1.0 Address: 0x8006B004
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C734
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowRampTexture(int *textureOut)
{
  *textureOut = DAT_803ddc1c;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b010
 * EN v1.0 Address: 0x8006B010
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8006C740
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int newshadows_getSmallShadowTexture(void)
{
  return DAT_803ddc54;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b018
 * EN v1.0 Address: 0x8006B018
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C748
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowDiskTexture(int *textureOut)
{
  *textureOut = DAT_803ddc58;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b024
 * EN v1.0 Address: 0x8006B024
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C754
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006b024(undefined4 *param_1)
{
  *param_1 = DAT_803ddc5c;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b030
 * EN v1.0 Address: 0x8006B030
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C760
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowNoiseTexture(int *textureOut)
{
  *textureOut = DAT_803ddc60;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b03c
 * EN v1.0 Address: 0x8006B03C
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x8006C76C
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006b03c(int param_1,undefined4 *param_2,undefined4 *param_3,int *param_4,int *param_5)
{
  *param_2 = (&DAT_8038ee3c)[(DAT_803ddc0c + 1) % 3];
  *param_3 = **(undefined4 **)(param_1 + 100);
  *param_4 = (int)*(float *)(*(int *)(param_1 + 100) + 0x14);
  *param_5 = (int)*(float *)(*(int *)(param_1 + 100) + 0x18);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b0b4
 * EN v1.0 Address: 0x8006B0B4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8006C7EC
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double newshadows_getShadowNoiseScale(void)
{
  return (double)lbl_803DDC24;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b0bc
 * EN v1.0 Address: 0x8006B0BC
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8006C7F4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006b0bc(int param_1)
{
  FUN_8025b054((uint *)(DAT_803ddc50 + 0x20),param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b0e8
 * EN v1.0 Address: 0x8006B0E8
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8006C820
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006b0e8(int param_1)
{
  if (*(char *)(DAT_803ddc4c + 0x48) == '\0') {
    FUN_8025b054((uint *)(DAT_803ddc4c + 0x20),param_1);
  }
  else {
    FUN_8025aeac((uint *)(DAT_803ddc4c + 0x20),*(uint **)(DAT_803ddc4c + 0x40),param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b134
 * EN v1.0 Address: 0x8006B134
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8006C86C
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_bindShadowRenderTexture(int textureSlot)
{
  if (*(char *)(DAT_803ddbfc + 0x48) == '\0') {
    FUN_8025b054((uint *)(DAT_803ddbfc + 0x20),textureSlot);
  }
  else {
    FUN_8025aeac((uint *)(DAT_803ddbfc + 0x20),*(uint **)(DAT_803ddbfc + 0x40),textureSlot);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b180
 * EN v1.0 Address: 0x8006B180
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8006C8B8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int newshadows_getShadowRenderTexture(void)
{
  return DAT_803ddbfc;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b188
 * EN v1.0 Address: 0x8006B188
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8006C8C0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8006b188(void)
{
  return DAT_803ddc14;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b190
 * EN v1.0 Address: 0x8006B190
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8006C8C8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int newshadows_getInverseShadowRampTexture(void)
{
  return DAT_803ddc18;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b198
 * EN v1.0 Address: 0x8006B198
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8006C8D0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int newshadows_getRadialFalloffTexture(void)
{
  return DAT_803ddc10;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b1a0
 * EN v1.0 Address: 0x8006B1A0
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8006C8D8
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_bindShadowCaptureTexture(int textureSlot)
{
  if (*(char *)(DAT_803ddc64 + 0x48) == '\0') {
    FUN_8025b054((uint *)(DAT_803ddc64 + 0x20),textureSlot);
  }
  else {
    FUN_8025aeac((uint *)(DAT_803ddc64 + 0x20),*(uint **)(DAT_803ddc64 + 0x40),textureSlot);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b1ec
 * EN v1.0 Address: 0x8006B1EC
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x8006C924
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_refreshShadowCaptureTexture(void)
{
  FUN_800709e8((double)lbl_803DF9A8,(double)lbl_803DF9A8,DAT_803ddbfc,0xff,0x40);
  FUN_80259400(0,0,0x50,0x3c);
  FUN_80259504(0x50,0x3c,4,0);
  FUN_80259c0c(DAT_803ddc64 + 0x60,1);
  if (*(char *)(DAT_803ddc64 + 0x48) != '\0') {
    FUN_8025b280(DAT_803ddc64 + 0x20,*(uint **)(DAT_803ddc64 + 0x40));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b274
 * EN v1.0 Address: 0x8006B274
 * EN v1.0 Size: 236b
 * EN v1.1 Address: 0x8006C9AC
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_flushShadowRenderTargets(void)
{
  FUN_80259400(0,0,0x280,0x1e0);
  FUN_80259504(0x140,0xf0,4,1);
  FUN_80259c0c(DAT_803ddbfc + 0x60,0);
  FUN_80259400(0,0,0x280,0x1e0);
  FUN_80259504(0x140,0xf0,0x11,1);
  FUN_80259c0c(DAT_803ddc5c + 0x60,0);
  if (*(char *)(DAT_803ddbfc + 0x48) != '\0') {
    FUN_8025b280(DAT_803ddbfc + 0x20,*(uint **)(DAT_803ddbfc + 0x40));
  }
  if (*(char *)(DAT_803ddc5c + 0x48) != '\0') {
    FUN_8025b280(DAT_803ddc5c + 0x20,*(uint **)(DAT_803ddc5c + 0x40));
  }
  if ((*(char *)(DAT_803ddbfc + 0x48) == '\0') || (*(char *)(DAT_803ddc5c + 0x48) == '\0')) {
    FUN_8025b210();
  }
  FUN_80258c24();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b360
 * EN v1.0 Address: 0x8006B360
 * EN v1.0 Size: 388b
 * EN v1.1 Address: 0x8006CA98
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_updateFrameState(void)
{
  uint uVar1;
  int iVar2;
  char cVar3;
  undefined *puVar4;
  double dVar5;
  double in_f31;
  double dVar6;
  double in_ps31_1;
  float local_28;
  float local_24;
  undefined8 local_20;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar2 = FUN_800176d0();
  if (iVar2 == 0) {
    lbl_803DDC2C = lbl_803DFA14 * lbl_803DC074 + lbl_803DDC2C;
    lbl_803DDC28 = lbl_803DFA18 * lbl_803DC074 + lbl_803DDC28;
    if (lbl_803DFA1C < lbl_803DDC2C) {
      lbl_803DDC2C = lbl_803DDC2C - lbl_803DFA1C;
    }
    if (lbl_803DFA1C < lbl_803DDC28) {
      lbl_803DDC28 = lbl_803DDC28 - lbl_803DFA1C;
    }
  }
  DAT_803ddbf8 = 0;
  DAT_803ddc68 = (int)FUN_800069a8();
  DAT_803ddc20 = DAT_803ddc20 + (ushort)DAT_803dc070 * 0x28a;
  local_20 = CONCAT44(0x43300000,(uint)DAT_803ddc20);
  dVar5 = (double)FUN_802947f8();
  lbl_803DDC24 = (float)((double)lbl_803DFA20 * dVar5);
  FUN_800606a8();
  DAT_803ddc0c = (char)(DAT_803ddc0c + 1) + (char)((DAT_803ddc0c + 1) / 3) * -3;
  cVar3 = FUN_80048094();
  if (cVar3 != '\0') {
    puVar4 = FUN_8000697c();
    dVar6 = (double)*(float *)(puVar4 + 0x1c);
    FUN_80048048(&local_24,&local_28);
    dVar5 = (double)local_24;
    if (dVar6 < dVar5) {
      if ((double)local_28 < dVar6) {
        uVar1 = (uint)((lbl_803DF99C * (float)(dVar5 - dVar6)) / (float)(dVar5 - (double)local_28));
        local_20 = (longlong)(int)uVar1;
      }
      else {
        uVar1 = 0x40;
      }
    }
    else {
      uVar1 = 0;
    }
    if ((uVar1 & 0xff) != (uint)DAT_803ddc00) {
      FUN_80064384(uVar1 & 0xff);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b4e4
 * EN v1.0 Address: 0x8006B4E4
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x8006CC38
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowNoiseScroll(float *xOffsetOut,float *yOffsetOut)
{
  *xOffsetOut = lbl_803DDC2C;
  *yOffsetOut = lbl_803DDC28;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b4f8
 * EN v1.0 Address: 0x8006B4F8
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8006CC4C
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006b4f8(undefined *param_1)
{
  undefined *puVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  puVar1 = &DAT_8038eba8;
  iVar3 = 0x25;
  while ((puVar1[0x10] == '\0' || (puVar1 != param_1))) {
    puVar1 = puVar1 + 0x14;
    iVar2 = iVar2 + 1;
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      return;
    }
  }
  (&DAT_8038ebb8)[iVar2 * 0x14] = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b540
 * EN v1.0 Address: 0x8006B540
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8006CCA0
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_freeShadowDirectionTexture(void)
{
  FUN_80017814(DAT_803ddc3c);
  DAT_803ddc3c = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b56c
 * EN v1.0 Address: 0x8006B56C
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x8006CCCC
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_buildShadowDirectionTexture(void)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  double dVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  undefined8 local_18;
  
  DAT_803ddc3c = FUN_800537a0(0x100,0x100,3,'\0',0,0,0,1,1);
  dVar5 = DOUBLE_803dfa48;
  fVar4 = lbl_803DFA40;
  fVar3 = lbl_803DFA3C;
  fVar2 = lbl_803DFA2C;
  uVar6 = 0;
  dVar13 = (double)lbl_803DF9A8;
  dVar12 = (double)lbl_803DFA38;
  do {
    uVar7 = 0;
    local_18 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
    dVar9 = (double)((float)(local_18 - dVar5) - fVar2);
    iVar8 = 0x100;
    do {
      local_18 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
      dVar10 = (double)((float)(local_18 - dVar5) - fVar2);
      dVar14 = (double)(float)(dVar9 * dVar9 + (double)(float)(dVar10 * dVar10));
      if (dVar13 < dVar14) {
        dVar11 = 1.0 / SQRT(dVar14);
        dVar11 = DOUBLE_803df9d8 * dVar11 * -(dVar14 * dVar11 * dVar11 - DOUBLE_803df9e0);
        dVar11 = DOUBLE_803df9d8 * dVar11 * -(dVar14 * dVar11 * dVar11 - DOUBLE_803df9e0);
        dVar14 = (double)(float)(dVar14 * DOUBLE_803df9d8 * dVar11 *
                                          -(dVar14 * dVar11 * dVar11 - DOUBLE_803df9e0));
      }
      fVar1 = lbl_803DF9A8;
      if (dVar14 <= dVar12) {
        fVar1 = lbl_803DF9B4 * -(float)((double)lbl_803DF9C8 * dVar14 - (double)lbl_803DFA30)
                * lbl_803DFA34;
      }
      *(ushort *)
       (DAT_803ddc3c + (uVar6 & 3) * 2 + ((int)uVar6 >> 2) * 0x20 + (uVar7 & 3) * 8 +
        ((int)uVar7 >> 2) * 0x800 + 0x60) =
           (ushort)(int)(fVar4 * (float)(dVar10 / dVar14) * fVar1 + fVar3) |
           (ushort)(((int)(fVar4 * (float)(dVar9 / dVar14) * fVar1 + fVar3) & 0xffffU) << 8);
      uVar7 = uVar7 + 1;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
    uVar6 = uVar6 + 1;
  } while ((int)uVar6 < 0x100);
  FUN_802420e0(DAT_803ddc3c + 0x60,*(int *)(DAT_803ddc3c + 0x44));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b824
 * EN v1.0 Address: 0x8006B824
 * EN v1.0 Size: 1216b
 * EN v1.1 Address: 0x8006CE9C
 * EN v1.1 Size: 768b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006b824(double param_1,double param_2,double param_3,float *param_4,int param_5,
                 float *param_6,float *param_7)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  
  dVar5 = (double)lbl_803DF9A8;
  dVar6 = dVar5;
  if (0 < param_5) {
    do {
      dVar8 = (double)*param_4;
      if (param_3 < dVar8) {
        dVar8 = (double)(lbl_803DF9BC + (float)((double)(float)(dVar8 - param_3) / dVar8));
        if ((double)lbl_803DF9AC < dVar8) {
          dVar8 = (double)lbl_803DF9AC;
        }
        if ((double)lbl_803DF9A8 < dVar8) {
          dVar7 = 1.0 / SQRT(dVar8);
          dVar7 = DOUBLE_803df9d8 * dVar7 * -(dVar8 * dVar7 * dVar7 - DOUBLE_803df9e0);
          dVar7 = DOUBLE_803df9d8 * dVar7 * -(dVar8 * dVar7 * dVar7 - DOUBLE_803df9e0);
          dVar8 = (double)(float)(dVar8 * DOUBLE_803df9d8 * dVar7 *
                                          -(dVar8 * dVar7 * dVar7 - DOUBLE_803df9e0));
        }
        fVar2 = ABS((float)((double)param_4[1] - param_1));
        fVar1 = ABS((float)((double)(float)((double)lbl_803DF9AC + (double)param_4[1]) - param_1))
        ;
        if (fVar1 < fVar2) {
          fVar2 = fVar1;
        }
        fVar1 = ABS((float)((double)(param_4[1] - lbl_803DF9AC) - param_1));
        if (fVar1 < fVar2) {
          fVar2 = fVar1;
        }
        dVar7 = (double)param_4[2];
        fVar1 = lbl_803DF9A8;
        if (dVar7 < param_2) {
          fVar1 = (float)(param_2 - dVar7);
        }
        fVar4 = ABS((float)((double)(float)((double)lbl_803DF9AC + dVar7) - param_2));
        fVar3 = ABS((float)(dVar7 - param_2));
        if (fVar4 < ABS((float)(dVar7 - param_2))) {
          fVar3 = fVar4;
          fVar1 = lbl_803DF9A8;
        }
        dVar7 = (double)fVar1;
        dVar9 = (double)(param_4[2] - lbl_803DF9AC);
        fVar1 = ABS((float)(dVar9 - param_2));
        if ((fVar1 < fVar3) && (fVar3 = fVar1, dVar9 < param_2)) {
          dVar7 = (double)(float)(param_2 - dVar9);
        }
        dVar9 = (double)(fVar2 * fVar2 + fVar3 * fVar3);
        if ((double)lbl_803DF9A8 < dVar9) {
          dVar10 = 1.0 / SQRT(dVar9);
          dVar10 = DOUBLE_803df9d8 * dVar10 * -(dVar9 * dVar10 * dVar10 - DOUBLE_803df9e0);
          dVar10 = DOUBLE_803df9d8 * dVar10 * -(dVar9 * dVar10 * dVar10 - DOUBLE_803df9e0);
          dVar9 = (double)(float)(dVar9 * DOUBLE_803df9d8 * dVar10 *
                                          -(dVar9 * dVar10 * dVar10 - DOUBLE_803df9e0));
        }
        dVar10 = (double)(float)(param_3 / (double)*param_4);
        if ((double)lbl_803DF9A8 < dVar10) {
          dVar11 = 1.0 / SQRT(dVar10);
          dVar11 = DOUBLE_803df9d8 * dVar11 * -(dVar10 * dVar11 * dVar11 - DOUBLE_803df9e0);
          dVar11 = DOUBLE_803df9d8 * dVar11 * -(dVar10 * dVar11 * dVar11 - DOUBLE_803df9e0);
          dVar10 = (double)(float)(dVar10 * DOUBLE_803df9d8 * dVar11 *
                                            -(dVar10 * dVar11 * dVar11 - DOUBLE_803df9e0));
        }
        dVar10 = -(double)(float)(dVar10 * (double)(float)((double)param_4[3] - (double)param_4[4])
                                 - (double)param_4[3]);
        if (dVar9 <= dVar10) {
          dVar9 = (double)(lbl_803DF9AC - (float)(dVar9 / dVar10));
          if ((double)lbl_803DF9A8 < dVar9) {
            dVar11 = 1.0 / SQRT(dVar9);
            dVar11 = DOUBLE_803df9d8 * dVar11 * -(dVar9 * dVar11 * dVar11 - DOUBLE_803df9e0);
            dVar11 = DOUBLE_803df9d8 * dVar11 * -(dVar9 * dVar11 * dVar11 - DOUBLE_803df9e0);
            dVar9 = (double)(float)(dVar9 * DOUBLE_803df9d8 * dVar11 *
                                            -(dVar9 * dVar11 * dVar11 - DOUBLE_803df9e0));
          }
          dVar5 = (double)(float)(dVar8 * dVar9 + dVar5);
          dVar6 = (double)(lbl_803DF9B8 *
                           -(float)(param_3 * (double)lbl_803DFA50 - (double)lbl_803DF9AC) +
                          (float)(dVar6 + (double)(float)(dVar7 / dVar10)));
        }
      }
      param_4 = param_4 + 5;
      param_5 = param_5 + -1;
    } while (param_5 != 0);
  }
  if ((double)lbl_803DF9AC < dVar5) {
    dVar5 = (double)lbl_803DF9AC;
  }
  if ((double)lbl_803DF9AC < dVar6) {
    dVar6 = (double)lbl_803DF9AC;
  }
  *param_6 = (float)((double)lbl_803DF9C0 * dVar6 + (double)lbl_803DFA54);
  *param_7 = (float)dVar5;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006bce4
 * EN v1.0 Address: 0x8006BCE4
 * EN v1.0 Size: 1524b
 * EN v1.1 Address: 0x8006D19C
 * EN v1.1 Size: 1480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006bce4(void)
{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  uint uVar5;
  float *pfVar6;
  int iVar7;
  uint uVar8;
  float *pfVar9;
  uint uVar10;
  int iVar11;
  float *pfVar12;
  int *piVar13;
  float *pfVar14;
  uint uVar15;
  double dVar16;
  double dVar17;
  double in_f24;
  double in_f25;
  double in_f26;
  double in_f27;
  double dVar18;
  double dVar19;
  double in_f28;
  double in_f29;
  double dVar20;
  double in_f30;
  double dVar21;
  double in_f31;
  double dVar22;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_ec;
  float local_e8 [2];
  undefined4 local_e0;
  uint uStack_dc;
  undefined4 local_d8;
  uint uStack_d4;
  undefined8 local_d0;
  longlong local_c8;
  undefined8 local_c0;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
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
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  FUN_80286820();
  uVar5 = FUN_800177bc(1);
  uVar15 = 0;
  iVar11 = 0;
  dVar21 = (double)lbl_803DF9AC;
  dVar22 = (double)lbl_803DF9A8;
  dVar20 = (double)lbl_803DFA5C;
  dVar18 = (double)lbl_803DFA58;
  pfVar14 = (float *)&DAT_803925d8;
  dVar19 = DOUBLE_803dfa48;
  while ((iVar11 < 0x32 && (uVar15 < 10000))) {
    uStack_dc = randomGetRange(8,0x10);
    uStack_dc = uStack_dc ^ 0x80000000;
    local_e0 = 0x43300000;
    *pfVar14 = (float)((double)CONCAT44(0x43300000,uStack_dc) - dVar19);
    uStack_d4 = randomGetRange(5,10);
    uStack_d4 = uStack_d4 ^ 0x80000000;
    local_d8 = 0x43300000;
    pfVar14[3] = (float)(dVar18 * (double)(float)((double)CONCAT44(0x43300000,uStack_d4) - dVar19));
    uVar15 = randomGetRange(0x14,0x32);
    local_d0 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000);
    pfVar14[4] = pfVar14[3] * (float)(dVar18 * (double)(float)(local_d0 - dVar19));
    uVar15 = 0;
    pfVar9 = pfVar14 + 1;
    pfVar12 = pfVar14 + 2;
    do {
      uVar10 = randomGetRange(0,999);
      local_d0 = (double)CONCAT44(0x43300000,uVar10 ^ 0x80000000);
      *pfVar9 = (float)(dVar20 * (double)(float)(local_d0 - dVar19));
      uStack_d4 = randomGetRange(0,999);
      uStack_d4 = uStack_d4 ^ 0x80000000;
      local_d8 = 0x43300000;
      *pfVar12 = (float)(dVar20 * (double)(float)((double)CONCAT44(0x43300000,uStack_d4) - dVar19));
      bVar4 = false;
      iVar7 = 0;
      pfVar6 = (float *)&DAT_803925d8;
      while ((iVar7 < iVar11 && (!bVar4))) {
        fVar1 = ABS((float)((double)*pfVar9 - (double)pfVar6[1]));
        fVar2 = ABS((float)((double)(float)(dVar21 + (double)*pfVar9) - (double)pfVar6[1]));
        if (fVar2 < fVar1) {
          fVar1 = fVar2;
        }
        fVar2 = ABS((float)((double)*pfVar9 - dVar21) - pfVar6[1]);
        if (fVar2 < fVar1) {
          fVar1 = fVar2;
        }
        fVar2 = ABS((float)((double)*pfVar12 - (double)pfVar6[2]));
        fVar3 = ABS((float)((double)(float)(dVar21 + (double)*pfVar12) - (double)pfVar6[2]));
        if (fVar3 < fVar2) {
          fVar2 = fVar3;
        }
        fVar3 = ABS((float)((double)*pfVar12 - dVar21) - pfVar6[2]);
        if (fVar3 < fVar2) {
          fVar2 = fVar3;
        }
        dVar17 = (double)(fVar1 * fVar1 + fVar2 * fVar2);
        if (dVar22 < dVar17) {
          dVar16 = 1.0 / SQRT(dVar17);
          dVar16 = DOUBLE_803df9d8 * dVar16 * -(dVar17 * dVar16 * dVar16 - DOUBLE_803df9e0);
          dVar16 = DOUBLE_803df9d8 * dVar16 * -(dVar17 * dVar16 * dVar16 - DOUBLE_803df9e0);
          dVar17 = (double)(float)(dVar17 * DOUBLE_803df9d8 * dVar16 *
                                            -(dVar17 * dVar16 * dVar16 - DOUBLE_803df9e0));
        }
        if (dVar17 < (double)(pfVar14[4] + pfVar6[3])) {
          bVar4 = true;
        }
        pfVar6 = pfVar6 + 5;
        iVar7 = iVar7 + 1;
      }
      uVar15 = uVar15 + 1;
    } while ((bVar4) && (uVar15 < 10000));
    pfVar14 = pfVar14 + 5;
    iVar11 = iVar11 + 1;
  }
  uVar15 = 0;
  piVar13 = &DAT_8038eec8;
  dVar20 = (double)lbl_803DFA60;
  dVar18 = (double)lbl_803DF988;
  dVar19 = DOUBLE_803dfa48;
  do {
    iVar7 = FUN_800537a0(0x40,0x40,3,'\0',0,1,1,1,1);
    *piVar13 = iVar7;
    uVar10 = 0;
    do {
      uVar8 = 0;
      do {
        iVar7 = *piVar13;
        local_d0 = (double)CONCAT44(0x43300000,uVar10 ^ 0x80000000);
        uStack_d4 = uVar8 ^ 0x80000000;
        local_d8 = 0x43300000;
        local_e0 = 0x43300000;
        uStack_dc = uVar15 ^ 0x80000000;
        FUN_8006b824((double)(float)((double)(float)(local_d0 - dVar19) * dVar20),
                     (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_d4) - dVar19
                                                    ) * dVar20),
                     (double)(float)((double)CONCAT44(0x43300000,uVar15 ^ 0x80000000) - dVar19),
                     (float *)&DAT_803925d8,iVar11,local_e8,&local_ec);
        local_c8 = (longlong)(int)(dVar18 * (double)local_ec);
        local_c0 = (longlong)(int)(dVar18 * (double)local_e8[0]);
        *(ushort *)
         (iVar7 + (uVar10 & 3) * 2 + ((int)uVar10 >> 2) * 0x20 + (uVar8 & 3) * 8 +
          ((int)uVar8 >> 2) * 0x200 + 0x60) =
             (ushort)(((int)(dVar18 * (double)local_ec) & 0xffffU) << 8) |
             (ushort)(int)(dVar18 * (double)local_e8[0]);
        uVar8 = uVar8 + 1;
      } while ((int)uVar8 < 0x40);
      uVar10 = uVar10 + 1;
    } while ((int)uVar10 < 0x40);
    FUN_802420e0(*piVar13 + 0x60,*(int *)(*piVar13 + 0x44));
    piVar13 = piVar13 + 1;
    uVar15 = uVar15 + 1;
  } while ((int)uVar15 < 0x10);
  DAT_803ddc60 = FUN_800537a0(0x40,0x40,3,'\0',0,1,1,1,1);
  uVar15 = 0;
  dVar19 = (double)lbl_803DFA40;
  do {
    uVar10 = 0;
    do {
      iVar7 = DAT_803ddc60 + (uVar15 & 3) * 2;
      local_c0 = CONCAT44(0x43300000,uVar10 ^ 0x80000000);
      FUN_802947f8();
      dVar18 = (double)FUN_802949e8();
      dVar20 = (double)FUN_802949e8();
      iVar11 = (int)(dVar19 * dVar18 + dVar19);
      local_c8 = (longlong)iVar11;
      uVar8 = (uint)(dVar19 * (double)(float)(dVar18 * dVar20) + dVar19);
      local_d0 = (double)(longlong)(int)uVar8;
      *(ushort *)
       (iVar7 + ((int)uVar15 >> 2) * 0x20 + (uVar10 & 3) * 8 + ((int)uVar10 >> 2) * 0x200 + 0x60) =
           (ushort)iVar11 | (ushort)((uVar8 & 0xffff) << 8);
      uVar10 = uVar10 + 1;
    } while ((int)uVar10 < 0x40);
    uVar15 = uVar15 + 1;
  } while ((int)uVar15 < 0x40);
  FUN_802420e0(DAT_803ddc60 + 0x60,*(int *)(DAT_803ddc60 + 0x44));
  lbl_803DDC2C = lbl_803DF9A8;
  lbl_803DDC28 = lbl_803DF9A8;
  FUN_800177bc(uVar5 & 0xff);
  FUN_8028686c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006c2d8
 * EN v1.0 Address: 0x8006C2D8
 * EN v1.0 Size: 6448b
 * EN v1.1 Address: 0x8006D764
 * EN v1.1 Size: 5948b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006c2d8(void)
{
  int iVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  float fVar7;
  float fVar8;
  char cVar9;
  float fVar10;
  ushort uVar11;
  int iVar12;
  float fVar13;
  undefined uVar14;
  uint uVar15;
  int iVar16;
  undefined4 uVar17;
  undefined4 uVar18;
  uint uVar19;
  undefined4 uVar20;
  uint uVar21;
  uint uVar22;
  undefined4 uVar23;
  undefined4 uVar24;
  undefined4 uVar25;
  undefined *puVar26;
  int iVar27;
  int iVar28;
  double dVar29;
  double dVar30;
  double dVar31;
  double dVar32;
  double dVar33;
  double dVar34;
  double dVar35;
  longlong lVar36;
  double dVar37;
  double dVar38;
  double dVar39;
  double dVar40;
  double dVar41;
  double dVar42;
  double dVar43;
  double dVar44;
  double dVar45;
  double dVar46;
  double dVar47;
  double dVar48;
  double dVar49;
  double dVar50;
  undefined8 local_158;
  undefined8 local_150;
  undefined8 local_148;
  
  FUN_80286834();
  puVar26 = &DAT_8038eba8;
  uVar15 = FUN_800177bc(1);
  DAT_803925b8 = FUN_800537a0(0x100,0x100,0,'\0',0,0,0,1,1);
  DAT_803925bc = FUN_800537a0(0x100,0x100,1,'\0',0,0,0,0,0);
  DAT_803925c0 = DAT_803925bc;
  DAT_803925c4 = DAT_803925bc;
  DAT_803925c8 = DAT_803925bc;
  DAT_803925cc = DAT_803925bc;
  DAT_803925d0 = DAT_803925bc;
  DAT_803925d4 = DAT_803925bc;
  FUN_800033a8(DAT_803925b8 + 0x60,0,*(uint *)(DAT_803925b8 + 0x44));
  FUN_802420e0(DAT_803925b8 + 0x60,*(int *)(DAT_803925b8 + 0x44));
  DAT_803ddbfc = FUN_800537a0(0x140,0xf0,4,'\0',0,0,0,1,1);
  DAT_803ddc64 = FUN_800537a0(0x50,0x3c,4,'\0',0,0,0,1,1);
  DAT_803ddc5c = FUN_800537a0(0x140,0xf0,1,'\0',0,0,0,1,1);
  DAT_803ddc58 = FUN_800537a0(0x20,0x20,1,'\0',0,0,0,1,1);
  fVar8 = lbl_803DFA6C;
  fVar10 = lbl_803DFA50;
  dVar41 = DOUBLE_803dfa48;
  fVar13 = lbl_803DF9AC;
  fVar5 = lbl_803DF988;
  uVar19 = 0;
  dVar38 = (double)lbl_803DFA70;
  do {
    uVar21 = 0;
    local_158 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    fVar7 = (float)(local_158 - dVar41) - fVar8;
    iVar16 = (uVar19 & 7) + ((int)uVar19 >> 3) * 0x20;
    iVar27 = 0x10;
    do {
      local_158 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar3 = (float)((double)(fVar7 * fVar10) * dVar38);
      fVar4 = (float)((double)(((float)(local_158 - dVar41) - fVar8) * fVar10) * dVar38);
      fVar4 = fVar3 * fVar3 + fVar4 * fVar4;
      fVar3 = lbl_803DF9A8;
      if (fVar4 <= fVar13) {
        fVar3 = fVar13 - fVar4;
      }
      *(char *)(DAT_803ddc58 + iVar16 + (uVar21 & 3) * 8 + ((int)uVar21 >> 2) * 0x80 + 0x60) =
           (char)(int)(fVar5 * fVar3);
      uVar22 = uVar21 + 1;
      local_158 = (double)CONCAT44(0x43300000,uVar22 ^ 0x80000000);
      fVar3 = (float)((double)(fVar7 * fVar10) * dVar38);
      fVar4 = (float)((double)(((float)(local_158 - dVar41) - fVar8) * fVar10) * dVar38);
      fVar4 = fVar3 * fVar3 + fVar4 * fVar4;
      fVar3 = lbl_803DF9A8;
      if (fVar4 <= fVar13) {
        fVar3 = fVar13 - fVar4;
      }
      *(char *)(DAT_803ddc58 + iVar16 + (uVar22 & 3) * 8 + ((int)uVar22 >> 2) * 0x80 + 0x60) =
           (char)(int)(fVar5 * fVar3);
      uVar21 = uVar21 + 2;
      iVar27 = iVar27 + -1;
    } while (iVar27 != 0);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x20);
  FUN_802420e0(DAT_803ddc58 + 0x60,*(int *)(DAT_803ddc58 + 0x44));
  DAT_803ddc54 = FUN_800537a0(0x10,0x10,1,'\0',0,0,0,1,1);
  fVar10 = lbl_803DFA74;
  dVar41 = DOUBLE_803dfa48;
  fVar13 = lbl_803DF9C0;
  fVar5 = lbl_803DF9AC;
  uVar19 = 0;
  dVar40 = (double)lbl_803DF990;
  dVar29 = (double)lbl_803DF988;
  do {
    uVar21 = 0;
    local_150 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    dVar45 = local_150 - dVar41;
    iVar16 = 0x10;
    do {
      local_150 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar8 = (float)((double)(float)dVar45 - dVar40) * fVar13 * fVar10;
      fVar7 = (float)((double)(float)(local_150 - dVar41) - dVar40) * fVar13 * fVar10;
      fVar8 = fVar8 * fVar8 + fVar7 * fVar7;
      if (fVar8 <= fVar5) {
        dVar42 = (double)(fVar5 - fVar8);
        if ((double)lbl_803DF9A8 < dVar42) {
          dVar38 = 1.0 / SQRT(dVar42);
          dVar38 = DOUBLE_803df9d8 * dVar38 * -(dVar42 * dVar38 * dVar38 - DOUBLE_803df9e0);
          dVar38 = DOUBLE_803df9d8 * dVar38 * -(dVar42 * dVar38 * dVar38 - DOUBLE_803df9e0);
          dVar42 = (double)(float)(dVar42 * DOUBLE_803df9d8 * dVar38 *
                                            -(dVar42 * dVar38 * dVar38 - DOUBLE_803df9e0));
          dVar38 = DOUBLE_803df9e0;
        }
      }
      else {
        dVar42 = (double)lbl_803DF9A8;
      }
      *(char *)(DAT_803ddc54 +
               (uVar19 & 7) + ((int)uVar19 >> 3) * 0x20 + (uVar21 & 3) * 8 +
               ((int)uVar21 >> 2) * 0x40 + 0x60) = (char)(int)(dVar29 * dVar42);
      uVar21 = uVar21 + 1;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x10);
  FUN_802420e0(DAT_803ddc54 + 0x60,*(int *)(DAT_803ddc54 + 0x44));
  uVar17 = 5;
  uVar18 = 0;
  uVar20 = 0;
  uVar23 = 0;
  uVar24 = 0;
  uVar25 = 1;
  DAT_803ddc50 = FUN_800537a0(0x40,0x40,5,'\0',0,0,0,1,1);
  dVar29 = (double)lbl_803DF9A8;
  uVar19 = 0;
  dVar49 = (double)lbl_803DFA7C;
  dVar47 = (double)lbl_803DFA78;
  dVar45 = dVar29;
  dVar42 = dVar29;
  dVar46 = dVar29;
  dVar48 = DOUBLE_803dfa48;
  do {
    uVar21 = 0;
    local_150 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    local_158 = (double)CONCAT44(0x43300000,uVar19 + 1 ^ 0x80000000);
    dVar50 = (double)(float)((double)(float)((double)(float)(local_150 - dVar48) - dVar47) * dVar49)
    ;
    dVar43 = (double)(float)((double)(float)((double)(float)(local_158 - dVar48) - dVar47) * dVar49)
    ;
    do {
      local_150 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar5 = (float)((double)(float)((double)(float)(local_150 - dVar48) - dVar47) * dVar49);
      dVar39 = (double)(fVar5 * fVar5);
      if (dVar46 < (double)(float)(dVar50 * dVar50 + dVar39)) {
        dVar38 = DOUBLE_803df9e0;
      }
      if (dVar42 < (double)(float)(dVar43 * dVar43 + dVar39)) {
        dVar38 = DOUBLE_803df9e0;
      }
      local_150 = (double)CONCAT44(0x43300000,uVar21 + 1 ^ 0x80000000);
      fVar5 = (float)((double)(float)((double)(float)(local_150 - dVar48) - dVar47) * dVar49);
      if (dVar45 < (double)(float)(dVar50 * dVar50 + (double)(fVar5 * fVar5))) {
        dVar38 = DOUBLE_803df9e0;
      }
      dVar30 = (double)FUN_802949e8();
      dVar30 = -dVar30;
      dVar31 = (double)FUN_802949e8();
      dVar31 = ABS(dVar31);
      dVar32 = (double)FUN_802949e8();
      if (dVar29 < (double)(float)(dVar30 - (double)(float)dVar31)) {
        dVar29 = (double)(float)(dVar30 - (double)(float)dVar31);
      }
      if (dVar29 < (double)(float)(dVar30 - (double)(float)ABS(dVar32))) {
        dVar29 = (double)(float)(dVar30 - (double)(float)ABS(dVar32));
      }
      uVar21 = uVar21 + 1;
    } while ((int)uVar21 < 0x40);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x40);
  dVar45 = (double)lbl_803DF9AC;
  dVar50 = (double)(float)(dVar45 / dVar29);
  uVar19 = 0;
  dVar42 = (double)lbl_803DFA7C;
  dVar46 = (double)lbl_803DFA78;
  dVar48 = (double)lbl_803DF9A8;
  dVar47 = (double)lbl_803DFA40;
  dVar49 = (double)lbl_803DFA84;
  dVar43 = (double)lbl_803DFA50;
  dVar29 = DOUBLE_803dfa48;
  do {
    uVar21 = 0;
    local_150 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    local_158 = (double)CONCAT44(0x43300000,uVar19 + 1 ^ 0x80000000);
    dVar31 = (double)(float)((double)(float)((double)(float)(local_150 - dVar29) - dVar46) * dVar42)
    ;
    dVar30 = (double)(float)((double)(float)((double)(float)(local_158 - dVar29) - dVar46) * dVar42)
    ;
    do {
      iVar16 = DAT_803ddc50 + (uVar19 & 3) * 2;
      local_150 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar5 = (float)((double)(float)((double)(float)(local_150 - dVar29) - dVar46) * dVar42);
      dVar32 = (double)(fVar5 * fVar5);
      dVar44 = (double)(float)(dVar31 * dVar31 + dVar32);
      if (dVar48 < dVar44) {
        dVar38 = 1.0 / SQRT(dVar44);
        dVar38 = DOUBLE_803df9d8 * dVar38 * -(dVar44 * dVar38 * dVar38 - DOUBLE_803df9e0);
        dVar38 = DOUBLE_803df9d8 * dVar38 * -(dVar44 * dVar38 * dVar38 - DOUBLE_803df9e0);
        dVar44 = (double)(float)(dVar44 * DOUBLE_803df9d8 * dVar38 *
                                          -(dVar44 * dVar38 * dVar38 - DOUBLE_803df9e0));
        dVar38 = DOUBLE_803df9d8;
      }
      if (dVar48 < (double)(float)(dVar30 * dVar30 + dVar32)) {
        dVar38 = DOUBLE_803df9d8;
      }
      local_150 = (double)CONCAT44(0x43300000,uVar21 + 1 ^ 0x80000000);
      fVar5 = (float)((double)(float)((double)(float)(local_150 - dVar29) - dVar46) * dVar42);
      if (dVar48 < (double)(float)(dVar31 * dVar31 + (double)(fVar5 * fVar5))) {
        dVar38 = DOUBLE_803df9d8;
      }
      dVar33 = (double)FUN_802949e8();
      dVar33 = -dVar33;
      dVar34 = (double)FUN_802949e8();
      dVar34 = -dVar34;
      dVar35 = (double)FUN_802949e8();
      if (dVar45 <= dVar44) {
        dVar44 = (double)lbl_803DF9A8;
      }
      else {
        dVar44 = (double)(float)(dVar45 - dVar44);
        if ((double)lbl_803DF9A8 < dVar44) {
          dVar38 = 1.0 / SQRT(dVar44);
          dVar38 = DOUBLE_803df9d8 * dVar38 * -(dVar44 * dVar38 * dVar38 - DOUBLE_803df9e0);
          dVar39 = DOUBLE_803df9d8 * dVar38 * -(dVar44 * dVar38 * dVar38 - DOUBLE_803df9e0);
          dVar38 = DOUBLE_803df9d8 * dVar39;
          dVar44 = (double)(float)(dVar44 * dVar38 * -(dVar44 * dVar39 * dVar39 - DOUBLE_803df9e0));
          dVar32 = DOUBLE_803df9e0;
          dVar39 = DOUBLE_803df9d8;
        }
      }
      dVar37 = (double)(float)(dVar46 * dVar44);
      if (dVar49 < (double)(float)(dVar46 * dVar44)) {
        dVar37 = dVar49;
      }
      lVar36 = (longlong)(int)dVar37;
      *(ushort *)
       (iVar16 + ((int)uVar19 >> 2) * 0x20 + (uVar21 & 3) * 8 + ((int)uVar21 >> 2) * 0x200 + 0x60) =
           (ushort)(int)((double)(float)(dVar50 * (double)(float)(dVar47 * (double)(float)(dVar33 - 
                                                  -dVar35)) + dVar47) * dVar43) & 0xf |
           (ushort)(((int)dVar37 & 0xfU) << 4) |
           (ushort)(((int)((double)(float)(dVar50 * (double)(float)(dVar47 * (double)(float)(dVar33 
                                                  - dVar34)) + dVar47) * dVar42) & 7U) << 0xc);
      uVar21 = uVar21 + 1;
    } while ((int)uVar21 < 0x40);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x40);
  iVar16 = *(int *)(DAT_803ddc50 + 0x44);
  FUN_802420e0(DAT_803ddc50 + 0x60,iVar16);
  DAT_803ddc4c = FUN_8005398c(lVar36,dVar37,dVar38,dVar32,dVar39,dVar44,dVar40,dVar41,0x5b0,iVar16,
                              uVar17,uVar18,uVar20,uVar23,uVar24,uVar25);
  DAT_803ddc48 = FUN_8005398c(lVar36,dVar37,dVar38,dVar32,dVar39,dVar44,dVar40,dVar41,0x600,iVar16,
                              uVar17,uVar18,uVar20,uVar23,uVar24,uVar25);
  DAT_803ddc44 = FUN_8005398c(lVar36,dVar37,dVar38,dVar32,dVar39,dVar44,dVar40,dVar41,0xc18,iVar16,
                              uVar17,uVar18,uVar20,uVar23,uVar24,uVar25);
  DAT_803ddc1c = FUN_800537a0(0x100,4,1,'\0',0,0,0,0,0);
  uVar19 = 0;
  iVar16 = 0x80;
  do {
    uVar21 = uVar19 & 7;
    iVar27 = ((int)uVar19 >> 3) * 0x20;
    uVar14 = (undefined)uVar19;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x60) = uVar14;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x68) = uVar14;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x70) = uVar14;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x78) = uVar14;
    uVar22 = uVar19 + 1;
    uVar21 = uVar22 & 7;
    iVar27 = ((int)uVar22 >> 3) * 0x20;
    uVar14 = (undefined)uVar22;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x60) = uVar14;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x68) = uVar14;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x70) = uVar14;
    *(undefined *)(DAT_803ddc1c + uVar21 + iVar27 + 0x78) = uVar14;
    uVar19 = uVar19 + 2;
    iVar16 = iVar16 + -1;
  } while (iVar16 != 0);
  FUN_802420e0(DAT_803ddc1c + 0x60,*(int *)(DAT_803ddc1c + 0x44));
  DAT_803ddc18 = FUN_800537a0(0x100,4,1,'\0',0,0,0,1,1);
  uVar19 = 0;
  iVar16 = 0x80;
  do {
    uVar21 = uVar19 & 7;
    iVar27 = ((int)uVar19 >> 3) * 0x20;
    cVar9 = -1 - (char)uVar19;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x60) = cVar9;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x68) = cVar9;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x70) = cVar9;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x78) = cVar9;
    uVar22 = uVar19 + 1;
    uVar21 = uVar22 & 7;
    iVar27 = ((int)uVar22 >> 3) * 0x20;
    cVar9 = -1 - (char)uVar22;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x60) = cVar9;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x68) = cVar9;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x70) = cVar9;
    *(char *)(DAT_803ddc18 + uVar21 + iVar27 + 0x78) = cVar9;
    uVar19 = uVar19 + 2;
    iVar16 = iVar16 + -1;
  } while (iVar16 != 0);
  FUN_802420e0(DAT_803ddc18 + 0x60,*(int *)(DAT_803ddc18 + 0x44));
  DAT_803ddc10 = FUN_800537a0(0x80,0x80,1,'\0',0,0,0,1,1);
  fVar13 = lbl_803DFA60;
  dVar41 = DOUBLE_803dfa48;
  fVar5 = lbl_803DF99C;
  uVar19 = 0;
  dVar29 = (double)lbl_803DF9A8;
  dVar38 = (double)lbl_803DF9B8;
  do {
    uVar21 = 0;
    local_148 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    fVar10 = ((float)(local_148 - dVar41) - fVar5) * fVar13;
    iVar16 = 0x80;
    do {
      local_148 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar8 = ((float)(local_148 - dVar41) - fVar5) * fVar13;
      dVar40 = (double)(fVar10 * fVar10 + fVar8 * fVar8);
      if (dVar29 < dVar40) {
        dVar45 = 1.0 / SQRT(dVar40);
        dVar45 = DOUBLE_803df9d8 * dVar45 * -(dVar40 * dVar45 * dVar45 - DOUBLE_803df9e0);
        dVar45 = DOUBLE_803df9d8 * dVar45 * -(dVar40 * dVar45 * dVar45 - DOUBLE_803df9e0);
        dVar40 = (double)(float)(dVar40 * DOUBLE_803df9d8 * dVar45 *
                                          -(dVar40 * dVar45 * dVar45 - DOUBLE_803df9e0));
      }
      if (dVar38 <= dVar40) {
        if (dVar40 <= (double)lbl_803DF9AC) {
          uVar14 = (undefined)
                   (int)(lbl_803DFA88 *
                        (float)((double)lbl_803DF9AC -
                               (double)(float)((double)(float)(dVar40 - dVar38) / dVar38)));
        }
        else {
          uVar14 = 0;
        }
      }
      else {
        uVar14 = 0xa0;
      }
      *(undefined *)
       (DAT_803ddc10 +
       (uVar19 & 7) + ((int)uVar19 >> 3) * 0x20 + (uVar21 & 3) * 8 + ((int)uVar21 >> 2) * 0x200 +
       0x60) = uVar14;
      uVar21 = uVar21 + 1;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x80);
  FUN_802420e0(DAT_803ddc10 + 0x60,*(int *)(DAT_803ddc10 + 0x44));
  DAT_803ddc40 = FUN_800537a0(0x80,0x80,1,'\0',0,0,0,1,1);
  fVar13 = lbl_803DFA60;
  dVar41 = DOUBLE_803dfa48;
  fVar5 = lbl_803DF99C;
  uVar19 = 0;
  dVar40 = (double)lbl_803DF9A8;
  dVar29 = (double)lbl_803DF9AC;
  dVar38 = (double)lbl_803DF988;
  do {
    uVar21 = 0;
    local_148 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    fVar10 = ABS(((float)(local_148 - dVar41) - fVar5) * fVar13);
    iVar16 = 0x80;
    do {
      local_148 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar8 = ABS(((float)(local_148 - dVar41) - fVar5) * fVar13);
      dVar45 = (double)(fVar10 * fVar10 + fVar8 * fVar8);
      if (dVar40 < dVar45) {
        dVar42 = 1.0 / SQRT(dVar45);
        dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
        dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
        dVar45 = (double)(float)(dVar45 * DOUBLE_803df9d8 * dVar42 *
                                          -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0));
      }
      dVar42 = (double)(float)(dVar29 - dVar45);
      if ((double)(float)(dVar29 - dVar45) < dVar40) {
        dVar42 = dVar40;
      }
      *(char *)(DAT_803ddc40 +
               (uVar19 & 7) + ((int)uVar19 >> 3) * 0x20 + (uVar21 & 3) * 8 +
               ((int)uVar21 >> 2) * 0x200 + 0x60) = (char)(int)(dVar38 * dVar42);
      uVar21 = uVar21 + 1;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x80);
  FUN_802420e0(DAT_803ddc40 + 0x60,*(int *)(DAT_803ddc40 + 0x44));
  DAT_803ddc38 = FUN_800537a0(0x40,0x40,1,'\0',0,0,0,1,1);
  FUN_802420b0(DAT_803ddc38 + 0x60,*(int *)(DAT_803ddc38 + 0x44));
  FUN_80064384(0);
  DAT_803ddc34 = FUN_800537a0(0x20,4,1,'\0',0,0,0,1,1);
  fVar10 = lbl_803DFA6C;
  fVar13 = lbl_803DFA50;
  dVar41 = DOUBLE_803dfa48;
  fVar5 = lbl_803DF988;
  uVar19 = 0;
  dVar38 = (double)lbl_803DF9A8;
  dVar29 = (double)lbl_803DF9AC;
  do {
    uVar21 = 0;
    local_148 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    dVar40 = ABS((double)(((float)(local_148 - dVar41) - fVar10) * fVar13));
    iVar16 = 4;
    do {
      dVar45 = dVar40;
      if (dVar38 < dVar40) {
        dVar45 = 1.0 / SQRT(dVar40);
        dVar45 = DOUBLE_803df9d8 * dVar45 * -(dVar40 * dVar45 * dVar45 - DOUBLE_803df9e0);
        dVar45 = DOUBLE_803df9d8 * dVar45 * -(dVar40 * dVar45 * dVar45 - DOUBLE_803df9e0);
        dVar45 = (double)(float)(dVar40 * DOUBLE_803df9d8 * dVar45 *
                                          -(dVar40 * dVar45 * dVar45 - DOUBLE_803df9e0));
      }
      if (dVar38 < dVar45) {
        dVar42 = 1.0 / SQRT(dVar45);
        dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
        dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
        dVar45 = (double)(float)(dVar45 * DOUBLE_803df9d8 * dVar42 *
                                          -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0));
      }
      *(char *)(DAT_803ddc34 +
               (uVar19 & 7) + ((int)uVar19 >> 3) * 0x20 + (uVar21 & 3) * 8 +
               ((int)uVar21 >> 2) * 0x80 + 0x60) = (char)(int)(fVar5 * (float)(dVar29 - dVar45));
      uVar21 = uVar21 + 1;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x20);
  FUN_802420e0(DAT_803ddc34 + 0x60,*(int *)(DAT_803ddc34 + 0x44));
  DAT_803ddc30 = FUN_800537a0(0x80,0x80,1,'\0',0,1,1,1,1);
  fVar13 = lbl_803DFA60;
  dVar41 = DOUBLE_803dfa48;
  fVar5 = lbl_803DF99C;
  uVar19 = 0;
  dVar29 = (double)lbl_803DF9A8;
  dVar38 = (double)lbl_803DF9BC;
  dVar40 = (double)lbl_803DFA6C;
  do {
    local_148 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    fVar10 = ((float)(local_148 - dVar41) - fVar5) * fVar13;
    uVar21 = 0;
    iVar16 = 0x80;
    do {
      local_148 = (double)CONCAT44(0x43300000,uVar21 ^ 0x80000000);
      fVar8 = ((float)(local_148 - dVar41) - fVar5) * fVar13;
      dVar45 = (double)(fVar8 * fVar8 + fVar10 * fVar10);
      if (dVar29 < dVar45) {
        dVar42 = 1.0 / SQRT(dVar45);
        dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
        dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
        dVar45 = (double)(float)(dVar45 * DOUBLE_803df9d8 * dVar42 *
                                          -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0));
      }
      if ((dVar45 < dVar38) || ((double)lbl_803DFA8C < dVar45)) {
        dVar45 = (double)lbl_803DF9A8;
      }
      else {
        fVar8 = lbl_803DF9B4 * (float)(dVar45 - dVar38);
        if (fVar8 <= lbl_803DF9B8) {
          fVar8 = lbl_803DF9B8 - fVar8;
        }
        else {
          fVar8 = fVar8 - lbl_803DF9B8;
        }
        dVar45 = -(double)(lbl_803DF9B4 * fVar8 - lbl_803DF9AC);
        if ((double)lbl_803DF9A8 < dVar45) {
          dVar42 = 1.0 / SQRT(dVar45);
          dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
          dVar42 = DOUBLE_803df9d8 * dVar42 * -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0);
          dVar45 = (double)(float)(dVar45 * DOUBLE_803df9d8 * dVar42 *
                                            -(dVar45 * dVar42 * dVar42 - DOUBLE_803df9e0));
        }
      }
      *(char *)(DAT_803ddc30 +
               (uVar19 & 7) + ((int)uVar19 >> 3) * 0x20 + (uVar21 & 3) * 8 +
               ((int)uVar21 >> 2) * 0x200 + 0x60) = (char)(int)(dVar40 * dVar45);
      uVar21 = uVar21 + 1;
      iVar16 = iVar16 + -1;
    } while (iVar16 != 0);
    uVar19 = uVar19 + 1;
  } while ((int)uVar19 < 0x80);
  FUN_802420e0(DAT_803ddc30 + 0x60,*(int *)(DAT_803ddc30 + 0x44));
  DAT_803ddc14 = FUN_800537a0(4,4,3,'\0',0,0,0,1,1);
  fVar8 = lbl_803DFA90;
  dVar41 = DOUBLE_803dfa48;
  fVar10 = lbl_803DFA3C;
  fVar13 = lbl_803DF9B8;
  fVar5 = lbl_803DF988;
  uVar19 = 0;
  iVar16 = (int)lbl_803DF9B8;
  iVar27 = (int)lbl_803DFA94;
  iVar1 = (int)lbl_803DFA98;
  iVar2 = (int)lbl_803DFA9C;
  iVar28 = 4;
  do {
    local_148 = (double)CONCAT44(0x43300000,uVar19 ^ 0x80000000);
    iVar12 = (uVar19 & 3) * 2;
    iVar6 = ((int)uVar19 >> 2) * 0x20;
    uVar11 = (ushort)(((int)(fVar5 * ((float)(local_148 - dVar41) / fVar8 - fVar13) + fVar10) &
                      0xffU) << 8);
    *(ushort *)(DAT_803ddc14 + iVar12 + iVar6 + 0x60) = uVar11 | (ushort)iVar16 & 0xff;
    *(ushort *)(DAT_803ddc14 + iVar12 + iVar6 + 0x68) = uVar11 | (ushort)iVar27 & 0xff;
    *(ushort *)(DAT_803ddc14 + iVar12 + iVar6 + 0x70) = uVar11 | (ushort)iVar1 & 0xff;
    *(ushort *)(DAT_803ddc14 + iVar12 + iVar6 + 0x78) = uVar11 | (ushort)iVar2 & 0xff;
    uVar19 = uVar19 + 1;
    iVar28 = iVar28 + -1;
  } while (iVar28 != 0);
  FUN_802420e0(DAT_803ddc14 + 0x60,*(int *)(DAT_803ddc14 + 0x44));
  iVar16 = FUN_800537a0(0x80,0x80,1,'\0',0,0,0,1,1);
  FUN_800033a8(iVar16 + 0x60,0,*(uint *)(iVar16 + 0x44));
  *(undefined2 *)(iVar16 + 0xe) = 1;
  FUN_802420e0(iVar16 + 0x60,*(int *)(iVar16 + 0x44));
  DAT_8038ee3c = iVar16;
  iVar16 = FUN_800537a0(0x80,0x80,1,'\0',0,0,0,1,1);
  FUN_800033a8(iVar16 + 0x60,0,*(uint *)(iVar16 + 0x44));
  *(undefined2 *)(iVar16 + 0xe) = 1;
  FUN_802420e0(iVar16 + 0x60,*(int *)(iVar16 + 0x44));
  DAT_8038ee40 = iVar16;
  iVar16 = FUN_800537a0(0x80,0x80,1,'\0',0,0,0,1,1);
  FUN_800033a8(iVar16 + 0x60,0,*(uint *)(iVar16 + 0x44));
  *(undefined2 *)(iVar16 + 0xe) = 1;
  FUN_802420e0(iVar16 + 0x60,*(int *)(iVar16 + 0x44));
  DAT_8038ee44 = iVar16;
  FUN_80258c48();
  iVar16 = 0;
  iVar27 = 2;
  do {
    puVar26[0x10] = 0;
    puVar26[0x11] = 1;
    puVar26[0x24] = 0;
    puVar26[0x25] = 1;
    puVar26[0x38] = 0;
    puVar26[0x39] = 1;
    puVar26[0x4c] = 0;
    puVar26[0x4d] = 1;
    puVar26[0x60] = 0;
    puVar26[0x61] = 1;
    puVar26[0x74] = 0;
    puVar26[0x75] = 1;
    puVar26[0x88] = 0;
    puVar26[0x89] = 1;
    puVar26[0x9c] = 0;
    puVar26[0x9d] = 1;
    puVar26[0xb0] = 0;
    puVar26[0xb1] = 1;
    puVar26[0xc4] = 0;
    puVar26[0xc5] = 1;
    puVar26[0xd8] = 0;
    puVar26[0xd9] = 1;
    puVar26[0xec] = 0;
    puVar26[0xed] = 1;
    puVar26[0x100] = 0;
    puVar26[0x101] = 1;
    puVar26[0x114] = 0;
    puVar26[0x115] = 1;
    puVar26[0x128] = 0;
    puVar26[0x129] = 1;
    puVar26[0x13c] = 0;
    puVar26[0x13d] = 1;
    puVar26 = puVar26 + 0x140;
    iVar16 = iVar16 + 0x10;
    iVar27 = iVar27 + -1;
  } while (iVar27 != 0);
  puVar26 = &DAT_8038eba8 + iVar16 * 0x14;
  iVar27 = 0x21 - iVar16;
  if (iVar16 < 0x21) {
    do {
      puVar26[0x10] = 0;
      puVar26[0x11] = 1;
      puVar26 = puVar26 + 0x14;
      iVar27 = iVar27 + -1;
    } while (iVar27 != 0);
  }
  FUN_8025b210();
  FUN_800177bc(uVar15 & 0xff);
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006dc08
 * EN v1.0 Address: 0x8006DC08
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x8006EEA0
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 FUN_8006dc08(uint param_1,undefined param_2)
{
  uint uVar1;
  undefined2 *puVar2;
  
  puVar2 = &DAT_8030f470;
  if ((param_1 & 0xff) < 0x23) {
    uVar1 = (uint)(byte)(&DAT_8030f524)[param_1 & 0xff];
  }
  else {
    uVar1 = 0;
  }
  switch(param_2) {
  default:
    puVar2 = &DAT_8030f498;
    break;
  case 1:
    break;
  case 3:
    puVar2 = &DAT_8030f484;
    break;
  case 4:
    puVar2 = &DAT_8030f4ac;
    break;
  case 5:
    puVar2 = &DAT_8030f4d4;
    break;
  case 6:
    puVar2 = &DAT_8030f4c0;
    break;
  case 7:
    puVar2 = &DAT_8030f498;
    break;
  case 8:
    puVar2 = &DAT_8030f4e8;
    break;
  case 9:
    puVar2 = &DAT_8030f510;
    break;
  case 10:
    puVar2 = &DAT_8030f4fc;
  }
  return puVar2[uVar1];
}

/*
 * --INFO--
 *
 * Function: FUN_8006dca8
 * EN v1.0 Address: 0x8006DCA8
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x8006EF48
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006dca8(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,int param_6,int param_7)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined8 extraout_f1;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined auStack_48 [19];
  undefined auStack_35 [8];
  char local_2d;
  
  uVar5 = FUN_80286840();
  iVar1 = (int)uVar5;
  uVar4 = extraout_f1;
  FUN_800033a8((int)auStack_48,0,0x1c);
  uVar2 = 0;
  iVar3 = 8;
  do {
    if ((iVar1 >> (uVar2 & 0x3f) & 1U) != 0) {
      auStack_35[local_2d] = (char)uVar2;
      local_2d = local_2d + '\x01';
    }
    if ((iVar1 >> (uVar2 + 1 & 0x3f) & 1U) != 0) {
      auStack_35[local_2d] = (char)(uVar2 + 1);
      local_2d = local_2d + '\x01';
    }
    if ((iVar1 >> (uVar2 + 2 & 0x3f) & 1U) != 0) {
      auStack_35[local_2d] = (char)(uVar2 + 2);
      local_2d = local_2d + '\x01';
    }
    if ((iVar1 >> (uVar2 + 3 & 0x3f) & 1U) != 0) {
      auStack_35[local_2d] = (char)(uVar2 + 3);
      local_2d = local_2d + '\x01';
    }
    uVar2 = uVar2 + 4;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  FUN_8006ef38(uVar4,param_2,(int)((ulonglong)uVar5 >> 0x20),auStack_48,param_5,param_6,param_7);
  FUN_8028688c();
  return;
}

/* sda21 accessors. */
extern u32 lbl_803DCFD4;
extern u32 lbl_803DCF7C;
extern u32 lbl_803DCF94;
extern u32 lbl_803DCF98;
extern u32 lbl_803DCF90;
u32 fn_8006C5C4(void) { return lbl_803DCFD4; }
u32 getLastRenderedFrame(void) { return lbl_803DCF7C; }
u32 getTextureFn_8006c744(void) { return lbl_803DCF94; }
u32 fn_8006C74C(void) { return lbl_803DCF98; }
u32 fn_8006C754(void) { return lbl_803DCF90; }

/* Pattern wrappers. */
extern u32 lbl_803DCFC4;
extern u32 lbl_803DCFC8;
extern u32 lbl_803DCFB0;
extern u32 lbl_803DCFB4;
extern u32 lbl_803DCFB8;
extern u32 lbl_803DCFBC;
extern u32 lbl_803DCFC0;
extern u32 lbl_803DCF9C;
extern u32 lbl_803DCFD8;
extern u32 lbl_803DCFDC;
extern u32 lbl_803DCFE0;
void fn_8006C4F8(u32 *p) { *p = lbl_803DCFC4; }
void fn_8006C504(u32 *p) { *p = lbl_803DCFC8; }
void fn_8006C510(u32 *p) { *p = lbl_803DCFB0; }
void fn_8006C51C(u32 *p) { *p = lbl_803DCFB4; }
void fn_8006C528(u32 *p) { *p = lbl_803DCFB8; }
void fn_8006C534(u32 *p) { *p = lbl_803DCFBC; }
void fn_8006C540(u32 *p) { *p = lbl_803DCFC0; }
void fn_8006C5B8(u32 *p) { *p = lbl_803DCF9C; }
void fn_8006C5CC(u32 *p) { *p = lbl_803DCFD8; }
void getReflectionTexture2(u32 *p) { *p = lbl_803DCFDC; }
void getTextureFn_8006c5e4(u32 *p) { *p = lbl_803DCFE0; }

/* *p1 = lbl1; *p2 = lbl2; (f32) */
extern f32 lbl_803DCFAC;
extern f32 lbl_803DCFA8;
void fn_8006CABC(f32 *p1, f32 *p2) { *p1 = lbl_803DCFAC; *p2 = lbl_803DCFA8; }

/* misc 8b leaves */
extern f32 lbl_803DCFA4;
f32 fn_8006C670(void) { return lbl_803DCFA4; }

/* fn_X(lbl); lbl = 0; */
extern void mm_free(u32);
#pragma scheduling off
#pragma peephole off
void fn_8006CB24(void) { mm_free(lbl_803DCFBC); lbl_803DCFBC = 0; }
#pragma peephole reset
#pragma scheduling reset
