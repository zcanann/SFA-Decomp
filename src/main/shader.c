#include "ghidra_import.h"
#include "main/shader.h"

extern float ABS();
extern undefined4 FUN_800033a8();
extern undefined8 FUN_80006724();
extern undefined4 FUN_80006728();
extern undefined4 FUN_80006770();
extern undefined4 FUN_800068b8();
extern undefined4 FUN_800068d8();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_8000693c();
extern undefined4 FUN_80006958();
extern undefined4 FUN_8000696c();
extern void* FUN_800069a8();
extern undefined8 FUN_80006a88();
extern undefined4 FUN_80006adc();
extern undefined8 FUN_80006c1c();
extern undefined4 FUN_80006c28();
extern undefined4 FUN_80017488();
extern undefined8 FUN_800174b8();
extern undefined8 FUN_80017630();
extern undefined8 FUN_80017640();
extern undefined8 FUN_80017644();
extern undefined4 FUN_800176a8();
extern undefined4 FUN_8001771c();
extern undefined8 FUN_80017810();
extern undefined8 FUN_80017814();
extern undefined4 FUN_80017830();
extern undefined4 FUN_800178bc();
extern int FUN_80017a98();
extern undefined4 FUN_80017aa0();
extern undefined8 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern int FUN_80017b00();
extern undefined4 FUN_80017b10();
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_80040d88();
extern undefined8 FUN_80040d94();
extern int FUN_80042830();
extern int FUN_80042838();
extern undefined4 FUN_80042f88();
extern int FUN_800443cc();
extern undefined8 FUN_800443fc();
extern int FUN_80044404();
extern undefined8 FUN_80044424();
extern undefined4 FUN_80044428();
extern undefined8 FUN_80044f74();
extern uint FUN_800452f8();
extern undefined8 FUN_80045328();
extern undefined4 FUN_80045c4c();
extern undefined8 FUN_8004600c();
extern undefined4 FUN_80053754();
extern undefined4 FUN_80053758();
extern undefined4 FUN_80053c9c();
extern uint FUN_80053f60();
extern undefined4 FUN_800600f4();
extern undefined8 FUN_800601e4();
extern undefined4 FUN_800602d4();
extern undefined4 FUN_800604ac();
extern undefined4 FUN_8006069c();
extern undefined4 FUN_800614d0();
extern undefined8 FUN_800627a0();
extern undefined4 FUN_800632cc();
extern void trackDolphin_initIntersectionBuffers(void);
extern undefined8 FUN_8006f564();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_80080f28();
extern undefined4 FUN_80080f3c();
extern int FUN_800e83c8();
extern int FUN_800e87a0();
extern void* FUN_800e87a8();
extern undefined4 FUN_800e8b48();
extern undefined4 FUN_800e8b54();
extern int FUN_800e9b14();
extern undefined8 FUN_800e9c00();
extern undefined4 FUN_80130150();
extern undefined4 FUN_8013028c();
extern undefined4 FUN_80130298();
extern undefined4 FUN_80132550();
extern undefined4 FUN_80135814();
extern undefined4 FUN_80242114();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247edc();
extern double FUN_80247f90();
extern undefined8 FUN_8028681c();
extern undefined8 FUN_80286820();
extern undefined4 FUN_8028682c();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286868();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802924c4();

extern undefined4 DAT_802c25d8;
extern undefined4 DAT_802c25dc;
extern undefined4 DAT_802c25e0;
extern undefined4 DAT_802c25e4;
extern undefined4 DAT_802c25e8;
extern undefined4 DAT_802c25ec;
extern undefined4 DAT_802c25f0;
extern undefined4 DAT_802c25f4;
extern undefined4 DAT_802c25f8;
extern undefined4 DAT_802c25fc;
extern undefined4 DAT_802c2600;
extern undefined4 DAT_802c2604;
extern undefined4 DAT_802c2608;
extern undefined4 DAT_802c260c;
extern undefined4 DAT_802c2610;
extern undefined4 DAT_802c2614;
extern undefined4 DAT_802c2618;
extern undefined4 DAT_802c261c;
extern undefined4 DAT_802c2620;
extern undefined4 DAT_802c2624;
extern undefined4 DAT_8030f11c;
extern undefined4 DAT_8030f194;
extern undefined4 DAT_80382e98;
extern short* DAT_80382e9c;
extern undefined4 DAT_80382ea0;
extern char* DAT_80382ea4;
extern undefined4 DAT_80382ea8;
extern int DAT_80382eac;
extern undefined4 DAT_80382eb0;
extern undefined4 DAT_80382eb2;
extern int DAT_80382eec;
extern int DAT_80382f00;
extern int DAT_80382f14;
extern undefined4 DAT_80382fb0;
extern uint DAT_803870c8;
extern int DAT_80387208;
extern undefined4 DAT_803872a8;
extern undefined4 DAT_803872ac;
extern undefined4 DAT_803872b0;
extern undefined4 DAT_803872b4;
extern undefined4 DAT_803872c4;
extern undefined4 DAT_803872d4;
extern undefined4 DAT_803872e4;
extern undefined4 DAT_803872f4;
extern undefined4 DAT_80387304;
extern undefined4 DAT_80387314;
extern undefined4 DAT_80387324;
extern undefined4 DAT_80387334;
extern undefined4 DAT_80387344;
extern undefined4 DAT_80387354;
extern undefined4 DAT_80387364;
extern undefined4 DAT_80387374;
extern undefined4 DAT_80387384;
extern undefined4 DAT_80387394;
extern undefined4 DAT_803873a4;
extern undefined4 DAT_803873b4;
extern undefined4 DAT_803873c4;
extern undefined4 DAT_803873d4;
extern undefined4 DAT_803873e4;
extern undefined4 DAT_803873f4;
extern undefined4 DAT_80387404;
extern undefined4 DAT_80387414;
extern undefined4 DAT_80387424;
extern undefined4 DAT_80387434;
extern undefined4 DAT_80387444;
extern undefined4 DAT_80387454;
extern undefined4 DAT_80387464;
extern undefined4 DAT_80387474;
extern undefined4 DAT_80387484;
extern undefined4 DAT_80388538;
extern undefined4 DAT_8038859c;
extern undefined4 DAT_803885a0;
extern undefined4 DAT_803885a4;
extern undefined4 DAT_803885a8;
extern undefined4 DAT_803dc280;
extern undefined4 DAT_803dc284;
extern undefined4 DAT_803dc2a8;
extern undefined4 DAT_803dd5d0;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6dc;
extern undefined4* DAT_803dd6e0;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd6ec;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd700;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803dda48;
extern undefined4 DAT_803dda4c;
extern undefined4 DAT_803dda50;
extern undefined4 DAT_803dda54;
extern undefined4 DAT_803dda60;
extern undefined4 DAT_803dda61;
extern int* DAT_803dda64;
extern undefined4 DAT_803dda68;
extern undefined4 DAT_803dda6c;
extern undefined4 DAT_803dda6d;
extern undefined4 DAT_803dda74;
extern undefined4 DAT_803dda77;
extern undefined4 DAT_803dda80;
extern undefined4 DAT_803dda84;
extern undefined4 DAT_803dda9c;
extern undefined4 DAT_803ddae8;
extern int* DAT_803ddaec;
extern undefined4 DAT_803ddaf0;
extern undefined4 DAT_803ddaf4;
extern short* DAT_803ddaf8;
extern undefined4 DAT_803ddafc;
extern undefined4 DAT_803ddb04;
extern undefined4 DAT_803ddb08;
extern undefined4 DAT_803ddb0c;
extern undefined4 DAT_803ddb10;
extern short* DAT_803ddb14;
extern undefined4 DAT_803ddb18;
extern undefined4 DAT_803ddb1c;
extern undefined4 DAT_803ddb20;
extern undefined4 DAT_803ddb24;
extern undefined4 DAT_803ddb28;
extern undefined4 DAT_803ddb30;
extern undefined4 DAT_803ddb34;
extern undefined4 DAT_803ddb36;
extern undefined4 DAT_803ddb38;
extern undefined4 DAT_803ddb3d;
extern undefined4 DAT_803ddb40;
extern undefined4 DAT_803ddb44;
extern undefined4 DAT_803ddb48;
extern f64 DOUBLE_803df840;
extern f32 FLOAT_803dc28c;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803ddadc;
extern f32 FLOAT_803ddae0;
extern f32 FLOAT_803ddae4;
extern f32 FLOAT_803ddb4c;
extern f32 FLOAT_803ddb50;
extern f32 FLOAT_803df834;
extern f32 FLOAT_803df838;
extern f32 FLOAT_803df848;
extern f32 FLOAT_803df84c;
extern f32 FLOAT_803df850;
extern f32 FLOAT_803df854;
extern f32 FLOAT_803df858;
extern f32 FLOAT_803df85c;
extern f32 FLOAT_803df860;
extern f32 FLOAT_803df864;
extern f32 FLOAT_803df868;
extern f32 FLOAT_803df86c;
extern f32 FLOAT_803df870;
extern f32 FLOAT_803df874;
extern undefined cRam803dc285;
extern undefined2 cRam803dc286;
extern undefined cRam803dc287;
extern undefined4 cRam803dc288;

/*
 * --INFO--
 *
 * Function: FUN_80055980
 * EN v1.0 Address: 0x80055980
 * EN v1.0 Size: 908b
 * EN v1.1 Address: 0x80055AFC
 * EN v1.1 Size: 932b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80055980(undefined4 param_1,undefined4 param_2,undefined4 param_3)
{
  bool bVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  bool bVar6;
  int iVar7;
  uint uVar8;
  int *piVar9;
  int iVar10;
  char extraout_r4;
  char cVar11;
  double dVar12;
  double in_f29;
  double in_f30;
  double in_f31;
  undefined8 local_58;
  
  iVar7 = FUN_80286840();
  bVar1 = *(int *)(iVar7 + 0x14) == 0x49054;
  uVar8 = (**(code **)(*DAT_803dd72c + 0x40))(param_3);
  uVar8 = uVar8 & 0xff;
  if (uVar8 == 0xffffffff) {
    bVar6 = false;
    goto LAB_80055bd4;
  }
  if (uVar8 == 0) {
LAB_80055bd0:
    bVar6 = true;
  }
  else if (uVar8 < 9) {
    if (((int)(uint)*(byte *)(iVar7 + 3) >> (uVar8 - 1 & 0x3f) & 1U) == 0) goto LAB_80055bd0;
    bVar6 = false;
  }
  else {
    if (((int)(uint)*(byte *)(iVar7 + 5) >> (0x10 - uVar8 & 0x3f) & 1U) == 0) goto LAB_80055bd0;
    bVar6 = false;
  }
LAB_80055bd4:
  if (bVar6) {
    if ((*(byte *)(iVar7 + 4) & 1) == 0) {
      if ((*(byte *)(iVar7 + 4) & 2) == 0) {
        if (extraout_r4 == '\0') {
          dVar12 = (double)FUN_802924c4();
          iVar10 = (int)dVar12;
          dVar12 = (double)FUN_802924c4();
          iVar2 = (int)dVar12;
          if ((((iVar10 < 0) || (iVar2 < 0)) || (0xf < iVar10)) || (0xf < iVar2)) {
            if (bVar1) {
              FUN_800723a0();
            }
            goto LAB_80055e70;
          }
          bVar6 = false;
          piVar9 = &DAT_80382f14;
          for (cVar11 = '\0'; cVar11 < '\x05'; cVar11 = cVar11 + '\x01') {
            if (-1 < *(char *)(iVar10 + iVar2 * 0x10 + *piVar9)) {
              bVar6 = true;
            }
            piVar9 = piVar9 + 1;
          }
          if (!bVar6) {
            if (bVar1) {
              FUN_800723a0();
            }
            goto LAB_80055e70;
          }
        }
        if ((*(byte *)(iVar7 + 4) & 0x20) == 0) {
          bVar6 = false;
          if (((*(byte *)(iVar7 + 4) & 4) == 0) || (extraout_r4 != '\0')) {
            bVar6 = true;
          }
          else {
            iVar10 = FUN_80017a98();
            if (iVar10 == 0) {
              bVar6 = true;
            }
            else {
              in_f29 = (double)*(float *)(iVar10 + 0x18);
              in_f31 = (double)*(float *)(iVar10 + 0x1c);
              in_f30 = (double)*(float *)(iVar10 + 0x20);
            }
          }
          if (bVar6) {
            iVar10 = (int)extraout_r4;
            in_f29 = (double)(float)(&DAT_803872a8)[iVar10 * 4];
            in_f31 = (double)(float)(&DAT_803872ac)[iVar10 * 4];
            in_f30 = (double)(float)(&DAT_803872b0)[iVar10 * 4];
          }
          local_58 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar7 + 6) << 3 ^ 0x80000000);
          fVar3 = (float)(in_f29 - (double)*(float *)(iVar7 + 8));
          fVar4 = (float)(in_f31 - (double)*(float *)(iVar7 + 0xc));
          fVar5 = (float)(in_f30 - (double)*(float *)(iVar7 + 0x10));
          if ((float)(local_58 - DOUBLE_803df840) * (float)(local_58 - DOUBLE_803df840) <=
              fVar5 * fVar5 + fVar4 * fVar4 + fVar3 * fVar3) {
            if (bVar1) {
              FUN_800723a0();
            }
          }
          else if (bVar1) {
            FUN_800723a0();
          }
        }
        else if (bVar1) {
          FUN_800723a0();
        }
      }
      else if (bVar1) {
        FUN_800723a0();
      }
    }
    else if (bVar1) {
      FUN_800723a0();
    }
  }
LAB_80055e70:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80055d0c
 * EN v1.0 Address: 0x80055D0C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80055EA0
 * EN v1.1 Size: 1912b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80055d0c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80055d10
 * EN v1.0 Address: 0x80055D10
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x80056618
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80055d10(void)
{
  int iVar1;
  int *piVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  float local_28;
  float local_24;
  float local_20;
  int local_1c [7];
  
  FUN_80286840();
  piVar2 = ObjGroup_GetObjects(6,local_1c);
  psVar3 = FUN_800069a8();
  FUN_800068d8(psVar3);
  DAT_803872c4 = 0;
  DAT_803872d4 = 0;
  DAT_803872e4 = 0;
  DAT_803872f4 = 0;
  DAT_80387304 = 0;
  DAT_80387314 = 0;
  DAT_80387324 = 0;
  DAT_80387334 = 0;
  DAT_80387344 = 0;
  DAT_80387354 = 0;
  DAT_80387364 = 0;
  DAT_80387374 = 0;
  DAT_80387384 = 0;
  DAT_80387394 = 0;
  DAT_803873a4 = 0;
  DAT_803873b4 = 0;
  DAT_803873c4 = 0;
  DAT_803873d4 = 0;
  DAT_803873e4 = 0;
  DAT_803873f4 = 0;
  DAT_80387404 = 0;
  DAT_80387414 = 0;
  DAT_80387424 = 0;
  DAT_80387434 = 0;
  DAT_80387444 = 0;
  DAT_80387454 = 0;
  DAT_80387464 = 0;
  DAT_80387474 = 0;
  DAT_80387484 = 0;
  iVar4 = -0x7fc78b78;
  iVar1 = 1;
  do {
    *(undefined4 *)(iVar4 + 0xc) = 0;
    iVar4 = iVar4 + 0x10;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  DAT_803872a8 = *(undefined4 *)(psVar3 + 0x22);
  DAT_803872ac = *(undefined4 *)(psVar3 + 0x24);
  DAT_803872b0 = *(undefined4 *)(psVar3 + 0x26);
  DAT_803872b4 = 1;
  for (iVar1 = 0; iVar1 < local_1c[0]; iVar1 = iVar1 + 1) {
    iVar4 = *piVar2;
    iVar5 = *(char *)(iVar4 + 0x35) + 1;
    if (*(int *)(psVar3 + 0x20) == iVar4) {
      (&DAT_803872a8)[iVar5 * 4] = *(undefined4 *)(psVar3 + 6);
      (&DAT_803872ac)[iVar5 * 4] = *(undefined4 *)(psVar3 + 8);
      (&DAT_803872b0)[iVar5 * 4] = *(undefined4 *)(psVar3 + 10);
    }
    else {
      FUN_800068f4((double)*(float *)(psVar3 + 0x22),(double)*(float *)(psVar3 + 0x24),
                   (double)*(float *)(psVar3 + 0x26),&local_20,&local_24,&local_28,iVar4);
      (&DAT_803872a8)[iVar5 * 4] = local_20;
      (&DAT_803872ac)[iVar5 * 4] = local_24;
      (&DAT_803872b0)[iVar5 * 4] = local_28;
    }
    (&DAT_803872b4)[iVar5 * 4] = 1;
    piVar2 = piVar2 + 1;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80056800
 * EN v1.0 Address: 0x80055ED8
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80056800
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_80056800(int param_1)
{
  return (int)(DAT_803ddaec + param_1 * 4);
}

/*
 * --INFO--
 *
 * Function: FUN_80055ee8
 * EN v1.0 Address: 0x80055EE8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80056810
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80055ee8(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80055ef0
 * EN v1.0 Address: 0x80055EF0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80056818
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80055ef0(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80055ef8
 * EN v1.0 Address: 0x80055EF8
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x80056820
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80055ef8(int param_1,uint param_2)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar2 = 0;
  iVar4 = 0x28;
  do {
    piVar1 = (int *)(DAT_803ddaec + iVar2);
    if (((*piVar1 == param_1) && (param_2 == *(byte *)((int)piVar1 + 0xe))) &&
       (0 < *(short *)(piVar1 + 3))) {
      *(short *)(piVar1 + 3) = *(short *)(piVar1 + 3) + -1;
      if (*(short *)(DAT_803ddaec + iVar2 + 0xc) == 0) {
        *(undefined4 *)(DAT_803ddaec + iVar2 + 4) = 0;
        *(undefined *)(DAT_803ddaec + iVar2 + 0xe) = 0;
        *(undefined4 *)(DAT_803ddaec + iVar2) = 0;
        *(undefined4 *)(DAT_803ddaec + iVar2 + 8) = 0;
      }
    }
    iVar3 = iVar2 + 0x10;
    piVar1 = (int *)(DAT_803ddaec + iVar3);
    if (((*piVar1 == param_1) && (param_2 == *(byte *)((int)piVar1 + 0xe))) &&
       (0 < *(short *)(piVar1 + 3))) {
      *(short *)(piVar1 + 3) = *(short *)(piVar1 + 3) + -1;
      if (*(short *)(DAT_803ddaec + iVar3 + 0xc) == 0) {
        *(undefined4 *)(DAT_803ddaec + iVar3 + 4) = 0;
        *(undefined *)(DAT_803ddaec + iVar2 + 0x1e) = 0;
        *(undefined4 *)(DAT_803ddaec + iVar3) = 0;
        *(undefined4 *)(DAT_803ddaec + iVar2 + 0x18) = 0;
      }
    }
    iVar2 = iVar2 + 0x20;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056000
 * EN v1.0 Address: 0x80056000
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x80056924
 * EN v1.1 Size: 708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80056000(int param_1,int param_2,uint param_3)
{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = 0;
  iVar4 = 0x10;
  piVar2 = DAT_803ddaec;
  do {
    if ((((*(short *)(piVar2 + 3) != 0) && (*piVar2 == param_1)) &&
        (iVar1 = iVar3, param_3 == *(byte *)((int)piVar2 + 0xe))) ||
       ((((((iVar1 = iVar3 + 1, *(short *)(piVar2 + 7) != 0 && (piVar2[4] == param_1)) &&
           (param_3 == *(byte *)((int)piVar2 + 0x1e))) ||
          (((iVar1 = iVar3 + 2, *(short *)(piVar2 + 0xb) != 0 && (piVar2[8] == param_1)) &&
           (param_3 == *(byte *)((int)piVar2 + 0x2e))))) ||
         (((iVar1 = iVar3 + 3, *(short *)(piVar2 + 0xf) != 0 && (piVar2[0xc] == param_1)) &&
          (param_3 == *(byte *)((int)piVar2 + 0x3e))))) ||
        (((*(short *)(piVar2 + 0x13) != 0 && (piVar2[0x10] == param_1)) &&
         (iVar1 = iVar3 + 4, param_3 == *(byte *)((int)piVar2 + 0x4e))))))) break;
    piVar2 = piVar2 + 0x14;
    iVar3 = iVar3 + 5;
    iVar4 = iVar4 + -1;
    iVar1 = -1;
  } while (iVar4 != 0);
  if (iVar1 == -1) {
    iVar3 = 0;
    iVar4 = 8;
    piVar2 = DAT_803ddaec;
    do {
      iVar1 = iVar3;
      if (((((*(short *)(piVar2 + 3) == 0) || (iVar1 = iVar3 + 1, *(short *)(piVar2 + 7) == 0)) ||
           ((iVar1 = iVar3 + 2, *(short *)(piVar2 + 0xb) == 0 ||
            ((((iVar1 = iVar3 + 3, *(short *)(piVar2 + 0xf) == 0 ||
               (iVar1 = iVar3 + 4, *(short *)(piVar2 + 0x13) == 0)) ||
              (iVar1 = iVar3 + 5, *(short *)(piVar2 + 0x17) == 0)) ||
             ((iVar1 = iVar3 + 6, *(short *)(piVar2 + 0x1b) == 0 ||
              (iVar1 = iVar3 + 7, *(short *)(piVar2 + 0x1f) == 0)))))))) ||
          (iVar1 = iVar3 + 8, *(short *)(piVar2 + 0x23) == 0)) ||
         (iVar1 = iVar3 + 9, *(short *)(piVar2 + 0x27) == 0)) break;
      piVar2 = piVar2 + 0x28;
      iVar3 = iVar3 + 10;
      iVar4 = iVar4 + -1;
      iVar1 = -1;
    } while (iVar4 != 0);
    if (iVar1 == -1) {
      FUN_800723a0();
      iVar1 = 0;
    }
    else {
      *(undefined2 *)(DAT_803ddaec + iVar1 * 4 + 3) = 1;
      DAT_803ddaec[iVar1 * 4 + 1] = 0;
      DAT_803ddaec[iVar1 * 4 + 2] = param_2;
      DAT_803ddaec[iVar1 * 4] = param_1;
      *(char *)((int)DAT_803ddaec + iVar1 * 0x10 + 0xe) = (char)param_3;
    }
  }
  else {
    *(short *)(DAT_803ddaec + iVar1 * 4 + 3) = *(short *)(DAT_803ddaec + iVar1 * 4 + 3) + 1;
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_800562d0
 * EN v1.0 Address: 0x800562D0
 * EN v1.0 Size: 280b
 * EN v1.1 Address: 0x80056BE8
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800562d0(uint param_1,int param_2,int param_3)
{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  iVar1 = 0;
  iVar3 = 0x10;
  do {
    piVar2 = (int *)(DAT_803ddaec + iVar1);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    piVar2 = (int *)(DAT_803ddaec + iVar1 + 0x10);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    piVar2 = (int *)(DAT_803ddaec + iVar1 + 0x20);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    piVar2 = (int *)(DAT_803ddaec + iVar1 + 0x30);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    piVar2 = (int *)(DAT_803ddaec + iVar1 + 0x40);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    iVar1 = iVar1 + 0x50;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800563e8
 * EN v1.0 Address: 0x800563E8
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80056D08
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800563e8(int param_1,float *param_2,float *param_3)
{
  float fVar1;
  
  fVar1 = FLOAT_803df848;
  *param_2 = *(float *)(DAT_803ddae8 + param_1 * 0x10) / FLOAT_803df848;
  *param_3 = *(float *)(DAT_803ddae8 + param_1 * 0x10 + 4) / fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056418
 * EN v1.0 Address: 0x80056418
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80056D38
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056418(int param_1,int param_2,int param_3,int param_4,int param_5)
{
  int iVar1;
  
  iVar1 = DAT_803ddae8 + param_1 * 0x10;
  *(short *)(iVar1 + 8) = (short)((param_2 << 0x10) / (param_4 >> 6));
  *(short *)(iVar1 + 10) = (short)((param_3 << 0x10) / (param_5 >> 6));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056448
 * EN v1.0 Address: 0x80056448
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x80056D70
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80056448(int param_1,int param_2,int param_3,int param_4)
{
  float fVar1;
  int iVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar4 = 0;
  iVar6 = 0x3a;
  iVar2 = DAT_803ddae8;
  do {
    if ((*(short *)(iVar2 + 8) == param_1) && (*(short *)(iVar2 + 10) == param_2)) {
      *(char *)(iVar2 + 0xc) = *(char *)(iVar2 + 0xc) + '\x01';
      return iVar4;
    }
    iVar2 = iVar2 + 0x10;
    iVar4 = iVar4 + 1;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  iVar4 = 0;
  iVar6 = 0x1d;
  iVar2 = DAT_803ddae8;
  do {
    iVar5 = iVar4;
    if ((*(char *)(iVar2 + 0xc) == '\0') || (iVar5 = iVar4 + 1, *(char *)(iVar2 + 0x1c) == '\0'))
    break;
    iVar2 = iVar2 + 0x20;
    iVar4 = iVar4 + 2;
    iVar6 = iVar6 + -1;
    iVar5 = -1;
  } while (iVar6 != 0);
  if (iVar5 != -1) {
    pfVar3 = (float *)(DAT_803ddae8 + iVar5 * 0x10);
    *(short *)(pfVar3 + 2) = (short)((param_1 << 0x10) / (param_3 >> 6));
    *(short *)((int)pfVar3 + 10) = (short)((param_2 << 0x10) / (param_4 >> 6));
    fVar1 = FLOAT_803df84c;
    *pfVar3 = FLOAT_803df84c;
    pfVar3[1] = fVar1;
    *(char *)(pfVar3 + 3) = *(char *)(pfVar3 + 3) + '\x01';
    return iVar5;
  }
  return -1;
}

/*
 * --INFO--
 *
 * Function: FUN_8005652c
 * EN v1.0 Address: 0x8005652C
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x80056E68
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005652c(undefined4 param_1,undefined4 param_2,int param_3,int param_4)
{
  undefined4 uVar1;
  short *psVar2;
  short extraout_r4;
  uint uVar3;
  uint uVar4;
  
  uVar1 = FUN_80286840();
  uVar3 = 0;
  uVar4 = (uint)DAT_803ddb18;
  for (psVar2 = DAT_803ddb14; (uVar4 != 0 && (*psVar2 != -1)); psVar2 = psVar2 + 1) {
    uVar3 = uVar3 + 1;
    uVar4 = uVar4 - 1;
  }
  if ((uVar3 == DAT_803ddb18) && (DAT_803ddb18 = DAT_803ddb18 + 1, DAT_803ddb18 == 0x40)) {
    FUN_800723a0();
  }
  *(char *)((&DAT_80382f14)[param_4] + param_3) = (char)uVar3;
  *(undefined4 *)(DAT_803ddb1c + uVar3 * 4) = uVar1;
  DAT_803ddb14[uVar3] = extraout_r4;
  *(undefined *)(DAT_803ddb0c + uVar3) = 1;
  FUN_800632cc();
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800565f8
 * EN v1.0 Address: 0x800565F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80056F48
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800565f8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 int param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800565fc
 * EN v1.0 Address: 0x800565FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800570F8
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800565fc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80056600
 * EN v1.0 Address: 0x80056600
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80057360
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80056600(void)
{
  return (int)DAT_803dda61;
}

/*
 * --INFO--
 *
 * Function: FUN_80056608
 * EN v1.0 Address: 0x80056608
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8005736C
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056608(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char param_9)
{
  if (((DAT_803ddb48 != -1) &&
      (((DAT_803ddb48 != DAT_803ddb44 || (param_9 != '\0')) &&
       (DAT_803ddb44 = DAT_803ddb48, DAT_803ddb48 < 0x76)))) &&
     ((char)(&DAT_8030f11c)[DAT_803ddb48] != -1)) {
    FUN_80017488(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)(char)(&DAT_8030f11c)[DAT_803ddb48]);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800566c8
 * EN v1.0 Address: 0x800566C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800573D4
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800566c8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800566cc
 * EN v1.0 Address: 0x800566CC
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x8005756C
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800566cc(void)
{
  DAT_803ddb24 = 0;
  DAT_803ddb36 = 0;
  DAT_803ddb34 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800566e0
 * EN v1.0 Address: 0x800566E0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80057580
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800566e0(void)
{
  return (int)DAT_803ddb24;
}

/*
 * --INFO--
 *
 * Function: FUN_800566e8
 * EN v1.0 Address: 0x800566E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8005758C
 * EN v1.1 Size: 2324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800566e8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800566ec
 * EN v1.0 Address: 0x800566EC
 * EN v1.0 Size: 776b
 * EN v1.1 Address: 0x80057EA0
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800566ec(int param_1,int param_2,int *param_3,int *param_4,int *param_5,int *param_6,
                 int param_7,int param_8,int param_9)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  short *psVar5;
  short *psVar6;
  
  if (param_9 != -1) {
    psVar5 = (short *)(DAT_80382e9c + (short)(&DAT_80382eb0)[param_9 * 4] * 10);
    psVar6 = (short *)(&DAT_80382eac)[param_9 * 2];
    if (param_9 != -1) {
      if (param_8 == 0) {
        iVar2 = *(int *)(psVar6 + 10);
        iVar3 = *(int *)(psVar6 + 0x16);
      }
      else {
        iVar2 = *(int *)(psVar6 + 0x18);
        iVar3 = *(int *)(psVar6 + 0x1a);
      }
      uVar1 = (param_1 - *psVar5) + (param_2 - psVar5[2]) * (int)*psVar6;
      if (param_7 == 0) {
        uVar4 = *(uint *)(iVar2 + uVar1 * 8);
        *param_3 = (uVar4 >> 0xc & 0xf) - 7;
        param_3[2] = (uVar4 >> 8 & 0xf) - 7;
        param_3[1] = (uVar4 >> 4 & 0xf) - 7;
        param_3[3] = (uVar4 & 0xf) - 7;
        *param_4 = (uVar4 >> 0x1c) - 7;
        param_4[2] = (uVar4 >> 0x18 & 0xf) - 7;
        param_4[1] = (uVar4 >> 0x14 & 0xf) - 7;
        param_4[3] = (uVar4 >> 0x10 & 0xf) - 7;
        uVar1 = *(uint *)(iVar2 + uVar1 * 8 + 4);
        *param_5 = (uVar1 >> 0xc & 0xf) - 7;
        param_5[2] = (uVar1 >> 8 & 0xf) - 7;
        param_5[1] = (uVar1 >> 4 & 0xf) - 7;
        param_5[3] = (uVar1 & 0xf) - 7;
        *param_6 = (uVar1 >> 0x1c) - 7;
        param_6[2] = (uVar1 >> 0x18 & 0xf) - 7;
        param_6[1] = (uVar1 >> 0x14 & 0xf) - 7;
        param_6[3] = (uVar1 >> 0x10 & 0xf) - 7;
      }
      else {
        *param_3 = 0;
        param_3[1] = -1;
        param_3[2] = 0;
        param_3[3] = -1;
        *param_4 = 0;
        param_4[1] = -1;
        param_4[2] = 0;
        param_4[3] = -1;
        *param_5 = 0;
        param_5[1] = -1;
        param_5[2] = 0;
        param_5[3] = -1;
        *param_6 = 0;
        param_6[1] = -1;
        param_6[2] = 0;
        param_6[3] = -1;
        uVar1 = *(uint *)(*(int *)(psVar6 + 6) + ((int)(uVar1 * 2 | uVar1 >> 0x1f) >> 1) * 4) & 0x7f
        ;
        if (uVar1 != 0x7f) {
          uVar1 = *(uint *)(iVar3 + (param_7 + uVar1 * 4 + -1) * 4);
          *param_3 = (uVar1 >> 0xc & 0xf) - 7;
          param_3[2] = (uVar1 >> 8 & 0xf) - 7;
          param_3[1] = (uVar1 >> 4 & 0xf) - 7;
          param_3[3] = (uVar1 & 0xf) - 7;
          *param_4 = (uVar1 >> 0x1c) - 7;
          param_4[2] = (uVar1 >> 0x18 & 0xf) - 7;
          param_4[1] = (uVar1 >> 0x14 & 0xf) - 7;
          param_4[3] = (uVar1 >> 0x10 & 0xf) - 7;
        }
      }
    }
    else {
      *param_3 = -1;
      param_3[1] = 1;
      param_3[2] = -1;
      param_3[3] = 1;
      *param_4 = 0;
      param_4[1] = 0;
      param_4[2] = 0;
      param_4[3] = -1;
      *param_5 = 0;
      param_5[1] = 0;
      param_5[2] = 0;
      param_5[3] = -1;
      *param_6 = 0;
      param_6[1] = 0;
      param_6[2] = 0;
      param_6[3] = -1;
      if (param_7 != 0) {
        param_3[3] = -2;
      }
    }
  }
  else {
    *param_3 = -1;
    param_3[1] = 1;
    param_3[2] = -1;
    param_3[3] = 1;
    *param_4 = 0;
    param_4[1] = 0;
    param_4[2] = 0;
    param_4[3] = -1;
    *param_5 = 0;
    param_5[1] = 0;
    param_5[2] = 0;
    param_5[3] = -1;
    *param_6 = 0;
    param_6[1] = 0;
    param_6[2] = 0;
    param_6[3] = -1;
    if (param_7 != 0) {
      param_3[3] = -2;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800569f4
 * EN v1.0 Address: 0x800569F4
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x800581A8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800569f4(void)
{
  DAT_803dda61 = DAT_803dda61 + -1;
  if (DAT_803dda61 < -2) {
    DAT_803dda61 = -2;
  }
  DAT_803dda68 = DAT_803dda68 | 0x4000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056a20
 * EN v1.0 Address: 0x80056A20
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x800581DC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056a20(void)
{
  DAT_803dda61 = DAT_803dda61 + '\x01';
  if ('\x02' < DAT_803dda61) {
    DAT_803dda61 = '\x02';
  }
  DAT_803dda68 = DAT_803dda68 | 0x4000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056a4c
 * EN v1.0 Address: 0x80056A4C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80058210
 * EN v1.1 Size: 3144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056a4c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80056a50
 * EN v1.0 Address: 0x80056A50
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80058E58
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056a50(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  uint uVar2;
  
  if (((DAT_803dda68 & 2) == 0) || ((DAT_803dda68 & 0x800) != 0)) {
    FLOAT_803ddae4 = (float)param_1;
    FLOAT_803ddae0 = (float)param_2;
    FLOAT_803ddadc = (float)param_3;
    uVar2 = DAT_803dda68 | 2;
    uVar1 = DAT_803dda68 & 0x800;
    DAT_803dda68 = uVar2;
    if (uVar1 != 0) {
      FUN_80056a4c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056a88
 * EN v1.0 Address: 0x80056A88
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x80058EB8
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056a88(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,short param_11,short param_12,int param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  short *psVar2;
  short *psVar3;
  uint uVar4;
  short sVar5;
  short sVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  
  uVar7 = FUN_8028683c();
  psVar2 = DAT_803ddaf8;
  psVar3 = (short *)((ulonglong)uVar7 >> 0x20);
  iVar1 = param_13 * 0x1c;
  FUN_80017640(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803ddaf8,0x1d
               ,*(int *)(DAT_803ddafc + iVar1),
               *(int *)(DAT_803ddafc + iVar1 + 8) - *(int *)(DAT_803ddafc + iVar1),param_13,param_14
               ,param_15,param_16);
  *(int *)(psVar2 + 6) =
       (int)psVar2 + (*(int *)(DAT_803ddafc + iVar1 + 4) - *(int *)(DAT_803ddafc + iVar1));
  *psVar3 = param_11 - psVar2[2];
  psVar3[2] = param_12 - psVar2[3];
  psVar3[1] = *psVar3 + *psVar2 + -1;
  psVar3[3] = psVar3[2] + psVar2[1] + -1;
  *(char *)(psVar3 + 4) = (char)psVar2[2];
  *(char *)((int)psVar3 + 9) = (char)psVar2[3];
  for (sVar6 = 0; sVar6 < psVar2[1]; sVar6 = sVar6 + 1) {
    for (sVar5 = 0; (int)sVar5 < (int)*psVar2; sVar5 = sVar5 + 1) {
      uVar4 = (int)sVar5 + (int)sVar6 * (int)*psVar2;
      if ((*(uint *)(*(int *)(psVar2 + 6) + uVar4 * 4) >> 0x17 & 0xff) != 0xff) {
        *(byte *)((int)uVar7 + ((int)uVar4 >> 3)) =
             *(byte *)((int)uVar7 + ((int)uVar4 >> 3)) | (byte)(1 << (uVar4 & 7));
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056c88
 * EN v1.0 Address: 0x80056C88
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80059024
 * EN v1.1 Size: 1084b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056c88(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80056c8c
 * EN v1.0 Address: 0x80056C8C
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x80059460
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80056c8c(void)
{
  int iVar1;
  int iVar2;
  
  iVar2 = (int)*(short *)(DAT_80382f00 + 0x594);
  if (*(short *)(DAT_80382f00 + 0x594) < 0) {
    iVar2 = DAT_803dc2a8;
  }
  if (iVar2 < 0) {
    return 0;
  }
  iVar1 = (&DAT_803870c8)[iVar2];
  if (iVar1 == 0) {
    return 0;
  }
  DAT_803dc2a8 = iVar2;
  DAT_803ddb20 = iVar1;
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_80056cdc
 * EN v1.0 Address: 0x80056CDC
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x800594B0
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80056cdc(int param_1,int param_2)
{
  return DAT_80382f00 + (param_1 + param_2 * 0x10) * 0xc;
}

/*
 * --INFO--
 *
 * Function: FUN_80056cf4
 * EN v1.0 Address: 0x80056CF4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800594D0
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056cf4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined2 *param_11,int param_12)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80056cf8
 * EN v1.0 Address: 0x80056CF8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800597C0
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056cf8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80056cfc
 * EN v1.0 Address: 0x80056CFC
 * EN v1.0 Size: 844b
 * EN v1.1 Address: 0x800598A8
 * EN v1.1 Size: 804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056cfc(void)
{
  byte *pbVar1;
  short sVar2;
  bool bVar3;
  uint uVar4;
  uint *puVar5;
  uint *puVar6;
  int in_r6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  short *psVar10;
  int iVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_80286834();
  iVar11 = (int)((ulonglong)uVar12 >> 0x20);
  puVar6 = (uint *)uVar12;
  bVar3 = false;
  uVar7 = 0;
  psVar10 = *(short **)(iVar11 + 0x20);
  uVar9 = (uint)*(ushort *)(iVar11 + 8);
  if (uVar9 != 0) {
    iVar8 = 0;
    if (in_r6 == 0) {
      puVar6[0x21] = 0xffffffff;
      *puVar6 = 0xffffffff;
      puVar6[1] = 0xffffffff;
      puVar6[2] = 0xffffffff;
      puVar6[3] = 0xffffffff;
      puVar6[4] = 0xffffffff;
      puVar6[5] = 0xffffffff;
      puVar6[6] = 0xffffffff;
      puVar6[7] = 0xffffffff;
      puVar6[8] = 0xffffffff;
      puVar6[9] = 0xffffffff;
      puVar6[10] = 0xffffffff;
      puVar6[0xb] = 0xffffffff;
      puVar6[0xc] = 0xffffffff;
      puVar6[0xd] = 0xffffffff;
      puVar6[0xe] = 0xffffffff;
      puVar6[0xf] = 0xffffffff;
      puVar6[0x10] = 0xffffffff;
      puVar6[0x11] = 0xffffffff;
      puVar6[0x12] = 0xffffffff;
      puVar6[0x13] = 0xffffffff;
      puVar6[0x14] = 0xffffffff;
      puVar6[0x15] = 0xffffffff;
      puVar6[0x16] = 0xffffffff;
      puVar6[0x17] = 0xffffffff;
      puVar6[0x18] = 0xffffffff;
      puVar6[0x19] = 0xffffffff;
      puVar6[0x1a] = 0xffffffff;
      puVar6[0x1b] = 0xffffffff;
      puVar6[0x1c] = 0xffffffff;
      puVar6[0x1d] = 0xffffffff;
      puVar6[0x1e] = 0xffffffff;
      puVar6[0x1f] = 0xffffffff;
    }
    for (; iVar8 < (int)uVar9; iVar8 = iVar8 + (uint)*pbVar1 * 4) {
      if (in_r6 == 0) {
        sVar2 = *psVar10;
        if ((sVar2 == 0x6e) || (sVar2 == 5)) {
          if (sVar2 == 0x6e) {
            (**(code **)(*DAT_803dd71c + 8))(psVar10);
          }
          else {
            (**(code **)(*DAT_803dd6ec + 8))(psVar10);
          }
          if (!bVar3) {
            puVar6[0x21] = (int)psVar10 - *(int *)(iVar11 + 0x20);
            bVar3 = true;
          }
        }
        else if (((*(byte *)(psVar10 + 2) & 0x10) != 0) &&
                ((uVar7 & 1 << (uint)*(byte *)(psVar10 + 3)) == 0)) {
          puVar6[*(byte *)(psVar10 + 3)] = (int)psVar10 - *(int *)(iVar11 + 0x20);
          uVar7 = uVar7 | 1 << (uint)*(byte *)(psVar10 + 3);
        }
      }
      else {
        if (*psVar10 == 0x6e) {
          (**(code **)(*DAT_803dd71c + 0xc))(psVar10);
        }
        if (*psVar10 == 5) {
          (**(code **)(*DAT_803dd6ec + 0xc))(psVar10);
        }
      }
      pbVar1 = (byte *)(psVar10 + 1);
      psVar10 = psVar10 + (uint)*pbVar1 * 2;
    }
    if (in_r6 == 0) {
      uVar4 = puVar6[0x21];
      uVar7 = uVar9;
      if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar9)) {
        uVar7 = uVar4;
      }
      iVar11 = 4;
      puVar5 = puVar6;
      do {
        uVar4 = *puVar5;
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[1];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[2];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[3];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[4];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[5];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[6];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[7];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        puVar5 = puVar5 + 8;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      puVar6[0x22] = uVar7;
      if (puVar6[0x21] == 0xffffffff) {
        puVar6[0x20] = uVar9;
      }
      else {
        puVar6[0x20] = puVar6[0x21];
      }
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80057048
 * EN v1.0 Address: 0x80057048
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x80059BCC
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80057048(int param_1)
{
  if ((&DAT_803870c8)[param_1] != 0) {
    FUN_80056cfc();
    FUN_80017814((&DAT_803870c8)[param_1]);
    (&DAT_803870c8)[param_1] = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005709c
 * EN v1.0 Address: 0x8005709C
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x80059C3C
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8005709c(int param_1,int param_2,int param_3)
{
  int iVar1;
  uint uVar2;
  char *pcVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar6 = 0;
  iVar7 = 0x40;
  pcVar3 = DAT_80382ea4;
  psVar4 = DAT_80382e9c;
  iVar5 = DAT_80382ea8;
  while (((((int)DAT_803dda61 + (int)(char)(&DAT_803dc284)[param_3] != (int)*pcVar3 ||
           (iVar1 = (int)*psVar4, param_1 < iVar1)) || (psVar4[1] < param_1)) ||
         (((param_2 < psVar4[2] || (psVar4[3] < param_2)) ||
          (uVar2 = (param_1 - iVar1) + (param_2 - psVar4[2]) * ((psVar4[1] - iVar1) + 1),
          (1 << (uVar2 & 7) & (uint)*(byte *)(iVar5 + ((int)uVar2 >> 3))) == 0))))) {
    if ((((int)DAT_803dda61 + (int)(char)(&DAT_803dc284)[param_3] == (int)pcVar3[1]) &&
        (iVar1 = (int)psVar4[5], iVar1 <= param_1)) &&
       ((param_1 <= psVar4[6] &&
        (((psVar4[7] <= param_2 && (param_2 <= psVar4[8])) &&
         (uVar2 = (param_1 - iVar1) + (param_2 - psVar4[7]) * ((psVar4[6] - iVar1) + 1),
         (1 << (uVar2 & 7) & (uint)*(byte *)(iVar5 + 0x40 + ((int)uVar2 >> 3))) != 0)))))) {
      return iVar6 + 1;
    }
    psVar4 = psVar4 + 10;
    iVar5 = iVar5 + 0x80;
    pcVar3 = pcVar3 + 2;
    iVar6 = iVar6 + 2;
    iVar7 = iVar7 + -1;
    if (iVar7 == 0) {
      return -1;
    }
  }
  return iVar6;
}

/*
 * --INFO--
 *
 * Function: FUN_800571f8
 * EN v1.0 Address: 0x800571F8
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x80059DA8
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800571f8(undefined *param_1)
{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  
  iVar4 = 0;
  do {
    iVar2 = 0;
    iVar1 = (int)DAT_803dda6c;
    piVar3 = &DAT_80382eac;
    if (0 < iVar1) {
      do {
        if ((*piVar3 != 0) && (iVar4 == *(short *)(piVar3 + 1))) goto LAB_80059dfc;
        piVar3 = piVar3 + 2;
        iVar2 = iVar2 + 1;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
    }
    iVar2 = -1;
LAB_80059dfc:
    if (iVar2 == -1) {
      *param_1 = 0;
    }
    else {
      *param_1 = 1;
    }
    iVar4 = iVar4 + 1;
    param_1 = param_1 + 1;
    if (0x77 < iVar4) {
      return;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_80057270
 * EN v1.0 Address: 0x80057270
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80059E2C
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80057270(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80057274
 * EN v1.0 Address: 0x80057274
 * EN v1.0 Size: 832b
 * EN v1.1 Address: 0x8005A05C
 * EN v1.1 Size: 556b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80057274(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar5;
  uint uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  int local_28;
  int iStack_24;
  int local_20 [8];
  
  uVar8 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  iVar4 = iVar2 * 7;
  iVar3 = iVar2 * 0x1c;
  uVar6 = *(uint *)(DAT_803ddafc + iVar3);
  uVar5 = *(int *)(DAT_803ddafc + iVar3 + 0x1c) - uVar6;
  uVar7 = FUN_80044f74(uVar6,local_20,&iStack_24,&local_28,iVar4);
  DAT_803ddb20 = FUN_80017830(uVar5 + (local_20[0] + 7 >> 3) + 0x401 + local_28,5);
  uVar7 = FUN_80045328(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1d,
                       DAT_803ddb20,uVar6,uVar5,iVar4,in_r8,in_r9,in_r10);
  *(uint *)(DAT_803ddb20 + 0xc) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 4)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x14) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 8)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x30) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 0xc)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x2c) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 0x10)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x34) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 0x14)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x20) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 0x18)) - uVar6;
  FUN_80044428(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               *(undefined4 *)(DAT_803ddafc + iVar3 + 0x18),iVar2,*(uint *)(DAT_803ddb20 + 0x20),
               uVar5,iVar4,in_r8,in_r9,in_r10);
  *(uint *)(DAT_803ddb20 + 0x10) =
       (local_28 + *(int *)(DAT_803ddafc + iVar3 + 0x1c) + DAT_803ddb20) - uVar6;
  for (iVar3 = 0; fVar1 = FLOAT_803df84c, iVar3 < (local_20[0] + 7 >> 3) + 1; iVar3 = iVar3 + 1) {
    *(undefined *)(*(int *)(DAT_803ddb20 + 0x10) + iVar3) = 0;
  }
  *(float *)(DAT_803ddb20 + 0x24) = FLOAT_803df84c;
  *(float *)(DAT_803ddb20 + 0x28) = fVar1;
  *(undefined *)(DAT_803ddb20 + 0x18) = 0;
  *(undefined *)(DAT_803ddb20 + 0x19) = 0;
  if ((int)uVar8 == 0) {
    FUN_80056cfc();
    (**(code **)(*DAT_803dd72c + 0x58))(iVar2);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800575b4
 * EN v1.0 Address: 0x800575B4
 * EN v1.0 Size: 220b
 * EN v1.1 Address: 0x8005A288
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800575b4(double param_1,float *param_2)
{
  uint uVar1;
  byte bVar2;
  
  bVar2 = 0;
  while( true ) {
    if (4 < bVar2) {
      return 1;
    }
    uVar1 = (uint)bVar2;
    if ((float)(param_1 +
               (double)((float)(&DAT_803885a8)[uVar1 * 5] +
                       (float)(&DAT_803885a4)[uVar1 * 5] * (param_2[2] - FLOAT_803dda5c) +
                       param_2[1] * (float)(&DAT_803885a0)[uVar1 * 5] +
                       (float)(&DAT_8038859c)[uVar1 * 5] * (*param_2 - FLOAT_803dda58))) <
        FLOAT_803df84c) break;
    bVar2 = bVar2 + 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80057690
 * EN v1.0 Address: 0x80057690
 * EN v1.0 Size: 828b
 * EN v1.1 Address: 0x8005A310
 * EN v1.1 Size: 712b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80057690(int param_1)
{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  byte bVar4;
  int iVar5;
  uint uVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  float fStack_48;
  float fStack_44;
  float local_40;
  float fStack_3c;
  undefined auStack_38 [4];
  undefined auStack_34 [4];
  undefined8 local_30;
  
  if (*(byte *)(param_1 + 0x36) == 0) {
    *(undefined *)(param_1 + 0x37) = 0;
    return 0;
  }
  iVar5 = *(int *)(param_1 + 0x4c);
  if ((iVar5 == 0) || ((*(byte *)(iVar5 + 5) & 1) == 0)) {
    dVar9 = (double)*(float *)(param_1 + 0x40);
    if (dVar9 < (double)FLOAT_803df838) {
      *(undefined *)(param_1 + 0x37) = 0;
      return 0;
    }
    iVar2 = FUN_80017a98();
    if (((iVar5 == 0) || ((*(byte *)(iVar5 + 5) & 2) == 0)) || (iVar2 == 0)) {
      dVar8 = (double)FUN_80006958((double)*(float *)(param_1 + 0x18),
                                   (double)*(float *)(param_1 + 0x1c),
                                   (double)*(float *)(param_1 + 0x20));
    }
    else {
      dVar8 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
    }
    if (dVar9 < dVar8) {
      *(undefined *)(param_1 + 0x37) = 0;
      return 0;
    }
    uVar6 = 0xff;
    dVar7 = (double)(float)(dVar9 - (double)FLOAT_803df854);
    if (dVar7 < dVar8) {
      uVar6 = (uint)(FLOAT_803df858 *
                    (FLOAT_803df85c - (float)(dVar8 - dVar7) / (float)(dVar9 - dVar7)));
      local_30 = (double)(longlong)(int)uVar6;
    }
    FUN_8000693c((double)(*(float *)(param_1 + 0x18) - FLOAT_803dda58),
                 (double)*(float *)(param_1 + 0x1c),
                 (double)(*(float *)(param_1 + 0x20) - FLOAT_803dda5c),
                 (double)(*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)),auStack_34,
                 auStack_38,&fStack_3c,&local_40,&fStack_44,&fStack_48);
    fVar1 = ABS(local_40) * FLOAT_803df834;
    if (fVar1 < FLOAT_803df860) {
      *(undefined *)(param_1 + 0x37) = 0;
      return 0;
    }
    if (fVar1 < FLOAT_803df868) {
      local_30 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      uVar6 = (uint)(((float)(local_30 - DOUBLE_803df840) * (fVar1 - FLOAT_803df860)) /
                    FLOAT_803df864);
    }
    *(char *)(param_1 + 0x37) = (char)(uVar6 * (*(byte *)(param_1 + 0x36) + 1) >> 8);
  }
  else {
    *(char *)(param_1 + 0x37) = (char)((*(byte *)(param_1 + 0x36) + 1) * 0xff >> 8);
  }
  if (*(char *)(param_1 + 0x37) == '\0') {
    uVar3 = 0;
  }
  else {
    for (bVar4 = 0; bVar4 < 5; bVar4 = bVar4 + 1) {
      uVar6 = (uint)bVar4;
      if (*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8) +
          (float)(&DAT_803885a8)[uVar6 * 5] +
          (float)(&DAT_803885a4)[uVar6 * 5] * (*(float *)(param_1 + 0x20) - FLOAT_803dda5c) +
          *(float *)(param_1 + 0x1c) * (float)(&DAT_803885a0)[uVar6 * 5] +
          (float)(&DAT_8038859c)[uVar6 * 5] * (*(float *)(param_1 + 0x18) - FLOAT_803dda58) <
          FLOAT_803df84c) {
        return 0;
      }
    }
    uVar3 = 1;
  }
  return uVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_800579cc
 * EN v1.0 Address: 0x800579CC
 * EN v1.0 Size: 796b
 * EN v1.1 Address: 0x8005A5D8
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800579cc(undefined4 *param_1)
{
  float fVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 local_20;
  
  if (DAT_803dda6d != '\0') {
    dVar9 = (double)FUN_802924c4();
    iVar8 = (int)dVar9;
    dVar9 = (double)FUN_802924c4();
    iVar2 = (int)dVar9;
    if ((((iVar8 < 0) || (iVar2 < 0)) || (0xf < iVar8)) || (0xf < iVar2)) {
      iVar8 = 0;
    }
    else {
      iVar8 = (int)*(char *)(DAT_80382f14 + iVar8 + iVar2 * 0x10);
      if ((iVar8 < 0) || ((int)(uint)DAT_803ddb18 <= iVar8)) {
        iVar8 = 0;
      }
      else {
        iVar8 = *(int *)(DAT_803ddb1c + iVar8 * 4);
      }
    }
    dVar9 = (double)FUN_802924c4();
    dVar11 = (double)FLOAT_803df834;
    dVar10 = (double)FUN_802924c4();
    iVar2 = (int)(*(float *)(DAT_803ddb28 + 0xc) -
                 (float)((double)CONCAT44(0x43300000,(int)(dVar11 * dVar9) ^ 0x80000000) -
                        DOUBLE_803df840));
    iVar3 = (int)(*(float *)(DAT_803ddb28 + 0x14) -
                 (float)((double)CONCAT44(0x43300000,
                                          (int)((double)FLOAT_803df834 * dVar10) ^ 0x80000000) -
                        DOUBLE_803df840));
    if (iVar8 != 0) {
      uVar6 = (uint)*(short *)(iVar8 + 0x8a);
      uVar7 = uVar6;
      if ((uVar6 & 1) != 0) {
        uVar7 = uVar6 - 1;
      }
      fVar1 = *(float *)(DAT_803ddb28 + 0x10);
      uVar4 = (uint)*(short *)(iVar8 + 0x8c);
      local_20 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      if ((float)(local_20 - DOUBLE_803df840) < fVar1) {
        fVar1 = (float)((double)CONCAT44(0x43300000,uVar4 - 1 ^ 0x80000000) - DOUBLE_803df840);
      }
      uVar4 = uVar4 - uVar6;
      iVar8 = (int)uVar4 / 0x50 + ((int)uVar4 >> 0x1f);
      if (iVar8 - (iVar8 >> 0x1f) < 8) {
        iVar8 = ((int)uVar4 >> 3) + (uint)((int)uVar4 < 0 && (uVar4 & 7) != 0);
      }
      else {
        iVar8 = 0x50;
      }
      iVar2 = iVar2 / 0x50 + (iVar2 >> 0x1f);
      iVar3 = iVar3 / 0x50 + (iVar3 >> 0x1f);
      FUN_80135814();
      uVar6 = (uint)DAT_803ddaf0;
      iVar5 = (int)uVar6 >> 3;
      if ((uVar6 & 7) != 0) {
        iVar5 = iVar5 + 1;
      }
      FUN_80006adc(param_1,DAT_803ddaf4 +
                           iVar5 * (((int)((int)fVar1 - uVar7) / iVar8) * 0x40 +
                                    (iVar3 - (iVar3 >> 0x1f)) * 8 + (iVar2 - (iVar2 >> 0x1f))),uVar6
                   ,uVar6);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80057ce8
 * EN v1.0 Address: 0x80057CE8
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x8005A8A4
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80057ce8(uint param_1,uint param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  bool bVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float *pfVar9;
  uint uVar10;
  int iVar11;
  
  fVar1 = FLOAT_803df834 *
          (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803df840);
  fVar2 = FLOAT_803df834 *
          (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803df840);
  fVar3 = FLOAT_803df86c;
  fVar4 = FLOAT_803df870;
  if (param_3 != 0) {
    fVar3 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x8a) ^ 0x80000000) -
                   DOUBLE_803df840);
    fVar4 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x8c) ^ 0x80000000) -
                   DOUBLE_803df840);
  }
  pfVar9 = (float *)&DAT_8038859c;
  iVar11 = 5;
  while( true ) {
    uVar10 = 0;
    bVar5 = false;
    while (((int)uVar10 < 8 && (!bVar5))) {
      fVar6 = FLOAT_803df834 + fVar1;
      if ((uVar10 & 1) != 0) {
        fVar6 = fVar1;
      }
      fVar7 = FLOAT_803df834 + fVar2;
      if ((uVar10 & 2) != 0) {
        fVar7 = fVar2;
      }
      fVar8 = fVar4;
      if ((uVar10 & 4) != 0) {
        fVar8 = fVar3;
      }
      if (FLOAT_803df84c < fVar6 * *pfVar9 + fVar7 * pfVar9[2] + fVar8 * pfVar9[1] + pfVar9[3]) {
        bVar5 = true;
      }
      uVar10 = uVar10 + 1;
    }
    if ((uVar10 == 8) && (!bVar5)) break;
    pfVar9 = pfVar9 + 5;
    iVar11 = iVar11 + -1;
    if (iVar11 == 0) {
      return 1;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80057ea0
 * EN v1.0 Address: 0x80057EA0
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x8005AA20
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80057ea0(float *param_1,int param_2)
{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int in_r8;
  
  for (iVar5 = 0; iVar5 < param_2; iVar5 = iVar5 + 1) {
    iVar3 = 0;
    fVar1 = FLOAT_803df84c;
    while (iVar4 = iVar3, iVar4 < 0x18) {
      fVar2 = param_1[2] * (float)(&DAT_8030f194)[iVar4 + 2] +
              param_1[1] * (float)(&DAT_8030f194)[iVar4 + 1] +
              *param_1 * (float)(&DAT_8030f194)[iVar4];
      iVar3 = iVar4 + 3;
      if (fVar1 < fVar2) {
        in_r8 = iVar4;
        fVar1 = fVar2;
      }
    }
    switch(in_r8) {
    case 0:
      *(undefined *)(param_1 + 4) = 0;
      break;
    case 3:
      *(undefined *)(param_1 + 4) = 2;
      break;
    case 6:
      *(undefined *)(param_1 + 4) = 5;
      break;
    case 9:
      *(undefined *)(param_1 + 4) = 7;
      break;
    case 0xc:
      *(undefined *)(param_1 + 4) = 1;
      break;
    case 0xf:
      *(undefined *)(param_1 + 4) = 3;
      break;
    case 0x12:
      *(undefined *)(param_1 + 4) = 4;
      break;
    case 0x15:
      *(undefined *)(param_1 + 4) = 6;
    }
    param_1 = param_1 + 5;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80057fd0
 * EN v1.0 Address: 0x80057FD0
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x8005AB2C
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80057fd0(void)
{
  int iVar1;
  undefined2 *puVar2;
  float *pfVar3;
  float *pfVar4;
  float *pfVar5;
  float *pfVar6;
  double dVar7;
  float local_88;
  undefined4 local_84;
  float local_80;
  float afStack_7c [3];
  float local_70 [4];
  undefined4 local_60;
  float local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  FUN_80286840();
  local_5c = DAT_802c25d8;
  local_58 = DAT_802c25dc;
  local_54 = DAT_802c25e0;
  local_50 = DAT_802c25e4;
  local_4c = DAT_802c25e8;
  local_48 = DAT_802c25ec;
  local_44 = DAT_802c25f0;
  local_40 = DAT_802c25f4;
  local_3c = DAT_802c25f8;
  local_38 = DAT_802c25fc;
  local_34 = DAT_802c2600;
  local_30 = DAT_802c2604;
  local_2c = DAT_802c2608;
  local_28 = DAT_802c260c;
  local_24 = DAT_802c2610;
  local_70[0] = DAT_802c2614;
  local_70[1] = (float)DAT_802c2618;
  local_70[2] = (float)DAT_802c261c;
  local_70[3] = (float)DAT_802c2620;
  local_60 = DAT_802c2624;
  iVar1 = FUN_80017a98();
  puVar2 = FUN_800069a8();
  local_88 = *(float *)(puVar2 + 0x22) - FLOAT_803dda58;
  local_84 = *(undefined4 *)(puVar2 + 0x24);
  local_80 = *(float *)(puVar2 + 0x26) - FLOAT_803dda5c;
  pfVar3 = (float *)FUN_8000696c();
  if (iVar1 == 0) {
    dVar7 = (double)FLOAT_803df874;
  }
  else {
    dVar7 = (double)FUN_80006958((double)*(float *)(iVar1 + 0x18),(double)*(float *)(iVar1 + 0x1c),
                                 (double)*(float *)(iVar1 + 0x20));
    dVar7 = -dVar7;
  }
  local_70[0] = (float)dVar7;
  iVar1 = 0;
  pfVar6 = (float *)&DAT_80388538;
  pfVar5 = &local_5c;
  pfVar4 = local_70;
  do {
    FUN_80247bf8(pfVar3,pfVar5,pfVar6);
    FUN_80247edc((double)*pfVar4,pfVar6,afStack_7c);
    FUN_80247e94(&local_88,afStack_7c,afStack_7c);
    dVar7 = FUN_80247f90(afStack_7c,pfVar6);
    pfVar6[3] = (float)-dVar7;
    pfVar6 = pfVar6 + 5;
    pfVar5 = pfVar5 + 3;
    pfVar4 = pfVar4 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 5);
  FUN_80057ea0((float *)&DAT_80388538,5);
  FUN_8028688c();
  return;
}

/* 8b "li r3, N; blr" returners. */
int fn_80056694(void) { return 0x0; }
int fn_8005669C(void) { return 0x0; }
