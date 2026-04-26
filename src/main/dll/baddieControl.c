#include "ghidra_import.h"
#include "main/dll/baddieControl.h"

extern undefined4 ABS();
extern undefined4 FUN_800033a8();
extern undefined4 FUN_8000676c();
extern undefined4 FUN_800067c0();
extern undefined8 FUN_8000680c();
extern undefined4 FUN_800068f4();
extern double FUN_80006a30();
extern undefined4 FUN_80006a5c();
extern undefined4 FUN_80006a60();
extern char FUN_80006a64();
extern undefined8 FUN_80006a68();
extern char FUN_80006bb8();
extern char FUN_80006bc0();
extern undefined4 FUN_80006c00();
extern uint FUN_80006c10();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_800176f4();
extern int FUN_80017730();
extern undefined4 FUN_80017754();
extern undefined4 FUN_80017760();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern int FUN_80017b00();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern uint FUN_80038a34();
extern int FUN_8003964c();
extern undefined4 FUN_80053ba4();
extern undefined4 FUN_80053bb0();
extern int FUN_8005b398();
extern uint FUN_8005d06c();
extern int FUN_800620e8();
extern int FUN_8007f810();
extern u8 *gameplay_getPreviewSettings();
extern undefined4 camcontrol_traceMove();
extern undefined4 camcontrol_traceFromTarget();
extern undefined4 camcontrol_getTargetPosition();
extern undefined4 FUN_80117c30();
extern undefined4 FUN_8012e0f4();
extern int FUN_8020a6e4();
extern uint FUN_8020a6f4();
extern undefined4 FUN_80247e94();
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
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint FUN_80294bd8();
extern double FUN_80294c4c();
extern undefined4 FUN_80294d2c();
extern int FUN_80294d58();
extern undefined4 FUN_80294dbc();
extern uint countLeadingZeros();

extern undefined4 DAT_802c2910;
extern undefined4 DAT_802c2914;
extern undefined4 DAT_802c2918;
extern undefined4 DAT_8031aa48;
extern undefined4 DAT_8031ac08;
extern undefined4 DAT_8031ac0c;
extern undefined4 DAT_8031ac10;
extern undefined4 DAT_8031ac14;
extern undefined4 DAT_8031ac16;
extern undefined4 DAT_8031ac18;
extern undefined4 DAT_8031ac98;
extern undefined4 DAT_8031aca4;
extern undefined4 DAT_803a5020;
extern undefined4 DAT_803a5024;
extern undefined4 DAT_803a5028;
extern undefined4 DAT_803a502c;
extern undefined4 DAT_803a5030;
extern undefined4 DAT_803a5034;
extern undefined4 DAT_803a5044;
extern undefined4 DAT_803a5048;
extern undefined4 DAT_803a504c;
extern undefined4 DAT_803a5050;
extern undefined4 DAT_803a5054;
extern undefined4 DAT_803a5058;
extern undefined4 DAT_803a505c;
extern undefined4 DAT_803a5060;
extern undefined4 DAT_803a5064;
extern undefined4 DAT_803a5068;
extern undefined4 DAT_803a506c;
extern undefined4 DAT_803a5070;
extern undefined4 DAT_803a5074;
extern undefined4 DAT_803a5076;
extern undefined4 DAT_803a5078;
extern undefined4 DAT_803a507a;
extern undefined4 DAT_803a507b;
extern undefined4 DAT_803a507e;
extern undefined4 DAT_803a5080;
extern undefined4 DAT_803a5084;
extern undefined4 DAT_803a5088;
extern undefined4 DAT_803a508c;
extern undefined4 DAT_803a508e;
extern undefined4 DAT_803a5090;
extern undefined4 DAT_803dc61c;
extern undefined4 DAT_803dc634;
extern undefined4 DAT_803dc640;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6f4;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern float* DAT_803de1fc;
extern undefined4* DAT_803de200;
extern undefined4 DAT_803de208;
extern undefined4 DAT_803de210;
extern undefined4* DAT_803de218;
extern undefined4* DAT_803de230;
extern undefined4* DAT_803de238;
extern undefined4* DAT_803de240;
extern undefined4 DAT_803de248;
extern undefined4 DAT_803de249;
extern undefined4 DAT_803de24a;
extern undefined4 DAT_803de258;
extern undefined4 DAT_803de25c;
extern undefined4 DAT_803e2898;
extern undefined4 DAT_803e289c;
extern undefined4 DAT_803e28a0;
extern undefined4 DAT_803e28a4;
extern undefined4 DAT_803e28a8;
extern f64 DOUBLE_803e2660;
extern f64 DOUBLE_803e26f0;
extern f64 DOUBLE_803e2748;
extern f64 DOUBLE_803e2778;
extern f64 DOUBLE_803e2790;
extern f64 DOUBLE_803e27b8;
extern f64 DOUBLE_803e27f0;
extern f64 DOUBLE_803e2838;
extern f64 DOUBLE_803e2888;
extern f64 DOUBLE_803e2890;
extern f64 DOUBLE_803e28b0;
extern f64 DOUBLE_803e28b8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc608;
extern f32 FLOAT_803dc60c;
extern f32 FLOAT_803dc610;
extern f32 FLOAT_803dc614;
extern f32 FLOAT_803dc618;
extern f32 FLOAT_803dc620;
extern f32 FLOAT_803dc628;
extern f32 FLOAT_803dc630;
extern f32 FLOAT_803dc638;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803de1f8;
extern f32 FLOAT_803de220;
extern f32 FLOAT_803de224;
extern f32 FLOAT_803de228;
extern f32 FLOAT_803e2658;
extern f32 FLOAT_803e265c;
extern f32 FLOAT_803e2668;
extern f32 FLOAT_803e266c;
extern f32 FLOAT_803e2670;
extern f32 FLOAT_803e2674;
extern f32 FLOAT_803e2678;
extern f32 FLOAT_803e267c;
extern f32 FLOAT_803e2680;
extern f32 FLOAT_803e2684;
extern f32 FLOAT_803e2688;
extern f32 FLOAT_803e268c;
extern f32 FLOAT_803e2690;
extern f32 FLOAT_803e2694;
extern f32 FLOAT_803e2698;
extern f32 FLOAT_803e269c;
extern f32 FLOAT_803e26a0;
extern f32 FLOAT_803e26a8;
extern f32 FLOAT_803e26ac;
extern f32 FLOAT_803e26b0;
extern f32 FLOAT_803e26b4;
extern f32 FLOAT_803e26b8;
extern f32 FLOAT_803e26bc;
extern f32 FLOAT_803e26c0;
extern f32 FLOAT_803e26c4;
extern f32 FLOAT_803e26d0;
extern f32 FLOAT_803e26d8;
extern f32 FLOAT_803e26dc;
extern f32 FLOAT_803e26e0;
extern f32 FLOAT_803e26e4;
extern f32 FLOAT_803e26e8;
extern f32 FLOAT_803e26ec;
extern f32 FLOAT_803e2700;
extern f32 FLOAT_803e2708;
extern f32 FLOAT_803e270c;
extern f32 FLOAT_803e2710;
extern f32 FLOAT_803e271c;
extern f32 FLOAT_803e2720;
extern f32 FLOAT_803e2724;
extern f32 FLOAT_803e2728;
extern f32 FLOAT_803e272c;
extern f32 FLOAT_803e2730;
extern f32 FLOAT_803e2734;
extern f32 FLOAT_803e2750;
extern f32 FLOAT_803e2754;
extern f32 FLOAT_803e2758;
extern f32 FLOAT_803e275c;
extern f32 FLOAT_803e2760;
extern f32 FLOAT_803e2764;
extern f32 FLOAT_803e2770;
extern f32 FLOAT_803e2788;
extern f32 FLOAT_803e2798;
extern f32 FLOAT_803e279c;
extern f32 FLOAT_803e27a0;
extern f32 FLOAT_803e27a4;
extern f32 FLOAT_803e27a8;
extern f32 FLOAT_803e27ac;
extern f32 FLOAT_803e27c0;
extern f32 FLOAT_803e27c4;
extern f32 FLOAT_803e27c8;
extern f32 FLOAT_803e27cc;
extern f32 FLOAT_803e27d0;
extern f32 FLOAT_803e27d4;
extern f32 FLOAT_803e27d8;
extern f32 FLOAT_803e27dc;
extern f32 FLOAT_803e27e8;
extern f32 FLOAT_803e27f8;
extern f32 FLOAT_803e27fc;
extern f32 FLOAT_803e2800;
extern f32 FLOAT_803e2818;
extern f32 FLOAT_803e281c;
extern f32 FLOAT_803e2820;
extern f32 FLOAT_803e2824;
extern f32 FLOAT_803e2828;
extern f32 FLOAT_803e282c;
extern f32 FLOAT_803e2830;
extern f32 FLOAT_803e2840;
extern f32 FLOAT_803e2844;
extern f32 FLOAT_803e2848;
extern f32 FLOAT_803e284c;
extern f32 FLOAT_803e2850;
extern f32 FLOAT_803e2854;
extern f32 FLOAT_803e2858;
extern f32 FLOAT_803e285c;
extern f32 FLOAT_803e2860;
extern f32 FLOAT_803e2864;
extern f32 FLOAT_803e2868;
extern f32 FLOAT_803e286c;
extern f32 FLOAT_803e2870;
extern f32 FLOAT_803e2874;
extern f32 FLOAT_803e2878;
extern f32 FLOAT_803e287c;
extern f32 FLOAT_803e2880;
extern f32 FLOAT_803e28ac;
extern f32 FLOAT_803e28c0;
extern f32 FLOAT_803e28c4;
extern f32 FLOAT_803e28c8;
extern f32 FLOAT_803e28cc;
extern f32 FLOAT_803e28d0;
extern f32 FLOAT_803e28d4;
extern f32 FLOAT_803e28d8;
extern f32 FLOAT_803e28dc;
extern f32 FLOAT_803e28e0;
extern f32 FLOAT_803e28e4;
extern f32 FLOAT_803e28e8;

/*
 * --INFO--
 *
 * Function: FUN_8010dd58
 * EN v1.0 Address: 0x8010DD58
 * EN v1.0 Size: 388b
 * EN v1.1 Address: 0x8010DE18
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010dd58(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)
{
  float fVar1;
  float *pfVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  pfVar2 = DAT_803de1fc;
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  dVar7 = (double)(*(float *)(iVar3 + 0x18) - *DAT_803de1fc);
  dVar5 = (double)(*(float *)(iVar3 + 0x20) - DAT_803de1fc[2]);
  dVar4 = FUN_80293900((double)(float)(dVar7 * dVar7 + (double)(float)(dVar5 * dVar5)));
  FUN_80017730();
  dVar8 = (double)((float)(dVar7 * (double)DAT_803de1fc[0x11]) + *pfVar2);
  dVar6 = (double)((float)(dVar5 * (double)DAT_803de1fc[0x11]) + pfVar2[2]);
  dVar5 = (double)FUN_80293f90();
  dVar7 = (double)FUN_80294964();
  if (dVar4 < (double)DAT_803de1fc[0x10]) {
    dVar4 = (double)DAT_803de1fc[0x10];
  }
  fVar1 = DAT_803de1fc[4];
  *(float *)uVar9 = (float)(dVar5 * (double)(float)(dVar4 + (double)fVar1) + dVar8);
  *param_3 = -(FLOAT_803e2658 * ((FLOAT_803e265c + *(float *)(iVar3 + 0x1c)) - pfVar2[1]) -
              (*(float *)(iVar3 + 0x1c) + DAT_803de1fc[0xc]));
  *param_4 = (float)(dVar7 * (double)(float)(dVar4 + (double)fVar1) + dVar6);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010dedc
 * EN v1.0 Address: 0x8010DEDC
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x8010DFC4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010dedc(void)
{
  FUN_80017814(DAT_803de1fc);
  DAT_803de1fc = 0;
  FUN_80053ba4();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010df0c
 * EN v1.0 Address: 0x8010DF0C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010DFF4
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010df0c(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8010df10
 * EN v1.0 Address: 0x8010DF10
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010E28C
 * EN v1.1 Size: 1432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010df10(int param_1,undefined4 param_2,undefined4 *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8010df14
 * EN v1.0 Address: 0x8010DF14
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010E824
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010df14(void)
{
  FUN_80017814(DAT_803de200);
  DAT_803de200 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010df40
 * EN v1.0 Address: 0x8010DF40
 * EN v1.0 Size: 3168b
 * EN v1.1 Address: 0x8010E850
 * EN v1.1 Size: 3212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010df40(void)
{
  float fVar1;
  float fVar2;
  float fVar3;
  short sVar4;
  short *psVar5;
  int iVar6;
  short *psVar7;
  uint uVar8;
  int iVar9;
  char cVar11;
  char cVar12;
  short *psVar10;
  short sVar13;
  int iVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  
  psVar5 = (short *)FUN_80286838();
  dVar18 = (double)FLOAT_803e26a8;
  iVar14 = *(int *)(psVar5 + 0x52);
  iVar6 = FUN_80017af8(0x42fff);
  psVar7 = (short *)FUN_80017af8(0x4325b);
  uVar8 = FUN_80006c10(0);
  FUN_80006c00(0);
  if (*(char *)(DAT_803de200 + 2) == '\x01') {
    psVar10 = (short *)FUN_80017af8(0x43077);
    if (*(char *)((int)DAT_803de200 + 9) == *(char *)(DAT_803de200 + 2)) {
      if ((*(char *)((int)DAT_803de200 + 0x15) < '\0') &&
         (iVar6 = (**(code **)(*DAT_803dd6cc + 0x14))(), iVar6 != 0)) {
        FUN_8012e0f4('\x01');
        (**(code **)(*DAT_803dd6cc + 0xc))(0xc,1);
        *(byte *)((int)DAT_803de200 + 0x15) = *(byte *)((int)DAT_803de200 + 0x15) & 0x7f;
        iVar6 = FUN_80017af8(0x43077);
        *(undefined *)(*(int *)(iVar6 + 0xb8) + 0x27d) = 1;
      }
      if (-1 < *(char *)((int)DAT_803de200 + 0x15)) {
        *(short *)((int)DAT_803de200 + 10) = *(short *)((int)DAT_803de200 + 10) + -1;
        if (*(short *)((int)DAT_803de200 + 10) < 1) {
          *(undefined2 *)((int)DAT_803de200 + 10) = 1;
        }
        iVar6 = FUN_80017730();
        sVar4 = (-0x308f - (short)iVar6) - *psVar5;
        if (0x8000 < sVar4) {
          sVar4 = sVar4 + 1;
        }
        if (sVar4 < -0x8000) {
          sVar4 = sVar4 + -1;
        }
        *psVar5 = *psVar5 + sVar4 / *(short *)((int)DAT_803de200 + 10);
        sVar4 = -psVar5[1] + 2000;
        if (0x8000 < sVar4) {
          sVar4 = -psVar5[1] + 0x7d1;
        }
        if (sVar4 < -0x8000) {
          sVar4 = sVar4 + -1;
        }
        psVar5[1] = psVar5[1] + sVar4 / *(short *)((int)DAT_803de200 + 10);
        dVar19 = (double)FUN_80294964();
        dVar19 = -dVar19;
        dVar15 = (double)FUN_80293f90();
        dVar17 = (double)FUN_80294964();
        dVar16 = (double)FUN_80293f90();
        dVar18 = DOUBLE_803e26f0;
        dVar17 = (double)(float)((double)FLOAT_803e26d8 * dVar17);
        fVar2 = FLOAT_803e26dc +
                *(float *)(iVar14 + 0x1c) + (float)((double)FLOAT_803e26d8 * dVar16);
        fVar1 = *(float *)(iVar14 + 0x20);
        *(float *)(psVar5 + 0xc) =
             *(float *)(psVar5 + 0xc) -
             (*(float *)(psVar5 + 0xc) - (*(float *)(iVar14 + 0x18) + (float)(dVar17 * dVar15))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803de200 + 10) ^ 0x80000000) -
                    DOUBLE_803e26f0);
        *(float *)(psVar5 + 0xe) =
             *(float *)(psVar5 + 0xe) -
             (*(float *)(psVar5 + 0xe) - fVar2) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803de200 + 10) ^ 0x80000000) - dVar18
                    );
        *(float *)(psVar5 + 0x10) =
             *(float *)(psVar5 + 0x10) -
             (*(float *)(psVar5 + 0x10) - (fVar1 + (float)(dVar17 * dVar19))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803de200 + 10) ^ 0x80000000) - dVar18
                    );
        sVar4 = *psVar5;
        sVar13 = sVar4 + 5000;
        uVar8 = FUN_8005d06c();
        if (uVar8 != 0) {
          sVar13 = sVar4 + 0x189c;
        }
        dVar18 = (double)FUN_80294964();
        dVar19 = (double)FUN_80293f90();
        dVar15 = (double)FLOAT_803e26e0;
        *(float *)(psVar10 + 6) = (float)(dVar15 * -dVar19 + (double)*(float *)(psVar5 + 0xc));
        *(float *)(psVar10 + 8) =
             *(float *)(psVar5 + 0xe) +
             *(float *)(&DAT_8031aa48 + *(char *)((int)psVar10 + 0xad) * 4);
        *(float *)(psVar10 + 10) = (float)(dVar15 * dVar18 + (double)*(float *)(psVar5 + 0x10));
        *psVar10 = -3000 - sVar13;
      }
    }
    else {
      (**(code **)(*DAT_803dd6cc + 8))(0xc,1);
      *(undefined2 *)((int)DAT_803de200 + 10) = 2;
      *(byte *)((int)DAT_803de200 + 0x15) = *(byte *)((int)DAT_803de200 + 0x15) & 0x7f | 0x80;
    }
  }
  else if (*(char *)(DAT_803de200 + 2) == '\0') {
    if (*(char *)((int)DAT_803de200 + 9) == '\0') {
      if ((*(char *)((int)DAT_803de200 + 0x15) < '\0') &&
         (iVar9 = (**(code **)(*DAT_803dd6cc + 0x14))(), iVar9 != 0)) {
        FUN_8012e0f4('\0');
        (**(code **)(*DAT_803dd6cc + 0xc))(0xc,1);
        *(byte *)((int)DAT_803de200 + 0x15) = *(byte *)((int)DAT_803de200 + 0x15) & 0x7f;
        iVar9 = FUN_80017af8(0x43077);
        *(undefined *)(*(int *)(iVar9 + 0xb8) + 0x27d) = 0;
      }
      if (-1 < *(char *)((int)DAT_803de200 + 0x15)) {
        *(short *)((int)DAT_803de200 + 10) = *(short *)((int)DAT_803de200 + 10) + -1;
        if (*(short *)((int)DAT_803de200 + 10) < 1) {
          *(undefined2 *)((int)DAT_803de200 + 10) = 1;
        }
        if ((uVar8 & 8) != 0) {
          dVar18 = (double)(FLOAT_803e26ac * *DAT_803de200);
        }
        if ((uVar8 & 4) != 0) {
          dVar18 = (double)(FLOAT_803e26b0 * *DAT_803de200);
        }
        dVar19 = dVar18;
        if (dVar18 < (double)FLOAT_803e26a8) {
          dVar19 = -dVar18;
        }
        dVar17 = (double)DAT_803de200[1];
        dVar15 = dVar17;
        if (dVar17 < (double)FLOAT_803e26a8) {
          dVar15 = -dVar17;
        }
        fVar1 = FLOAT_803e26b8;
        if (dVar19 < dVar15) {
          fVar1 = FLOAT_803e26b4;
        }
        DAT_803de200[1] = fVar1 * (float)(dVar18 - dVar17) + DAT_803de200[1];
        *DAT_803de200 = *DAT_803de200 + DAT_803de200[1];
        if (*DAT_803de200 < FLOAT_803e26bc) {
          *DAT_803de200 = FLOAT_803e26bc;
        }
        if (FLOAT_803e26c0 < *DAT_803de200) {
          *DAT_803de200 = FLOAT_803e26c0;
        }
        cVar11 = FUN_80006bc0(0);
        cVar12 = FUN_80006bb8(0);
        if (*(char *)(DAT_803de200 + 5) != '\0') {
          iVar9 = FUN_80017af8((int)DAT_803de200[4]);
          dVar18 = (double)(*(float *)(iVar9 + 0x18) - *(float *)(iVar6 + 0x18));
          dVar19 = (double)(*(float *)(iVar9 + 0x20) - *(float *)(iVar6 + 0x20));
          iVar6 = FUN_80017730();
          *(short *)(DAT_803de200 + 3) = -0x8000 - (short)iVar6;
          sVar4 = *(short *)(DAT_803de200 + 3) - *psVar5;
          if (0x8000 < sVar4) {
            sVar4 = sVar4 + 1;
          }
          if (sVar4 < -0x8000) {
            sVar4 = sVar4 + -1;
          }
          *psVar5 = *psVar5 + (short)((int)sVar4 / (int)(uint)*(byte *)(DAT_803de200 + 5));
          FUN_80293900((double)(float)(dVar18 * dVar18 + (double)(float)(dVar19 * dVar19)));
          iVar6 = FUN_80017730();
          *(short *)(DAT_803de200 + 3) = 0x47d0 - (short)iVar6;
          sVar4 = *(short *)(DAT_803de200 + 3) - psVar5[1];
          if (0x8000 < sVar4) {
            sVar4 = sVar4 + 1;
          }
          if (sVar4 < -0x8000) {
            sVar4 = sVar4 + -1;
          }
          psVar5[1] = psVar5[1] + (short)((int)sVar4 / (int)(uint)*(byte *)(DAT_803de200 + 5));
          *DAT_803de200 =
               *DAT_803de200 +
               (float)((double)CONCAT44(0x43300000,
                                        (int)(short)(int)(FLOAT_803e26c4 - *DAT_803de200) /
                                        (int)(uint)*(byte *)(DAT_803de200 + 5) ^ 0x80000000) -
                      DOUBLE_803e26f0);
          *(char *)(DAT_803de200 + 5) = *(char *)(DAT_803de200 + 5) + -1;
        }
        *psVar5 = *psVar5 + cVar11 * 3;
        psVar5[1] = psVar5[1] + cVar12 * 3;
        if (12000 < psVar5[1]) {
          psVar5[1] = 12000;
        }
        if (psVar5[1] < -12000) {
          psVar5[1] = -12000;
        }
        dVar19 = (double)FUN_80294964();
        dVar19 = -dVar19;
        dVar15 = (double)FUN_80293f90();
        dVar17 = (double)FUN_80294964();
        dVar16 = (double)FUN_80293f90();
        dVar18 = DOUBLE_803e26f0;
        fVar1 = *DAT_803de200;
        dVar17 = (double)(float)((double)fVar1 * dVar17);
        fVar3 = FLOAT_803e26d0 + *(float *)(iVar14 + 0x1c);
        fVar2 = *(float *)(iVar14 + 0x20);
        *(float *)(psVar5 + 0xc) =
             *(float *)(psVar5 + 0xc) -
             (*(float *)(psVar5 + 0xc) - (*(float *)(iVar14 + 0x18) + (float)(dVar17 * dVar15))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803de200 + 10) ^ 0x80000000) -
                    DOUBLE_803e26f0);
        *(float *)(psVar5 + 0xe) =
             *(float *)(psVar5 + 0xe) -
             (*(float *)(psVar5 + 0xe) - (fVar3 + (float)((double)fVar1 * dVar16))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803de200 + 10) ^ 0x80000000) - dVar18
                    );
        *(float *)(psVar5 + 0x10) =
             *(float *)(psVar5 + 0x10) -
             (*(float *)(psVar5 + 0x10) - (fVar2 + (float)(dVar17 * dVar19))) /
             (float)((double)CONCAT44(0x43300000,
                                      (int)*(short *)((int)DAT_803de200 + 10) ^ 0x80000000) - dVar18
                    );
      }
    }
    else {
      *(undefined *)(DAT_803de200 + 5) = 1;
      (**(code **)(*DAT_803dd6cc + 8))(0xc,1);
      *(undefined2 *)((int)DAT_803de200 + 10) = 2;
      *(byte *)((int)DAT_803de200 + 0x15) = *(byte *)((int)DAT_803de200 + 0x15) & 0x7f | 0x80;
    }
  }
  *(undefined *)((int)DAT_803de200 + 9) = *(undefined *)(DAT_803de200 + 2);
  psVar10 = (short *)FUN_80017af8(0x431dc);
  dVar18 = (double)(*(float *)(psVar10 + 0xc) - *(float *)(psVar5 + 0xc));
  dVar19 = (double)(*(float *)(psVar10 + 0x10) - *(float *)(psVar5 + 0x10));
  iVar6 = FUN_80017730();
  *psVar10 = (short)iVar6 + -0x8000;
  FUN_80293900((double)(float)(dVar18 * dVar18 + (double)(float)(dVar19 * dVar19)));
  iVar6 = FUN_80017730();
  psVar10[1] = -0x8000 - (short)iVar6;
  *(float *)(psVar10 + 4) = FLOAT_803e26e4 + FLOAT_803e26e8 / *DAT_803de200;
  *psVar7 = *psVar10;
  psVar7[1] = psVar10[1];
  *(undefined4 *)(psVar7 + 4) = *(undefined4 *)(psVar10 + 4);
  if (((short)(*psVar7 + -0x2198) < -0x1fff) || (0x1fff < (short)(*psVar7 + -0x2198))) {
    *(undefined *)(psVar7 + 0x1b) = 0;
  }
  else {
    dVar18 = (double)FUN_80294964();
    dVar19 = (double)FUN_80294964();
    fVar1 = FLOAT_803e26a8;
    if (FLOAT_803e26a8 <= FLOAT_803e26ec * (float)(dVar19 * dVar18)) {
      dVar18 = (double)FUN_80294964();
      dVar19 = (double)FUN_80294964();
      fVar1 = FLOAT_803e26ec * (float)(dVar19 * dVar18);
    }
    *(char *)(psVar7 + 0x1b) = (char)(int)fVar1;
  }
  FUN_800068f4((double)*(float *)(psVar5 + 0xc),(double)*(float *)(psVar5 + 0xe),
               (double)*(float *)(psVar5 + 0x10),(float *)(psVar5 + 6),(float *)(psVar5 + 8),
               (float *)(psVar5 + 10),*(int *)(psVar5 + 0x18));
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010eba0
 * EN v1.0 Address: 0x8010EBA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8010F4DC
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010eba0(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8010eba4
 * EN v1.0 Address: 0x8010EBA4
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010F598
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010eba4(void)
{
  FUN_80017814(DAT_803de208);
  DAT_803de208 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010ebd0
 * EN v1.0 Address: 0x8010EBD0
 * EN v1.0 Size: 432b
 * EN v1.1 Address: 0x8010F5C4
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010ebd0(short *param_1)
{
  float fVar1;
  short sVar2;
  short *psVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  longlong local_58;
  undefined4 local_50;
  uint uStack_4c;
  
  local_68 = FLOAT_803e2708;
  local_64 = FLOAT_803e270c;
  local_60 = FLOAT_803e2708;
  local_5c = FLOAT_803e2708;
  dVar4 = FUN_80006a30((double)*(float *)(DAT_803de208 + 4),&local_68,(float *)0x0);
  psVar3 = *(short **)(param_1 + 0x52);
  local_58 = (longlong)(int)((double)FLOAT_803e2710 * dVar4);
  sVar2 = (-0x8000 - *psVar3) + (short)(int)((double)FLOAT_803e2710 * dVar4);
  uStack_4c = (int)sVar2 ^ 0x80000000;
  local_50 = 0x43300000;
  dVar5 = (double)FUN_80294964();
  dVar6 = (double)FUN_80293f90();
  dVar8 = (double)FLOAT_803e271c;
  dVar7 = (double)FLOAT_803e2720;
  *(float *)(param_1 + 6) =
       *(float *)(psVar3 + 0xc) + (float)(dVar8 * dVar5 - (double)(float)(dVar7 * dVar6));
  *(float *)(param_1 + 10) =
       *(float *)(psVar3 + 0x10) + (float)(dVar8 * dVar6 + (double)(float)(dVar7 * dVar5));
  fVar1 = FLOAT_803e2724;
  *(float *)(param_1 + 8) =
       -(float)((double)FLOAT_803e2728 * dVar4 - (double)(FLOAT_803e2724 + *(float *)(psVar3 + 0xe))
               );
  param_1[1] = 0x11c6 - (short)(int)(fVar1 * (float)((double)FLOAT_803e272c * dVar4));
  *param_1 = sVar2 + 0x1ffe;
  param_1[2] = 0;
  *(undefined *)((int)param_1 + 0x13b) = 0;
  *(float *)(param_1 + 0x5a) = FLOAT_803e2730;
  *(float *)(DAT_803de208 + 4) = FLOAT_803e2734 * FLOAT_803dc074 + *(float *)(DAT_803de208 + 4);
  if (FLOAT_803e270c < *(float *)(DAT_803de208 + 4)) {
    *(float *)(DAT_803de208 + 4) = FLOAT_803e270c;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010ed80
 * EN v1.0 Address: 0x8010ED80
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x8010F78C
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010ed80(void)
{
  if (DAT_803de208 == 0) {
    DAT_803de208 = FUN_80017830(8,0xf);
  }
  *(float *)(DAT_803de208 + 4) = FLOAT_803e2708;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010edc4
 * EN v1.0 Address: 0x8010EDC4
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x8010F7DC
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010edc4(int param_1,int param_2)
{
  short sVar1;
  int iVar2;
  int iVar3;
  short *psVar4;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  
  if (param_1 != 0) {
    iVar2 = (**(code **)(*DAT_803dd6d0 + 0xc))();
    psVar4 = *(short **)(iVar2 + 0xa4);
    sVar1 = *psVar4;
    if (param_2 == 0) {
      uStack_34 = (int)sVar1 ^ 0x80000000;
      local_38 = 0x43300000;
      FUN_80293f90();
      uStack_2c = (int)*psVar4 ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_80294964();
    }
    else {
      uStack_2c = (int)sVar1 ^ 0x80000000;
      local_30 = 0x43300000;
      FUN_80293f90();
      uStack_34 = (int)*psVar4 ^ 0x80000000;
      local_38 = 0x43300000;
      FUN_80294964();
    }
    iVar3 = FUN_80017730();
    *psVar4 = (short)iVar3;
    camcontrol_getTargetPosition(iVar2,psVar4,&local_48,(short *)0x0);
    *psVar4 = sVar1;
    *(float *)(iVar2 + 0x18) = local_48;
    *(float *)(iVar2 + 0xb8) = local_48;
    *(undefined4 *)(iVar2 + 0x1c) = local_44;
    *(undefined4 *)(iVar2 + 0xbc) = local_44;
    *(undefined4 *)(iVar2 + 0x20) = local_40;
    *(undefined4 *)(iVar2 + 0xc0) = local_40;
    FUN_800068f4((double)*(float *)(iVar2 + 0x18),(double)*(float *)(iVar2 + 0x1c),
                 (double)*(float *)(iVar2 + 0x20),(float *)(iVar2 + 0xc),(float *)(iVar2 + 0x10),
                 (float *)(iVar2 + 0x14),*(int *)(iVar2 + 0x30));
    *(byte *)(DAT_803de210 + 8) = *(byte *)(DAT_803de210 + 8) & 0x7f | 0x80;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010eec0
 * EN v1.0 Address: 0x8010EEC0
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010F9BC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010eec0(void)
{
  FUN_80017814(DAT_803de210);
  DAT_803de210 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010eeec
 * EN v1.0 Address: 0x8010EEEC
 * EN v1.0 Size: 660b
 * EN v1.1 Address: 0x8010F9E8
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010eeec(ushort *param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  short *psVar4;
  double dVar5;
  float local_48;
  float local_44;
  undefined auStack_40 [4];
  float local_3c [2];
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  psVar4 = *(short **)(param_1 + 0x52);
  if (psVar4 != (short *)0x0) {
    if (*(char *)(DAT_803de210 + 8) < '\0') {
      iVar2 = (**(code **)(*DAT_803dd6d0 + 0x18))();
      (**(code **)(*DAT_803dd6d0 + 0x38))
                ((double)FLOAT_803e275c,param_1,local_3c,auStack_40,&local_44,&local_48,0);
      uVar1 = FUN_80017730();
      iVar3 = (0x8000 - (uVar1 & 0xffff)) - (uint)*param_1;
      if (0x8000 < iVar3) {
        iVar3 = iVar3 + -0xffff;
      }
      if (iVar3 < -0x8000) {
        iVar3 = iVar3 + 0xffff;
      }
      *param_1 = *param_1 + (short)iVar3;
      (**(code **)(**(int **)(iVar2 + 4) + 0x18))
                ((double)*(float *)(psVar4 + 0xe),(double)local_48,param_1);
    }
    else {
      uStack_34 = (int)*psVar4 ^ 0x80000000;
      local_3c[1] = 176.0;
      dVar5 = (double)FUN_80293f90();
      *(float *)(param_1 + 0xc) =
           (float)((double)FLOAT_803e2750 * dVar5 + (double)*(float *)(psVar4 + 0xc));
      uStack_2c = (int)*psVar4 ^ 0x80000000;
      local_30 = 0x43300000;
      dVar5 = (double)FUN_80294964();
      *(float *)(param_1 + 0x10) =
           (float)((double)FLOAT_803e2750 * dVar5 + (double)*(float *)(psVar4 + 0x10));
      *(float *)(param_1 + 0xe) = FLOAT_803e2754 + *(float *)(psVar4 + 0xe);
      local_3c[0] = *(float *)(param_1 + 6) - *(float *)(psVar4 + 0xc);
      local_44 = *(float *)(param_1 + 10) - *(float *)(psVar4 + 0x10);
      uVar1 = FUN_80017730();
      uStack_24 = (0x8000 - (uVar1 & 0xffff)) - (uint)*param_1;
      if (0x8000 < (int)uStack_24) {
        uStack_24 = uStack_24 - 0xffff;
      }
      if ((int)uStack_24 < -0x8000) {
        uStack_24 = uStack_24 + 0xffff;
      }
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      dVar5 = FUN_800176f4((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e2748)
                           ,(double)FLOAT_803e2758,(double)FLOAT_803dc074);
      uStack_1c = (int)(short)*param_1 ^ 0x80000000;
      local_20 = 0x43300000;
      iVar2 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2748) +
                   dVar5);
      local_18 = (longlong)iVar2;
      *param_1 = (ushort)iVar2;
      iVar2 = FUN_80017730();
      *param_1 = 0x8000 - (short)iVar2;
      param_1[1] = 0x800;
    }
    FUN_800068f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010f180
 * EN v1.0 Address: 0x8010F180
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x8010FCA0
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010f180(void)
{
  if (DAT_803de210 == 0) {
    DAT_803de210 = FUN_80017830(0xc,0xf);
    FUN_800033a8(DAT_803de210,0,0xc);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010f1c4
 * EN v1.0 Address: 0x8010F1C4
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8010FCF4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010f1c4(void)
{
  FUN_80017814(DAT_803de218);
  DAT_803de218 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010f1f0
 * EN v1.0 Address: 0x8010F1F0
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x8010FD20
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010f1f0(short *param_1)
{
  int iVar1;
  double dVar2;
  
  iVar1 = FUN_8003964c(*DAT_803de218,0);
  if ((short *)*DAT_803de218 != (short *)0x0) {
    *param_1 = (short)(int)((float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                   DOUBLE_803e2778) +
                           (float)((double)CONCAT44(0x43300000,
                                                    (int)(short)(((-0x8000 - *(short *)*DAT_803de218
                                                                  ) - *(short *)(iVar1 + 2)) -
                                                                *param_1) ^ 0x80000000) -
                                  DOUBLE_803e2778) / FLOAT_803e2760);
    dVar2 = (double)FUN_80293f90();
    *(float *)(param_1 + 6) =
         -(float)((double)FLOAT_803e2764 * dVar2 - (double)*(float *)(*DAT_803de218 + 0xc));
    *(float *)(param_1 + 8) = FLOAT_803e2770 + *(float *)(*DAT_803de218 + 0x10);
    dVar2 = (double)FUN_80294964();
    *(float *)(param_1 + 10) =
         -(float)((double)FLOAT_803e2764 * dVar2 - (double)*(float *)(*DAT_803de218 + 0x14));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010f358
 * EN v1.0 Address: 0x8010F358
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x8010FE88
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010f358(int param_1,undefined4 param_2,undefined4 *param_3)
{
  if (DAT_803de218 == (undefined4 *)0x0) {
    DAT_803de218 = (undefined4 *)FUN_80017830(4,0xf);
  }
  if (param_3 == (undefined4 *)0x0) {
    *DAT_803de218 = 0;
  }
  else {
    *DAT_803de218 = *param_3;
  }
  *(undefined2 *)(param_1 + 2) = 0xaf0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010f3d4
 * EN v1.0 Address: 0x8010F3D4
 * EN v1.0 Size: 908b
 * EN v1.1 Address: 0x8010FF18
 * EN v1.1 Size: 1084b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010f3d4(short *param_1)
{
  int iVar1;
  short *psVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  short local_d6;
  short local_d4 [2];
  float local_d0;
  float local_cc;
  float local_c8;
  undefined4 local_c0;
  uint uStack_bc;
  undefined4 local_b8;
  uint uStack_b4;
  undefined4 local_b0;
  uint uStack_ac;
  longlong local_a8;
  undefined4 local_a0;
  uint uStack_9c;
  undefined4 local_98;
  uint uStack_94;
  longlong local_90;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  
  psVar2 = *(short **)(param_1 + 0x52);
  uStack_bc = 0x8000U - (int)*param_1 ^ 0x80000000;
  local_c0 = 0x43300000;
  dVar3 = (double)FUN_80293f90();
  dVar4 = (double)FUN_80294964();
  dVar10 = (double)*(float *)(psVar2 + 0xc);
  local_d0 = (float)(dVar3 * (double)FLOAT_803dc628 + dVar10);
  local_cc = FLOAT_803e2788 + *(float *)(psVar2 + 0xe);
  dVar3 = (double)*(float *)(psVar2 + 0x10);
  local_c8 = (float)(dVar4 * (double)FLOAT_803dc628 + dVar3);
  camcontrol_traceFromTarget(&local_d0,(int)psVar2,&local_d0);
  dVar3 = FUN_80293900((double)((float)((double)local_d0 - dVar10) *
                                (float)((double)local_d0 - dVar10) +
                               (float)((double)local_c8 - dVar3) * (float)((double)local_c8 - dVar3)
                               ));
  FLOAT_803de228 = (float)dVar3;
  FLOAT_803de220 = (float)dVar3;
  FUN_80294d2c((int)psVar2,local_d4,&local_d6);
  local_d6 = local_d6 >> 1;
  dVar10 = (double)*(float *)(psVar2 + 0xc);
  dVar4 = (double)(*(float *)(psVar2 + 0xe) + FLOAT_803de224);
  dVar3 = (double)*(float *)(psVar2 + 0x10);
  local_d4[0] = ((-0x8000 - *psVar2) + (local_d4[0] >> 1)) - *param_1;
  if (0x8000 < local_d4[0]) {
    local_d4[0] = local_d4[0] + 1;
  }
  if (local_d4[0] < -0x8000) {
    local_d4[0] = local_d4[0] + -1;
  }
  uStack_b4 = (int)local_d4[0] ^ 0x80000000;
  local_b8 = 0x43300000;
  dVar5 = FUN_800176f4((double)(float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e2790),
                       (double)FLOAT_803e2798,(double)FLOAT_803dc074);
  uStack_ac = (int)*param_1 ^ 0x80000000;
  local_b0 = 0x43300000;
  iVar1 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_ac) - DOUBLE_803e2790) + dVar5);
  local_a8 = (longlong)iVar1;
  *param_1 = (short)iVar1;
  local_d6 = local_d6 - param_1[1];
  if (0x8000 < local_d6) {
    local_d6 = local_d6 + 1;
  }
  if (local_d6 < -0x8000) {
    local_d6 = local_d6 + -1;
  }
  uStack_9c = (int)local_d6 ^ 0x80000000;
  local_a0 = 0x43300000;
  dVar5 = FUN_800176f4((double)(float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803e2790),
                       (double)FLOAT_803e2798,(double)FLOAT_803dc074);
  uStack_94 = (int)param_1[1] ^ 0x80000000;
  local_98 = 0x43300000;
  iVar1 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e2790) + dVar5);
  local_90 = (longlong)iVar1;
  param_1[1] = (short)iVar1;
  uStack_84 = (int)*param_1 - 0x4000U ^ 0x80000000;
  local_88 = 0x43300000;
  dVar6 = (double)FUN_80293f90();
  uStack_7c = (int)*param_1 - 0x4000U ^ 0x80000000;
  local_80 = 0x43300000;
  dVar7 = (double)FUN_80294964();
  uStack_74 = (int)param_1[1] ^ 0x80000000;
  local_78 = 0x43300000;
  dVar8 = (double)FUN_80294964();
  uStack_6c = (int)param_1[1] ^ 0x80000000;
  local_70 = 0x43300000;
  dVar9 = (double)FUN_80293f90();
  dVar5 = (double)FLOAT_803de220;
  dVar8 = (double)(float)(dVar5 * dVar8);
  *(float *)(param_1 + 0xc) = (float)(dVar10 + (double)(float)(dVar8 * dVar7));
  *(float *)(param_1 + 0xe) = (float)(dVar4 + (double)(float)(dVar5 * dVar9));
  *(float *)(param_1 + 0x10) = (float)(dVar3 + (double)(float)(dVar8 * dVar6));
  camcontrol_traceFromTarget((float *)(param_1 + 0xc),(int)psVar2,(float *)(param_1 + 0xc));
  FUN_800068f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010f760
 * EN v1.0 Address: 0x8010F760
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x80110354
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010f760(int param_1,undefined4 param_2,undefined4 *param_3)
{
  short *psVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack_34;
  
  psVar1 = *(short **)(param_1 + 0xa4);
  uStack_34 = (int)*psVar1 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar2 = (double)FUN_80293f90();
  dVar3 = (double)FUN_80294964();
  dVar4 = (double)*(float *)(psVar1 + 0xc);
  local_44 = (float)(dVar2 * (double)FLOAT_803dc628 + dVar4);
  local_40 = FLOAT_803e2788 + *(float *)(psVar1 + 0xe);
  dVar2 = (double)*(float *)(psVar1 + 0x10);
  local_3c = (float)(dVar3 * (double)FLOAT_803dc628 + dVar2);
  camcontrol_traceFromTarget(&local_44,(int)psVar1,&local_44);
  dVar2 = FUN_80293900((double)((float)((double)local_44 - dVar4) *
                                (float)((double)local_44 - dVar4) +
                               (float)((double)local_3c - dVar2) * (float)((double)local_3c - dVar2)
                               ));
  FLOAT_803de228 = (float)dVar2;
  if (param_3 == (undefined4 *)0x0) {
    FLOAT_803dc628 = FLOAT_803e279c;
    FLOAT_803de224 = FLOAT_803e2788;
  }
  else {
    FLOAT_803dc628 = (float)*param_3;
    FLOAT_803de224 = (float)param_3[1];
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010f8bc
 * EN v1.0 Address: 0x8010F8BC
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80110484
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010f8bc(void)
{
  FUN_80017814(DAT_803de230);
  DAT_803de230 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010f8e8
 * EN v1.0 Address: 0x8010F8E8
 * EN v1.0 Size: 680b
 * EN v1.1 Address: 0x801104B0
 * EN v1.1 Size: 876b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010f8e8(short *param_1)
{
  float fVar1;
  ushort *puVar2;
  short *psVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  short local_c8;
  short local_c6;
  float local_c4;
  float local_c0;
  float local_bc;
  ushort local_b8;
  ushort local_b6;
  ushort local_b4;
  float local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  float afStack_a0 [16];
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  
  psVar3 = *(short **)(param_1 + 0x52);
  FUN_80294d2c((int)psVar3,&local_c6,&local_c8);
  puVar2 = (ushort *)FUN_80294dbc((int)psVar3);
  if (puVar2 == (ushort *)0x0) {
    local_bc = *(float *)(psVar3 + 0xc);
    local_c0 = *(float *)(psVar3 + 0xe) + FLOAT_803dc630;
    local_c4 = *(float *)(psVar3 + 0x10);
  }
  else if (puVar2[0x23] == 0x419) {
    local_ac = *(undefined4 *)(puVar2 + 0xc);
    local_a8 = *(undefined4 *)(puVar2 + 0xe);
    local_a4 = *(undefined4 *)(puVar2 + 0x10);
    local_b8 = *puVar2;
    local_b6 = puVar2[1];
    local_b4 = puVar2[2];
    local_b0 = FLOAT_803e27a0;
    FUN_80017754(afStack_a0,&local_b8);
    FUN_80017778((double)FLOAT_803e27a4,(double)FLOAT_803e27a8,(double)FLOAT_803e27ac,afStack_a0,
                 &local_bc,&local_c0,&local_c4);
  }
  else {
    local_bc = *(float *)(psVar3 + 0xc);
    local_c0 = *(float *)(psVar3 + 0xe) + FLOAT_803dc630;
    local_c4 = *(float *)(psVar3 + 0x10);
  }
  local_c6 = ((-0x8000 - *psVar3) + local_c6) - *param_1;
  if (0x8000 < local_c6) {
    local_c6 = local_c6 + 1;
  }
  if (local_c6 < -0x8000) {
    local_c6 = local_c6 + -1;
  }
  *param_1 = *param_1 + local_c6;
  local_c8 = local_c8 - param_1[1];
  if (0x8000 < local_c8) {
    local_c8 = local_c8 + 1;
  }
  if (local_c8 < -0x8000) {
    local_c8 = local_c8 + -1;
  }
  param_1[1] = param_1[1] + local_c8;
  param_1[2] = psVar3[2] * (short)DAT_803dc634;
  uStack_5c = (int)*param_1 - 0x4000U ^ 0x80000000;
  local_60 = 0x43300000;
  dVar4 = (double)FUN_80293f90();
  uStack_54 = (int)*param_1 - 0x4000U ^ 0x80000000;
  local_58 = 0x43300000;
  dVar5 = (double)FUN_80294964();
  uStack_4c = (int)param_1[1] ^ 0x80000000;
  local_50 = 0x43300000;
  dVar6 = (double)FUN_80294964();
  uStack_44 = (int)param_1[1] ^ 0x80000000;
  local_48 = 0x43300000;
  dVar7 = (double)FUN_80293f90();
  fVar1 = *(float *)(DAT_803de230 + 0xc);
  dVar6 = (double)(float)((double)fVar1 * dVar6);
  *(float *)(param_1 + 0xc) = local_bc + (float)(dVar6 * dVar5);
  *(float *)(param_1 + 0xe) = local_c0 + (float)((double)fVar1 * dVar7);
  *(float *)(param_1 + 0x10) = local_c4 + (float)(dVar6 * dVar4);
  FUN_800068f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010fb90
 * EN v1.0 Address: 0x8010FB90
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x8011081C
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010fb90(int param_1,uint param_2,undefined4 *param_3)
{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xa4);
  if (DAT_803de230 == (undefined4 *)0x0) {
    DAT_803de230 = (undefined4 *)FUN_80017830(0x10,0xf);
  }
  if (param_3 == (undefined4 *)0x0) {
    *DAT_803de230 = *(undefined4 *)(iVar2 + 0x18);
    DAT_803de230[1] = *(undefined4 *)(iVar2 + 0x1c);
    DAT_803de230[2] = *(undefined4 *)(iVar2 + 0x20);
    fVar1 = (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e27b8);
  }
  else {
    *DAT_803de230 = *param_3;
    DAT_803de230[1] = param_3[1];
    DAT_803de230[2] = param_3[2];
    fVar1 = (float)param_3[3];
  }
  DAT_803de230[3] = fVar1;
  FUN_80017730();
  FUN_80017730();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010fc88
 * EN v1.0 Address: 0x8010FC88
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80110954
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010fc88(void)
{
  FUN_80017814(DAT_803de238);
  DAT_803de238 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8010fcb4
 * EN v1.0 Address: 0x8010FCB4
 * EN v1.0 Size: 1272b
 * EN v1.1 Address: 0x80110980
 * EN v1.1 Size: 1168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010fcb4(short *param_1)
{
  float fVar1;
  float fVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  int local_c8;
  int local_c4 [3];
  undefined4 local_b8;
  uint uStack_b4;
  longlong local_b0;
  undefined4 local_a8;
  uint uStack_a4;
  undefined4 local_a0;
  uint uStack_9c;
  longlong local_98;
  
  if (*(char *)((int)DAT_803de238 + 0xd) == '\0') {
    if (DAT_803de238[1] == 0) {
      iVar4 = FUN_80017b00(local_c4,&local_c8);
      for (; local_c4[0] < local_c8; local_c4[0] = local_c4[0] + 1) {
        iVar5 = *(int *)(iVar4 + local_c4[0] * 4);
        if (*(short *)(iVar5 + 0x46) == 0x2ab) {
          DAT_803de238[1] = iVar5;
        }
        else if (*(short *)(iVar5 + 0x46) == 0x4dc) {
          *DAT_803de238 = iVar5;
        }
      }
    }
    if (DAT_803de238[2] == 0) {
      iVar4 = FUN_80017a98();
      DAT_803de238[2] = iVar4;
    }
    iVar5 = DAT_803de238[1];
    iVar4 = *DAT_803de238;
    dVar8 = (double)(*(float *)(iVar5 + 0x18) - *(float *)(iVar4 + 0x18));
    dVar7 = (double)(*(float *)(iVar5 + 0x1c) - *(float *)(iVar4 + 0x1c));
    dVar6 = (double)(*(float *)(iVar5 + 0x20) - *(float *)(iVar4 + 0x20));
    dVar10 = (double)(float)(dVar6 * dVar6);
    dVar9 = (double)(float)(dVar8 * dVar8);
    dVar7 = FUN_80293900((double)(float)(dVar10 + (double)(float)(dVar7 * dVar7 + dVar9)));
    dVar8 = (double)(float)(dVar8 / dVar7);
    dVar6 = (double)(float)(dVar6 / dVar7);
    fVar1 = -(float)((double)FLOAT_803e27c0 * dVar8 - (double)*(float *)(*DAT_803de238 + 0x18)) -
            *(float *)(DAT_803de238[2] + 0x18);
    fVar2 = -(float)((double)FLOAT_803e27c0 * dVar6 - (double)*(float *)(*DAT_803de238 + 0x20)) -
            *(float *)(DAT_803de238[2] + 0x20);
    dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    fVar1 = (float)((double)(float)((double)FLOAT_803e27c4 - dVar7) / (double)FLOAT_803e27c4);
    *(float *)(param_1 + 0x5a) = FLOAT_803e27cc * fVar1 + FLOAT_803e27c8;
    dVar7 = (double)(FLOAT_803e27d4 * fVar1 + FLOAT_803e27d0);
    *(float *)(param_1 + 0xc) = -(float)(dVar8 * dVar7 - (double)*(float *)(*DAT_803de238 + 0x18));
    *(float *)(param_1 + 0xe) =
         FLOAT_803e27dc * fVar1 + FLOAT_803e27d8 + *(float *)(*DAT_803de238 + 0x1c);
    *(float *)(param_1 + 0x10) = -(float)(dVar6 * dVar7 - (double)*(float *)(*DAT_803de238 + 0x20));
    iVar4 = FUN_80017730();
    *param_1 = -(short)iVar4;
    FUN_80293900((double)(float)(dVar9 + dVar10));
    iVar4 = FUN_80017730();
    param_1[1] = -(short)iVar4;
    if (*(char *)(DAT_803de238 + 3) == '\0') {
      fVar1 = (float)DAT_803de238[4] / FLOAT_803e27dc;
      *(float *)(param_1 + 0xc) =
           fVar1 * ((float)DAT_803de238[5] - *(float *)(param_1 + 0xc)) + *(float *)(param_1 + 0xc);
      *(float *)(param_1 + 0xe) =
           fVar1 * ((float)DAT_803de238[6] - *(float *)(param_1 + 0xe)) + *(float *)(param_1 + 0xe);
      *(float *)(param_1 + 0x10) =
           fVar1 * ((float)DAT_803de238[7] - *(float *)(param_1 + 0x10)) +
           *(float *)(param_1 + 0x10);
      sVar3 = *(short *)(DAT_803de238 + 8) - *param_1;
      if (0x8000 < sVar3) {
        sVar3 = sVar3 + 1;
      }
      if (sVar3 < -0x8000) {
        sVar3 = sVar3 + -1;
      }
      local_c4[2] = (int)sVar3 ^ 0x80000000;
      local_c4[1] = 0x43300000;
      uStack_b4 = (int)*param_1 ^ 0x80000000;
      local_b8 = 0x43300000;
      iVar4 = (int)((float)((double)CONCAT44(0x43300000,local_c4[2]) - DOUBLE_803e27f0) * fVar1 +
                   (float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e27f0));
      local_b0 = (longlong)iVar4;
      *param_1 = (short)iVar4;
      sVar3 = *(short *)((int)DAT_803de238 + 0x22) - param_1[1];
      if (0x8000 < sVar3) {
        sVar3 = sVar3 + 1;
      }
      if (sVar3 < -0x8000) {
        sVar3 = sVar3 + -1;
      }
      uStack_a4 = (int)sVar3 ^ 0x80000000;
      local_a8 = 0x43300000;
      uStack_9c = (int)param_1[1] ^ 0x80000000;
      local_a0 = 0x43300000;
      iVar4 = (int)((float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803e27f0) * fVar1 +
                   (float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803e27f0));
      local_98 = (longlong)iVar4;
      param_1[1] = (short)iVar4;
      DAT_803de238[4] = (int)((float)DAT_803de238[4] - FLOAT_803dc074);
      fVar1 = FLOAT_803e27e8;
      if ((float)DAT_803de238[4] < FLOAT_803e27e8) {
        *(undefined *)(DAT_803de238 + 3) = 1;
        DAT_803de238[4] = (int)fVar1;
      }
    }
    FUN_800068f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801101ac
 * EN v1.0 Address: 0x801101AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80110E10
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801101ac(undefined2 *param_1,undefined4 param_2,undefined2 *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801101b0
 * EN v1.0 Address: 0x801101B0
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80110F20
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801101b0(void)
{
  FUN_80017814(DAT_803de240);
  DAT_803de240 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801101dc
 * EN v1.0 Address: 0x801101DC
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x80110F4C
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801101dc(undefined2 *param_1)
{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(param_1 + 0x52);
  *DAT_803de240 = -(FLOAT_803e27f8 * FLOAT_803dc074 - *DAT_803de240);
  if (*DAT_803de240 < FLOAT_803e27fc) {
    *DAT_803de240 = FLOAT_803e27fc;
  }
  dVar2 = (double)FUN_80293f90();
  *(float *)(param_1 + 6) =
       -(float)((double)FLOAT_803e2800 * dVar2 - (double)*(float *)(iVar1 + 0x18));
  *(float *)(param_1 + 8) = DAT_803de240[1];
  dVar2 = (double)FUN_80294964();
  *(float *)(param_1 + 10) =
       -(float)((double)FLOAT_803e2800 * dVar2 - (double)*(float *)(iVar1 + 0x20));
  *param_1 = 0;
  param_1[1] = 0xc000;
  param_1[2] = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011031c
 * EN v1.0 Address: 0x8011031C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80111058
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011031c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80110320
 * EN v1.0 Address: 0x80110320
 * EN v1.0 Size: 1828b
 * EN v1.1 Address: 0x80111160
 * EN v1.1 Size: 1532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80110320(ushort *param_1)
{
  int iVar1;
  int iVar2;
  float fVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined local_88 [4];
  undefined local_84 [4];
  undefined local_80 [4];
  undefined local_7c [4];
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined4 local_50;
  uint uStack_4c;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  undefined8 local_20;
  
  iVar6 = *(int *)(param_1 + 0x52);
  *(float *)(param_1 + 0xc) = DAT_803a5020 * DAT_803a5044;
  *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + DAT_803a502c;
  *(float *)(param_1 + 0xe) = DAT_803a5024 * DAT_803a5048;
  *(float *)(param_1 + 0xe) = *(float *)(param_1 + 0xe) + DAT_803a5030;
  *(float *)(param_1 + 0x10) = *(float *)(iVar6 + 0x20) + DAT_803a5058;
  if (*(char *)(iVar6 + 0xac) != '&') {
    fVar3 = DAT_803a5060 / DAT_803a505c - FLOAT_803e2820;
    if (FLOAT_803e2824 <= fVar3) {
      local_78 = (double)CONCAT44(0x43300000,-(uint)DAT_803a507b ^ 0x80000000);
      *(float *)(param_1 + 0x10) =
           (float)(local_78 - DOUBLE_803e2838) * fVar3 + *(float *)(param_1 + 0x10);
    }
    else {
      local_78 = (double)CONCAT44(0x43300000,-(uint)DAT_803a507a ^ 0x80000000);
      *(float *)(param_1 + 0x10) =
           (float)(local_78 - DOUBLE_803e2838) * fVar3 + *(float *)(param_1 + 0x10);
    }
  }
  local_78 = (double)CONCAT44(0x43300000,(int)DAT_803a5074 ^ 0x80000000);
  iVar1 = (int)((float)(local_78 - DOUBLE_803e2838) * DAT_803a5064);
  local_70 = (double)(longlong)iVar1;
  local_68 = (double)CONCAT44(0x43300000,(int)DAT_803a5076 ^ 0x80000000);
  iVar2 = (int)((float)(local_68 - DOUBLE_803e2838) * DAT_803a5068);
  local_60 = (double)(longlong)iVar2;
  uVar4 = FUN_8020a6f4(iVar6);
  if (uVar4 == 0) {
    iVar6 = FUN_8020a6e4(iVar6);
    if (iVar6 == 0) {
      local_20 = (double)CONCAT44(0x43300000,(int)DAT_803a5078 ^ 0x80000000);
      iVar6 = (int)((float)(local_20 - DOUBLE_803e2838) * DAT_803a506c);
      local_28 = (double)(longlong)iVar6;
      uStack_2c = iVar6 - (uint)param_1[2];
      if (0x8000 < (int)uStack_2c) {
        uStack_2c = uStack_2c - 0xffff;
      }
      if ((int)uStack_2c < -0x8000) {
        uStack_2c = uStack_2c + 0xffff;
      }
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_38 = (double)CONCAT44(0x43300000,(int)(short)param_1[2] ^ 0x80000000);
      iVar6 = (int)((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e2838) *
                    FLOAT_803dc074 * FLOAT_803e282c + (float)(local_38 - DOUBLE_803e2838));
      local_40 = (double)(longlong)iVar6;
      param_1[2] = (ushort)iVar6;
      uVar4 = iVar1 - (uint)*param_1;
      if (0x8000 < (int)uVar4) {
        uVar4 = uVar4 - 0xffff;
      }
      if ((int)uVar4 < -0x8000) {
        uVar4 = uVar4 + 0xffff;
      }
      local_48 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      uStack_4c = (int)(short)*param_1 ^ 0x80000000;
      local_50 = 0x43300000;
      iVar6 = (int)((float)(local_48 - DOUBLE_803e2838) * FLOAT_803dc074 * FLOAT_803e282c +
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e2838));
      local_58 = (double)(longlong)iVar6;
      *param_1 = (ushort)iVar6;
      uVar4 = iVar2 - (uint)param_1[1];
      if (0x8000 < (int)uVar4) {
        uVar4 = uVar4 - 0xffff;
      }
      if ((int)uVar4 < -0x8000) {
        uVar4 = uVar4 + 0xffff;
      }
      local_60 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_68 = (double)CONCAT44(0x43300000,(int)(short)param_1[1] ^ 0x80000000);
      iVar6 = (int)((float)(local_60 - DOUBLE_803e2838) * FLOAT_803dc074 * FLOAT_803e282c +
                   (float)(local_68 - DOUBLE_803e2838));
      local_70 = (double)(longlong)iVar6;
      param_1[1] = (ushort)iVar6;
    }
    else {
      DAT_803a5070 = DAT_803a5070 * FLOAT_803e2830;
      local_20 = (double)CONCAT44(0x43300000,(int)(short)param_1[2] ^ 0x80000000);
      iVar6 = (int)(DAT_803a5070 * FLOAT_803dc074 + (float)(local_20 - DOUBLE_803e2838));
      local_28 = (double)(longlong)iVar6;
      param_1[2] = (ushort)iVar6;
    }
  }
  else {
    DAT_803a5070 = FLOAT_803e2828;
    (**(code **)(*DAT_803dd6d0 + 0x38))
              ((double)FLOAT_803e2824,param_1,local_7c,local_80,local_84,local_88,0);
    local_60 = (double)CONCAT44(0x43300000,(int)(short)param_1[2] ^ 0x80000000);
    iVar6 = (int)(DAT_803a5070 * FLOAT_803dc074 + (float)(local_60 - DOUBLE_803e2838));
    local_68 = (double)(longlong)iVar6;
    param_1[2] = (ushort)iVar6;
    uVar4 = FUN_80017730();
    uVar5 = FUN_80017730();
    uVar4 = (0x8000 - (uVar4 & 0xffff)) - (uint)*param_1;
    if (0x8000 < (int)uVar4) {
      uVar4 = uVar4 - 0xffff;
    }
    if ((int)uVar4 < -0x8000) {
      uVar4 = uVar4 + 0xffff;
    }
    local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    uVar4 = (uint)((float)(local_70 - DOUBLE_803e2838) * FLOAT_803dc074);
    local_78 = (double)(longlong)(int)uVar4;
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    uStack_4c = (int)(short)*param_1 ^ 0x80000000;
    local_50 = 0x43300000;
    iVar6 = (int)((float)(local_58 - DOUBLE_803e2838) * FLOAT_803e282c +
                 (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e2838));
    local_48 = (double)(longlong)iVar6;
    *param_1 = (ushort)iVar6;
    uVar4 = (uVar5 & 0xffff) - (uint)param_1[1];
    if (0x8000 < (int)uVar4) {
      uVar4 = uVar4 - 0xffff;
    }
    if ((int)uVar4 < -0x8000) {
      uVar4 = uVar4 + 0xffff;
    }
    local_40 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    uStack_2c = (uint)((float)(local_40 - DOUBLE_803e2838) * FLOAT_803dc074);
    local_38 = (double)(longlong)(int)uStack_2c;
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    local_28 = (double)CONCAT44(0x43300000,(int)(short)param_1[1] ^ 0x80000000);
    iVar6 = (int)((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e2838) * FLOAT_803e282c
                 + (float)(local_28 - DOUBLE_803e2838));
    local_20 = (double)(longlong)iVar6;
    param_1[1] = (ushort)iVar6;
  }
  FUN_800068f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
               (double)*(float *)(param_1 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
               (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80110a44
 * EN v1.0 Address: 0x80110A44
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x8011175C
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80110a44(int param_1,int param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xa4);
  if (param_2 != 1) {
    DAT_803a502c = *(undefined4 *)(iVar1 + 0x18);
    DAT_803a5030 = *(undefined4 *)(iVar1 + 0x1c);
    DAT_803a5034 = *(undefined4 *)(iVar1 + 0x20);
  }
  DAT_803a5050 = FLOAT_803e2824;
  DAT_803a5054 = FLOAT_803e2840;
  DAT_803a5058 = FLOAT_803e2844;
  FUN_80247e94((float *)(iVar1 + 0x18),&DAT_803a5050,(float *)(param_1 + 0x18));
  DAT_803a507e = 1;
  DAT_803a5064 = FLOAT_803e2848;
  DAT_803a5068 = FLOAT_803e284c;
  DAT_803a506c = FLOAT_803e2850;
  DAT_803a5044 = FLOAT_803e2854;
  DAT_803a5048 = FLOAT_803e2858;
  DAT_803a504c = FLOAT_803e2824;
  DAT_803a5060 = FLOAT_803e285c;
  DAT_803a505c = FLOAT_803e285c;
  DAT_803a507b = 0x5a;
  DAT_803a507a = 100;
  DAT_803a5028 = FLOAT_803e2824;
  DAT_803a5024 = FLOAT_803e2824;
  DAT_803a5020 = FLOAT_803e2824;
  *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(iVar1 + 0x18);
  *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(iVar1 + 0x1c);
  *(float *)(param_1 + 0x20) = *(float *)(iVar1 + 0x20) + DAT_803a5058;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80110b8c
 * EN v1.0 Address: 0x80110B8C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80111880
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80110b8c(void)
{
  return (double)FLOAT_803dc638;
}

/*
 * --INFO--
 *
 * Function: FUN_80110b94
 * EN v1.0 Address: 0x80110B94
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x80111888
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80110b94(char param_1)
{
  undefined1 *puVar1;
  
  if (param_1 != DAT_803de24a) {
    if (DAT_803de249 == '\x04') {
      if (FLOAT_803e2860 == FLOAT_803dc638) {
        FUN_800067c0((int *)0xbe,1);
        FUN_800067c0((int *)0xc1,1);
      }
      else {
        puVar1 = gameplay_getPreviewSettings();
        FUN_80117c30(0,1000);
        FUN_8000676c((uint)(byte)puVar1[10],1000,1,0,0);
      }
    }
    DAT_803de249 = DAT_803de24a;
    FLOAT_803dc638 = FLOAT_803e2864;
    DAT_803de248 = 1;
    DAT_803de24a = param_1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80110c58
 * EN v1.0 Address: 0x80110C58
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80111944
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80110c58(void)
{
  undefined1 *puVar1;
  
  puVar1 = gameplay_getPreviewSettings();
  FUN_8000676c((uint)(byte)puVar1[10],1000,1,0,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80110c90
 * EN v1.0 Address: 0x80110C90
 * EN v1.0 Size: 1840b
 * EN v1.1 Address: 0x8011197C
 * EN v1.1 Size: 1588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80110c90(ushort *param_1)
{
  float fVar1;
  uint uVar2;
  undefined1 *puVar3;
  undefined8 local_18;
  
  if (DAT_803de248 != '\0') {
    DAT_803a5080 = *(float *)(param_1 + 6);
    DAT_803a5084 = *(float *)(param_1 + 8);
    DAT_803a5088 = *(float *)(param_1 + 10);
    DAT_803a508c = *param_1;
    DAT_803a508e = param_1[1];
    DAT_803a5090 = param_1[2];
    DAT_803de248 = '\0';
  }
  if (DAT_803de24a != DAT_803de249) {
    puVar3 = gameplay_getPreviewSettings();
    FLOAT_803dc638 = FLOAT_803dc638 + FLOAT_803e2868;
    if (FLOAT_803dc638 < FLOAT_803e2860) {
      if (DAT_803de24a == 4) {
        FUN_80117c30((int)(FLOAT_803e286c * FLOAT_803dc638),1);
        FUN_8000676c((int)((float)((double)CONCAT44(0x43300000,(uint)(byte)puVar3[10]) -
                                  DOUBLE_803e2888) * (FLOAT_803e2860 - FLOAT_803dc638)),10,1,0,0);
      }
      else if (DAT_803de249 == 4) {
        FUN_80117c30((int)(FLOAT_803e286c * (FLOAT_803e2860 - FLOAT_803dc638)),1);
        FUN_8000676c((int)((float)((double)CONCAT44(0x43300000,(uint)(byte)puVar3[10]) -
                                  DOUBLE_803e2888) * FLOAT_803dc638),10,1,0,0);
      }
    }
    else {
      if (DAT_803de24a == 4) {
        FUN_80117c30(100,1);
        FUN_8000676c(0,10,1,0,0);
        FUN_800067c0((int *)0xbe,0);
        FUN_800067c0((int *)0xc1,0);
      }
      else if (DAT_803de249 == 4) {
        FUN_80117c30(0,1);
        FUN_8000676c((uint)(byte)puVar3[10],10,1,0,0);
      }
      FLOAT_803dc638 = FLOAT_803e2860;
      DAT_803de249 = DAT_803de24a;
    }
    if (FLOAT_803e2870 <= FLOAT_803dc638) {
      fVar1 = -(FLOAT_803e2874 * (FLOAT_803dc638 - FLOAT_803e2870) - FLOAT_803e2860);
      fVar1 = FLOAT_803e2870 * (FLOAT_803e2860 - fVar1 * fVar1) + FLOAT_803e2870;
    }
    else {
      fVar1 = FLOAT_803e2870 * FLOAT_803e2874 * FLOAT_803dc638 * FLOAT_803e2874 * FLOAT_803dc638;
    }
    fVar1 = fVar1 * FLOAT_803e287c * fVar1 * fVar1 +
            FLOAT_803e2870 * fVar1 + FLOAT_803e2878 * fVar1 * fVar1;
    *(float *)(param_1 + 6) =
         fVar1 * (*(float *)(&DAT_8031ac08 + (uint)DAT_803de24a * 0x14) - DAT_803a5080) +
         DAT_803a5080;
    *(float *)(param_1 + 8) =
         fVar1 * (*(float *)(&DAT_8031ac0c + (uint)DAT_803de24a * 0x14) - DAT_803a5084) +
         DAT_803a5084;
    *(float *)(param_1 + 10) =
         fVar1 * (*(float *)(&DAT_8031ac10 + (uint)DAT_803de24a * 0x14) - DAT_803a5088) +
         DAT_803a5088;
    uVar2 = (uint)*(ushort *)(&DAT_8031ac14 + (uint)DAT_803de24a * 0x14) - (uint)DAT_803a508c ^
            0x80000000;
    local_18 = (double)CONCAT44(0x43300000,uVar2);
    if (ABS((float)(local_18 - DOUBLE_803e2890)) <= FLOAT_803e2880) {
      local_18 = (double)CONCAT44(0x43300000,uVar2);
      *param_1 = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e2890) +
                              (float)((double)CONCAT44(0x43300000,(uint)DAT_803a508c) -
                                     DOUBLE_803e2888));
    }
    else {
      local_18 = (double)CONCAT44(0x43300000,
                                  (int)(short)*(ushort *)(&DAT_8031ac14 + (uint)DAT_803de24a * 0x14)
                                  - (int)(short)DAT_803a508c ^ 0x80000000);
      *param_1 = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e2890) +
                              (float)((double)CONCAT44(0x43300000,
                                                       (int)(short)DAT_803a508c ^ 0x80000000) -
                                     DOUBLE_803e2890));
    }
    uVar2 = (uint)*(ushort *)(&DAT_8031ac16 + (uint)DAT_803de24a * 0x14) - (uint)DAT_803a508e ^
            0x80000000;
    local_18 = (double)CONCAT44(0x43300000,uVar2);
    if (ABS((float)(local_18 - DOUBLE_803e2890)) <= FLOAT_803e2880) {
      local_18 = (double)CONCAT44(0x43300000,uVar2);
      param_1[1] = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e2890) +
                                (float)((double)CONCAT44(0x43300000,(uint)DAT_803a508e) -
                                       DOUBLE_803e2888));
    }
    else {
      local_18 = (double)CONCAT44(0x43300000,
                                  (int)(short)*(ushort *)(&DAT_8031ac16 + (uint)DAT_803de24a * 0x14)
                                  - (int)(short)DAT_803a508e ^ 0x80000000);
      param_1[1] = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e2890) +
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)DAT_803a508e ^ 0x80000000) -
                                       DOUBLE_803e2890));
    }
    uVar2 = (uint)*(ushort *)(&DAT_8031ac18 + (uint)DAT_803de24a * 0x14) - (uint)DAT_803a5090 ^
            0x80000000;
    local_18 = (double)CONCAT44(0x43300000,uVar2);
    if (ABS((float)(local_18 - DOUBLE_803e2890)) <= FLOAT_803e2880) {
      local_18 = (double)CONCAT44(0x43300000,uVar2);
      param_1[2] = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e2890) +
                                (float)((double)CONCAT44(0x43300000,(uint)DAT_803a5090) -
                                       DOUBLE_803e2888));
    }
    else {
      local_18 = (double)CONCAT44(0x43300000,
                                  (int)(short)*(ushort *)(&DAT_8031ac18 + (uint)DAT_803de24a * 0x14)
                                  - (int)(short)DAT_803a5090 ^ 0x80000000);
      param_1[2] = (ushort)(int)(fVar1 * (float)(local_18 - DOUBLE_803e2890) +
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)(short)DAT_803a5090 ^ 0x80000000) -
                                       DOUBLE_803e2890));
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801113c0
 * EN v1.0 Address: 0x801113C0
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x80111FB0
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801113c0(int param_1)
{
  short sVar1;
  
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 != 0x2ca) {
    if (sVar1 < 0x2ca) {
      if (sVar1 < 0x24e) {
        if (sVar1 != 0x170) {
          if (sVar1 < 0x170) {
            if (sVar1 != 0x16d) {
              if (0x16c < sVar1) {
                return 0;
              }
              if (sVar1 != 0x155) {
                return 0;
              }
            }
          }
          else if (sVar1 != 0x200) {
            if (sVar1 < 0x200) {
              if (sVar1 != 0x1da) {
                return 0;
              }
            }
            else if (sVar1 < 0x24c) {
              return 0;
            }
          }
        }
      }
      else if (sVar1 != 0x292) {
        if (sVar1 < 0x292) {
          if ((sVar1 != 0x28d) && (((0x28c < sVar1 || (0x27c < sVar1)) || (sVar1 < 0x27b)))) {
            return 0;
          }
        }
        else if (sVar1 != 0x2b9) {
          if (0x2b8 < sVar1) {
            return 0;
          }
          if (sVar1 != 0x2ab) {
            return 0;
          }
        }
      }
    }
    else if (sVar1 != 0x4ad) {
      if (sVar1 < 0x4ad) {
        if (sVar1 != 0x360) {
          if (sVar1 < 0x360) {
            if (sVar1 != 0x337) {
              if (0x336 < sVar1) {
                return 0;
              }
              if (sVar1 != 0x306) {
                return 0;
              }
            }
          }
          else if (sVar1 != 0x3fd) {
            if (0x3fc < sVar1) {
              return 0;
            }
            if (0x38a < sVar1) {
              return 0;
            }
            if (sVar1 < 0x389) {
              return 0;
            }
          }
        }
      }
      else if (sVar1 != 0x4fc) {
        if (sVar1 < 0x4fc) {
          if (sVar1 != 0x4d3) {
            if (0x4d2 < sVar1) {
              return 0;
            }
            if (sVar1 != 0x4b9) {
              return 0;
            }
          }
        }
        else if (sVar1 != 0x506) {
          return 0;
        }
      }
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80111558
 * EN v1.0 Address: 0x80111558
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x801120E4
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80111558(int param_1)
{
  float fVar1;
  uint uVar2;
  uint uVar3;
  
  uVar3 = (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x32);
  fVar1 = FLOAT_803e28ac;
  if ((uVar3 != 0) && (uVar2 = (uint)*(char *)(*(int *)(param_1 + 0xb8) + 0x354), uVar2 != 0)) {
    fVar1 = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e28b0) /
            (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e28b8);
  }
  return (double)fVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_801115e0
 * EN v1.0 Address: 0x801115E0
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x80112150
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801115e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined2 uStack_1a;
  undefined4 local_18;
  undefined4 local_14;
  undefined2 local_10;
  
  local_18 = DAT_802c2910;
  local_14 = DAT_802c2914;
  local_10 = DAT_802c2918;
  if ((*(char *)(param_10 + 0x407) != *(char *)(param_10 + 0x409)) &&
     (*(char *)(param_9 + 0x36) != '\0')) {
    if (*(int *)(param_9 + 200) != 0) {
      param_1 = FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             *(int *)(param_9 + 200));
      *(undefined4 *)(param_9 + 200) = 0;
    }
    uVar1 = FUN_80017ae8();
    if ((uVar1 & 0xff) == 0) {
      *(undefined *)(param_10 + 0x409) = 0;
    }
    else {
      if (0 < *(char *)(param_10 + 0x407)) {
        puVar2 = FUN_80017aa4(0x18,(&uStack_1a)[*(char *)(param_10 + 0x407)]);
        uVar3 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                             4,0xff,0xffffffff,*(uint **)(param_9 + 0x30),in_r8,in_r9,in_r10);
        *(undefined4 *)(param_9 + 200) = uVar3;
        *(ushort *)(*(int *)(param_9 + 200) + 0xb0) = *(ushort *)(param_9 + 0xb0) & 7;
      }
      *(undefined *)(param_10 + 0x409) = *(undefined *)(param_10 + 0x407);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80111778
 * EN v1.0 Address: 0x80111778
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x80112250
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80111778(int param_1,int param_2,byte param_3)
{
  FUN_8000680c(param_1,0x7f);
  if ((param_3 & *(byte *)(param_2 + 0x404)) == 0) {
    if (*(short *)(param_2 + 0x3fc) != 0) {
      (**(code **)(*DAT_803dd6f4 + 8))(param_1,*(short *)(param_2 + 0x3fc),0,0,0);
    }
    if (*(short *)(param_2 + 0x3fa) != 0) {
      (**(code **)(*DAT_803dd6f4 + 8))(param_1,*(short *)(param_2 + 0x3fa),0,0,0);
    }
  }
  FUN_80006a5c((uint *)(param_2 + 900));
  if (*(uint *)(param_2 + 0x3dc) != 0) {
    FUN_80017814(*(uint *)(param_2 + 0x3dc));
    *(undefined4 *)(param_2 + 0x3dc) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80111858
 * EN v1.0 Address: 0x80111858
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80112334
 * EN v1.1 Size: 1148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80111858(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6,uint param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8011185c
 * EN v1.0 Address: 0x8011185C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801127B0
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011185c(void)
{
  (**(code **)(*DAT_803dd6d0 + 0x3c))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80111890
 * EN v1.0 Address: 0x80111890
 * EN v1.0 Size: 604b
 * EN v1.1 Address: 0x801127E0
 * EN v1.1 Size: 412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80111890(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined *param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  short sVar8;
  undefined8 extraout_f1;
  undefined8 uVar9;
  uint local_30;
  uint local_2c;
  uint local_28 [10];
  
  uVar9 = FUN_80286834();
  uVar1 = (uint)((ulonglong)uVar9 >> 0x20);
  iVar3 = (int)uVar9;
  local_30 = 0;
  puVar4 = param_13;
  uVar5 = param_14;
  uVar6 = param_15;
  uVar7 = param_16;
  uVar9 = extraout_f1;
LAB_80112944:
  do {
    while( true ) {
      while( true ) {
        iVar2 = ObjMsg_Pop(uVar1,&local_2c,local_28,&local_30);
        if (iVar2 == 0) goto LAB_80112964;
        if (local_2c != 0xb) break;
        *(char *)(iVar3 + 0x34e) = (char)local_30;
      }
      sVar8 = (short)param_15;
      if ((int)local_2c < 0xb) break;
      if (local_2c == 0xe0000) {
        if (local_28[0] == *(uint *)(iVar3 + 0x2d0)) {
          *(short *)(iVar3 + 0x270) = (short)param_14;
          *(undefined4 *)(iVar3 + 0x2d0) = 0;
          *(undefined *)(iVar3 + 0x349) = 0;
        }
      }
      else if (((int)local_2c < 0xe0000) && (local_2c == 0xa0001)) {
LAB_801128c4:
        if (*(short *)(iVar3 + 0x270) != sVar8) {
          FUN_8011221c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,iVar3,
                       param_11,param_12,param_13,param_14,param_16,0,'\x01');
          *(short *)(iVar3 + 0x270) = sVar8;
          *(undefined *)(iVar3 + 0x349) = 0;
          *(uint *)(iVar3 + 0x2d0) = local_28[0];
          goto LAB_80112964;
        }
      }
    }
    if (local_2c != 3) {
      if ((int)local_2c < 3) {
        if (local_2c == 1) goto LAB_801128c4;
      }
      else if ((int)local_2c < 5) {
        ObjMsg_SendToObject(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_28[0],5,
                     uVar1,0,puVar4,uVar5,uVar6,uVar7);
      }
      goto LAB_80112944;
    }
    if (*(short *)(iVar3 + 0x270) == sVar8) {
      *(undefined *)(iVar3 + 0x349) = 0;
      *(undefined4 *)(iVar3 + 0x2d0) = 0;
      *(short *)(iVar3 + 0x270) = (short)param_14;
LAB_80112964:
      FUN_80286880();
      return;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_80111aec
 * EN v1.0 Address: 0x80111AEC
 * EN v1.0 Size: 920b
 * EN v1.1 Address: 0x8011297C
 * EN v1.1 Size: 840b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80111aec(void)
{
  ushort uVar1;
  float fVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int in_r7;
  float *pfVar8;
  int in_r8;
  undefined4 *puVar9;
  undefined2 in_r9;
  float *pfVar10;
  int in_r10;
  int iVar11;
  int iVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar17;
  float local_48;
  undefined4 local_44;
  float local_40;
  int local_3c;
  uint local_38;
  undefined4 local_34;
  undefined4 local_30;
  uint uStack_2c;
  
  uVar17 = FUN_80286830();
  uVar4 = (uint)((ulonglong)uVar17 >> 0x20);
  iVar7 = (int)uVar17;
  iVar12 = *(int *)(uVar4 + 0xb8);
  iVar11 = in_r10;
  iVar5 = FUN_80017a98();
  fVar2 = FLOAT_803e28ac;
  dVar16 = (double)*(float *)(iVar12 + 1000);
  dVar15 = (double)FLOAT_803e28ac;
  if (dVar15 < dVar16) {
    *(float *)(iVar12 + 1000) =
         (float)((double)FLOAT_803dc074 * (double)*(float *)(iVar12 + 0x3ec) + dVar16);
    uVar1 = *(ushort *)(iVar12 + 0x400);
    if ((uVar1 & 0x20) == 0) {
      if ((uVar1 & 0x40) == 0) {
        dVar13 = (double)*(float *)(iVar12 + 1000);
        if (dVar15 <= dVar13) {
          dVar14 = (double)FLOAT_803e28c4;
          if (dVar14 < dVar13) {
            *(float *)(iVar12 + 1000) = (float)(dVar14 - (double)(float)(dVar13 - dVar14));
            *(float *)(iVar12 + 0x3ec) = -*(float *)(iVar12 + 0x3ec);
          }
        }
        else {
          *(float *)(iVar12 + 1000) = fVar2;
        }
      }
      else if (FLOAT_803e28c0 < *(float *)(iVar12 + 1000)) {
        iVar6 = *(int *)(uVar4 + 0x4c);
        *(float *)(iVar12 + 1000) = fVar2;
        *(ushort *)(iVar12 + 0x400) = *(ushort *)(iVar12 + 0x400) & 0xffbf;
        *(undefined *)(iVar7 + 0x354) = 0;
        *(undefined *)(uVar4 + 0x36) = 0;
        *(undefined4 *)(uVar4 + 0xf4) = 1;
        *(ushort *)(uVar4 + 6) = *(ushort *)(uVar4 + 6) | 0x4000;
        uStack_2c = *(short *)(iVar6 + 0x2c) * 0x3c ^ 0x80000000;
        local_30 = 0x43300000;
        (**(code **)(*DAT_803dd72c + 100))
                  ((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e28b0),
                   *(undefined4 *)(iVar6 + 0x14));
      }
    }
    else {
      *(ushort *)(iVar12 + 0x400) = uVar1 & 0xffdf;
      *(ushort *)(iVar12 + 0x400) = *(ushort *)(iVar12 + 0x400) | 0x40;
      if (FLOAT_803e28c0 < *(float *)(iVar12 + 1000)) {
        *(float *)(iVar12 + 1000) = fVar2;
        *(ushort *)(iVar12 + 0x400) = *(ushort *)(iVar12 + 0x400) & 0xffbf;
      }
    }
  }
  if (*(char *)(iVar7 + 0x354) != '\0') {
    pfVar8 = &local_40;
    puVar9 = &local_44;
    pfVar10 = &local_48;
    iVar6 = ObjHits_GetPriorityHitWithPosition(uVar4,&local_3c,&local_34,&local_38,pfVar8,puVar9,pfVar10);
    *(undefined *)(iVar12 + 0x40a) = (undefined)local_34;
    if (iVar6 != 0) {
      if (in_r10 != 0) {
        *(float *)(in_r10 + 0xc) = local_40 + FLOAT_803dda58;
        *(undefined4 *)(in_r10 + 0x10) = local_44;
        *(float *)(in_r10 + 0x14) = local_48 + FLOAT_803dda5c;
      }
      if (in_r8 == 0) {
        local_38 = 0;
      }
      else {
        uVar3 = (uint)*(char *)(in_r8 + iVar6 + -2);
        if (uVar3 != 0xffffffff) {
          local_38 = uVar3;
        }
      }
      *(char *)(iVar7 + 0x354) = *(char *)(iVar7 + 0x354) - (char)local_38;
      if (*(char *)(iVar7 + 0x354) < '\x01') {
        *(ushort *)(iVar12 + 0x400) = *(ushort *)(iVar12 + 0x400) | 0x20;
        *(float *)(iVar12 + 1000) = FLOAT_803e28c8;
        *(float *)(iVar12 + 0x3ec) = FLOAT_803e28cc;
        *(undefined2 *)(iVar7 + 0x270) = in_r9;
        *(undefined *)(iVar7 + 0x354) = 0;
      }
      else if (local_38 != 0) {
        if ((*(int *)(iVar7 + 0x2d0) == 0) && (uVar3 = FUN_80294bd8(iVar5,1), uVar3 != 0)) {
          *(int *)(iVar7 + 0x2d0) = iVar5;
          *(undefined *)(iVar7 + 0x349) = 0;
        }
        *(float *)(iVar12 + 1000) = FLOAT_803e28c8;
        *(float *)(iVar12 + 0x3ec) = FLOAT_803e28d0;
        if ((in_r7 != 0) && (*(int *)(in_r7 + iVar6 * 4 + -8) != -1)) {
          (**(code **)(*DAT_803dd70c + 0x14))(uVar4,iVar7);
          *(undefined2 *)(iVar7 + 0x270) = in_r9;
        }
        *(char *)(iVar7 + 0x34f) = (char)iVar6;
      }
      uVar17 = FUN_8000680c(uVar4,0x10);
      ObjMsg_SendToObject(uVar17,dVar15,dVar16,in_f4,in_f5,in_f6,in_f7,in_f8,local_3c,0xe0001,uVar4,0,
                   pfVar8,puVar9,pfVar10,iVar11);
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80111e84
 * EN v1.0 Address: 0x80111E84
 * EN v1.0 Size: 920b
 * EN v1.1 Address: 0x80112CC4
 * EN v1.1 Size: 856b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80111e84(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined4 uVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint in_r6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined2 *unaff_r30;
  int iVar7;
  undefined8 extraout_f1;
  double in_f29;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
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
  uVar11 = FUN_80286840();
  iVar4 = (int)((ulonglong)uVar11 >> 0x20);
  uVar6 = (uint)uVar11;
  iVar7 = *(int *)(iVar4 + 0x4c);
  dVar8 = (double)FLOAT_803e28ac;
  local_5c = DAT_803e2898;
  local_58 = DAT_803e289c;
  local_64 = DAT_803e28a0;
  local_60 = DAT_803e28a4;
  if ((uVar6 != 0) && (uVar11 = extraout_f1, uVar5 = FUN_80017ae8(), (uVar5 & 0xff) != 0)) {
    if ((*(ushort *)(iVar7 + 0x22) & 0xf00) != 0) {
      iVar3 = ((int)(uVar6 & 0xf00) >> 8) + -1;
      if (3 < iVar3) {
        iVar3 = 3;
      }
      unaff_r30 = FUN_80017aa4(0x30,*(undefined2 *)((int)&local_5c + iVar3 * 2));
      dVar8 = (double)FLOAT_803e28d4;
    }
    if (((int)*(short *)(iVar7 + 0x22) & 0xf000U) != 0) {
      iVar3 = ((int)(uVar6 & 0xf000) >> 0xc) + -1;
      if (3 < iVar3) {
        iVar3 = 3;
      }
      unaff_r30 = FUN_80017aa4(0x30,*(undefined2 *)((int)&local_64 + iVar3 * 2));
      dVar8 = (double)FLOAT_803e28d4;
    }
    if ((*(ushort *)(iVar7 + 0x22) & 0xff) != 0) {
      if (uVar6 == 4) {
        unaff_r30 = FUN_80017aa4(0x30,0x2cd);
        dVar8 = (double)FLOAT_803e28d4;
      }
      else if ((int)uVar6 < 4) {
        if (uVar6 == 2) {
          unaff_r30 = FUN_80017aa4(0x30,9);
          dVar8 = (double)FLOAT_803e28d4;
        }
        else if ((int)uVar6 < 2) {
          if ((int)uVar6 < 1) goto LAB_80112fec;
          unaff_r30 = FUN_80017aa4(0x30,0x2cd);
          dVar8 = (double)FLOAT_803e28d4;
        }
        else {
          unaff_r30 = FUN_80017aa4(0x30,0xb);
          dVar8 = (double)FLOAT_803e28d4;
        }
      }
      else {
        if (uVar6 != 6) {
          if ((int)uVar6 < 6) {
            dVar10 = (double)*(float *)(iVar4 + 0x18);
            dVar9 = (double)*(float *)(iVar4 + 0x1c);
            dVar8 = (double)*(float *)(iVar4 + 0x20);
            iVar7 = *(int *)(iVar4 + 0x4c);
            if (iVar7 != 0) {
              *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(iVar7 + 8);
              *(undefined4 *)(iVar4 + 0x1c) = *(undefined4 *)(iVar7 + 0xc);
              *(undefined4 *)(iVar4 + 0x20) = *(undefined4 *)(iVar7 + 0x10);
            }
            local_68 = FLOAT_803e28d8;
            DAT_803de25c = ObjGroup_FindNearestObject(4,iVar4,&local_68);
            *(float *)(iVar4 + 0x18) = (float)dVar10;
            *(float *)(iVar4 + 0x1c) = (float)dVar9;
            *(float *)(iVar4 + 0x20) = (float)dVar8;
            if (DAT_803de25c != 0) {
              uVar1 = *(undefined4 *)(iVar4 + 0xc);
              *(undefined4 *)(DAT_803de25c + 0x18) = uVar1;
              *(undefined4 *)(DAT_803de25c + 0xc) = uVar1;
              fVar2 = *(float *)(iVar4 + 0x10) + FLOAT_803e28dc;
              *(float *)(DAT_803de25c + 0x1c) = fVar2;
              *(float *)(DAT_803de25c + 0x10) = fVar2;
              uVar1 = *(undefined4 *)(iVar4 + 0x14);
              *(undefined4 *)(DAT_803de25c + 0x20) = uVar1;
              *(undefined4 *)(DAT_803de25c + 0x14) = uVar1;
            }
          }
          goto LAB_80112fec;
        }
        unaff_r30 = FUN_80017aa4(0x30,0x6a6);
        *(undefined *)((int)unaff_r30 + 0x1b) = 0;
        *(undefined *)(unaff_r30 + 0x11) = 0;
        *(undefined *)((int)unaff_r30 + 0x23) = 0x40;
        dVar8 = (double)FLOAT_803e28e0;
      }
    }
    *(undefined *)(unaff_r30 + 0xd) = 0x14;
    unaff_r30[0x16] = 0xffff;
    unaff_r30[0xe] = 0xffff;
    unaff_r30[0x12] = 0xffff;
    *(undefined4 *)(unaff_r30 + 4) = *(undefined4 *)(iVar4 + 0xc);
    *(float *)(unaff_r30 + 6) = (float)((double)*(float *)(iVar4 + 0x10) + dVar8);
    *(undefined4 *)(unaff_r30 + 8) = *(undefined4 *)(iVar4 + 0x14);
    if ((in_r6 & 0xff) == 0) {
      unaff_r30[0x17] = 1;
    }
    else {
      unaff_r30[0x17] = 2;
    }
    *(undefined *)(unaff_r30 + 2) = *(undefined *)(iVar7 + 4);
    *(undefined *)(unaff_r30 + 3) = *(undefined *)(iVar7 + 6);
    *(undefined *)((int)unaff_r30 + 5) = *(undefined *)(iVar7 + 5);
    *(undefined *)((int)unaff_r30 + 7) = *(undefined *)(iVar7 + 7);
    DAT_803de25c = FUN_80017ae4(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                unaff_r30,5,*(undefined *)(iVar4 + 0xac),0xffffffff,
                                *(uint **)(iVar4 + 0x30),in_r8,in_r9,in_r10);
  }
LAB_80112fec:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8011221c
 * EN v1.0 Address: 0x8011221C
 * EN v1.0 Size: 464b
 * EN v1.1 Address: 0x8011301C
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011221c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined *param_13,undefined4 param_14,undefined4 param_15,int param_16,
                 char param_17)
{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_8028683c();
  uVar1 = (undefined4)((ulonglong)uVar6 >> 0x20);
  iVar2 = (int)uVar6;
  if (param_11 != 0) {
    *(undefined *)(param_11 + 0x24) = 0;
    *(undefined *)(param_11 + 0x25) = 0;
    *(undefined *)(param_11 + 0x26) = 4;
    *(undefined *)(param_11 + 0x27) = 0x14;
  }
  if ((short)param_14 != -1) {
    *(short *)(iVar2 + 0x270) = (short)param_14;
    *(undefined *)(iVar2 + 0x27b) = 1;
  }
  iVar3 = param_12;
  puVar4 = param_13;
  iVar5 = param_16;
  if ((short)param_15 != -1) {
    iVar3 = *DAT_803dd70c;
    (**(code **)(iVar3 + 0x14))(uVar1,iVar2);
  }
  if (param_13 != (undefined *)0x0) {
    *param_13 = 2;
  }
  if (param_16 != 0) {
    FUN_800305f8((double)FLOAT_803e28ac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 uVar1,param_16,0,iVar3,puVar4,param_14,param_15,iVar5);
  }
  (**(code **)(*DAT_803dd728 + 0x20))(uVar1,iVar2 + 4);
  if (param_17 != -1) {
    *(char *)(iVar2 + 0x25f) = param_17;
  }
  if ((int)(short)param_12 != 0xffffffff) {
    FUN_80017698((int)(short)param_12,1);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801123ec
 * EN v1.0 Address: 0x801123EC
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x80113130
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801123ec(undefined4 param_1,undefined4 param_2,int param_3)
{
  bool bVar1;
  ushort *puVar2;
  uint uVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  double extraout_f1;
  double dVar8;
  undefined8 uVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f31;
  double dVar12;
  double in_ps31_1;
  undefined8 uVar13;
  char local_c0 [4];
  short asStack_bc [4];
  short asStack_b4 [4];
  float local_ac;
  float local_a8;
  undefined4 local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  int local_94 [35];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar13 = FUN_80286838();
  puVar2 = (ushort *)((ulonglong)uVar13 >> 0x20);
  bVar1 = false;
  dVar12 = extraout_f1;
  local_94[0] = FUN_80017a98();
  local_94[1] = 0;
  for (piVar7 = local_94; (!bVar1 && (iVar6 = *piVar7, iVar6 != 0)); piVar7 = piVar7 + 1) {
    local_a0 = *(float *)(iVar6 + 0x18) - *(float *)(puVar2 + 0xc);
    dVar11 = (double)local_a0;
    local_9c = *(float *)(iVar6 + 0x1c) - *(float *)(puVar2 + 0xe);
    dVar10 = (double)local_9c;
    local_98 = *(float *)(iVar6 + 0x20) - *(float *)(puVar2 + 0x10);
    dVar8 = FUN_80293900((double)(local_98 * local_98 +
                                 (float)(dVar11 * dVar11) + (float)(dVar10 * dVar10)));
    if ((dVar8 < dVar12) && (*(char *)((int)uVar13 + 0x354) != '\0')) {
      dVar8 = FUN_80294c4c(iVar6);
      if ((double)FLOAT_803e28e4 < dVar8) {
        bVar1 = true;
      }
      dVar8 = -(double)local_98;
      uVar3 = FUN_80017730();
      if (*(short **)(puVar2 + 0x18) == (short *)0x0) {
        iVar5 = (uVar3 & 0xffff) - (uint)*puVar2;
        if (0x8000 < iVar5) {
          iVar5 = iVar5 + -0xffff;
        }
        if (iVar5 < -0x8000) {
          iVar5 = iVar5 + 0xffff;
        }
      }
      else {
        iVar5 = (uVar3 & 0xffff) -
                ((int)(short)*puVar2 + (int)**(short **)(puVar2 + 0x18) & 0xffffU);
        if (0x8000 < iVar5) {
          iVar5 = iVar5 + -0xffff;
        }
        if (iVar5 < -0x8000) {
          iVar5 = iVar5 + 0xffff;
        }
      }
      if ((iVar5 < param_3) && (-param_3 < iVar5)) {
        bVar1 = true;
      }
      uVar3 = FUN_80294bd8(iVar6,1);
      if (uVar3 == 0) {
        bVar1 = false;
      }
      iVar5 = FUN_80294d58(iVar6);
      if (iVar5 < 1) {
        bVar1 = false;
      }
      else {
        local_ac = *(float *)(puVar2 + 6);
        local_a8 = FLOAT_803e28e8 + *(float *)(puVar2 + 8);
        local_a4 = *(undefined4 *)(puVar2 + 10);
        FUN_80006a68(&local_ac,asStack_bc);
        local_ac = *(float *)(iVar6 + 0xc);
        local_a8 = FLOAT_803e28e8 + *(float *)(iVar6 + 0x10);
        local_a4 = *(undefined4 *)(iVar6 + 0x14);
        uVar9 = FUN_80006a68(&local_ac,asStack_b4);
        cVar4 = FUN_80006a64(uVar9,dVar8,dVar10,dVar11,in_f5,in_f6,in_f7,in_f8,asStack_b4,asStack_bc
                             ,(undefined4 *)0x0,local_c0,0);
        if ((local_c0[0] == '\x01') || (cVar4 != '\0')) {
          iVar6 = FUN_800620e8(puVar2 + 6,&local_ac,(float *)0x0,local_94 + 3,(int *)puVar2,4,
                               0xffffffff,0,0);
          if (iVar6 != 0) {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801126b8
 * EN v1.0 Address: 0x801126B8
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x801133D8
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801126b8(undefined4 param_1,undefined4 param_2,int param_3)
{
  int *piVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  double extraout_f1;
  double in_f31;
  double dVar5;
  double in_ps31_1;
  undefined8 uVar6;
  undefined4 local_90;
  float local_8c;
  undefined4 local_88;
  int aiStack_84 [31];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar6 = FUN_80286840();
  piVar1 = (int *)((ulonglong)uVar6 >> 0x20);
  iVar4 = (int)uVar6;
  dVar5 = extraout_f1;
  iVar2 = FUN_80017a98();
  if ((((*(char *)(iVar4 + 0x346) != '\0') && (*(int *)(iVar4 + 0x2d0) == iVar2)) &&
      (*(char *)(iVar4 + 0x354) != '\0')) &&
     ((((double)*(float *)(iVar4 + 0x2c0) <= dVar5 || (param_3 == 0)) &&
      ((uVar3 = FUN_80294bd8(iVar2,1), uVar3 != 0 && (iVar4 = FUN_80294d58(iVar2), 0 < iVar4)))))) {
    local_90 = *(undefined4 *)(iVar2 + 0xc);
    local_8c = FLOAT_803e28e8 + *(float *)(iVar2 + 0x10);
    local_88 = *(undefined4 *)(iVar2 + 0x14);
    FUN_800620e8(piVar1 + 3,&local_90,(float *)0x0,aiStack_84,piVar1,4,0xffffffff,0,0);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801127c4
 * EN v1.0 Address: 0x801127C4
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x80113514
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801127c4(int param_1,int param_2,char param_3)
{
  undefined4 uVar1;
  int iVar2;
  
  if (((param_3 == '\0') || ('\0' < *(char *)(param_2 + 0x354))) ||
     (*(char *)(param_1 + 0x36) != '\0')) {
    if ((*(int *)(param_1 + 0x30) == 0) &&
       (iVar2 = FUN_8005b398((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10)),
       iVar2 < 0)) {
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}
