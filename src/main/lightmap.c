#include "ghidra_import.h"
#include "main/lightmap.h"

extern undefined4 FUN_800033a8();
extern uint FUN_8000e640();
extern undefined4 FUN_8000e964();
extern undefined4 FUN_8000ef68();
extern undefined4 FUN_8000f11c();
extern undefined4 FUN_8000f56c();
extern undefined4 FUN_8000f578();
extern undefined4 FUN_8000f584();
extern undefined4 FUN_8000f7a0();
extern undefined4 FUN_8000f918();
extern undefined4 FUN_8000f9d4();
extern void* FUN_8000facc();
extern undefined4 FUN_8000faf8();
extern undefined4 FUN_8000fb20();
extern undefined4 FUN_8000fc4c();
extern double FUN_8000fc54();
extern undefined4 FUN_80013a7c();
extern undefined4 FUN_80013a84();
extern undefined4 FUN_8001f0c0();
extern undefined8 FUN_8001f82c();
extern int FUN_80020800();
extern undefined4 FUN_80021fac();
extern undefined4 FUN_80022790();
extern undefined4 FUN_80023d8c();
extern int FUN_8002b660();
extern int FUN_8002bac4();
extern int FUN_8002e1f4();
extern int FUN_8002e288();
extern undefined4 FUN_8003ba50();
extern undefined4 FUN_8003da78();
extern undefined4 FUN_8003fd58();
extern undefined4 FUN_800415ac();
extern undefined4 FUN_80053078();
extern undefined4 FUN_800540a8();
extern undefined4 FUN_800552ac();
extern undefined4 FUN_80057ea0();
extern undefined4 FUN_8005a310();
extern undefined4 FUN_8005a5d8();
extern int FUN_8005a8a4();
extern undefined4 FUN_8005aa20();
extern undefined4 FUN_8005ab2c();
extern undefined4 FUN_8005e4c4();
extern int FUN_8005e6dc();
extern undefined4 FUN_8005e8ac();
extern undefined4 FUN_8005edfc();
extern int FUN_8005f6d4();
extern undefined4 FUN_8005fa9c();
extern undefined4 FUN_8005fc74();
extern undefined4 FUN_8005fd40();
extern undefined4 FUN_8005ffa4();
extern undefined4 FUN_800617d0();
extern undefined4 FUN_80062614();
extern undefined4 FUN_80062984();
extern undefined4 FUN_80062a10();
extern undefined4 FUN_80062a54();
extern undefined4 FUN_8006b6d4();
extern void newshadows_renderQueuedShadowCasters(void);
extern void newshadows_queueShadowCaster(int object);
extern void newshadows_refreshShadowCaptureTexture(void);
extern void newshadows_flushShadowRenderTargets(void);
extern void newshadows_updateFrameState(void);
extern undefined4 FUN_8006f67c();
extern void trackIntersect_setColorRgb();
extern undefined4 FUN_80071050();
extern undefined4 FUN_80071978();
extern undefined4 FUN_80071ed0();
extern undefined4 FUN_8007242c();
extern undefined4 FUN_80079b60();
extern undefined4 FUN_80079ba0();
extern undefined4 FUN_80079be0();
extern undefined4 FUN_8007a898();
extern undefined4 FUN_8007ae8c();
extern undefined4 FUN_8007b198();
extern undefined4 FUN_8007d0f8();
extern undefined4 FUN_80088b10();
extern undefined4 FUN_80089ab8();
extern undefined4 FUN_80089b54();
extern undefined4 FUN_8008fd80();
extern undefined4 FUN_80093d6c();
extern undefined4 FUN_8009461c();
extern undefined4 FUN_8009e2c0();
extern undefined4 FUN_8009e3c8();
extern undefined4 FUN_8009ef70();
extern void* FUN_800e877c();
extern undefined4 FUN_8012a0f0();
extern undefined4 FUN_8016e0a0();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_80258c24();
extern undefined4 FUN_80259000();
extern undefined4 FUN_8025a2ec();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025d8c4();
extern undefined4 FUN_80286818();
extern undefined4 FUN_80286830();
extern undefined4 FUN_80286838();
extern int FUN_8028683c();
extern undefined4 FUN_80286864();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_802925a0();
extern undefined4 FUN_802929a8();
extern undefined4 FUN_80293900();
extern undefined4 FUN_80293d0c();
extern undefined4 FUN_80294224();
extern undefined4 FUN_802947f8();
extern undefined4 FUN_80294b54();
extern byte FUN_80296434();
extern undefined4 FUN_802b5638();
extern undefined4 builtin_strncpy();

extern undefined4 DAT_8037ed10;
extern undefined4 DAT_8037ed14;
extern undefined4 DAT_8037ed18;
extern undefined4 DAT_8037ed1c;
extern int DAT_8037ed20;
extern undefined4 DAT_8037ed24;
extern undefined4 DAT_8037ed28;
extern undefined4 DAT_8037ed2c;
extern undefined4 DAT_80382c68;
extern undefined4 DAT_80382c6c;
extern undefined4 DAT_80382c70;
extern undefined4 DAT_80382c74;
extern undefined4 DAT_80382c78;
extern undefined4 DAT_80382c7c;
extern undefined4 DAT_80382c80;
extern undefined4 DAT_80382c84;
extern undefined4 DAT_80382c88;
extern undefined4 DAT_80382c8c;
extern undefined4 DAT_80382c90;
extern undefined4 DAT_80382c94;
extern undefined4 DAT_80382e28;
extern int DAT_80382e34;
extern undefined4 DAT_80382e84;
extern undefined4 DAT_80382eec;
extern undefined4 DAT_80382ef0;
extern undefined4 DAT_80382ef4;
extern undefined4 DAT_80382ef8;
extern undefined4 DAT_80382efc;
extern undefined4 DAT_80382f00;
extern undefined4 DAT_80382f04;
extern undefined4 DAT_80382f08;
extern undefined4 DAT_80382f0c;
extern undefined4 DAT_80382f10;
extern int DAT_80382f14;
extern undefined4 DAT_80382f18;
extern undefined4 DAT_80382f1c;
extern undefined4 DAT_80382f20;
extern int DAT_80382f24;
extern int DAT_803870c8;
extern undefined4 DAT_80387538;
extern uint DAT_8038753c;
extern undefined4 DAT_8038859c;
extern undefined4 DAT_803885a0;
extern undefined4 DAT_803885a4;
extern undefined4 DAT_803885a8;
extern undefined4 DAT_803885b0;
extern undefined4 DAT_803885b4;
extern undefined4 DAT_803885b8;
extern undefined4 DAT_803885bc;
extern undefined4 DAT_803885c4;
extern undefined4 DAT_803885c8;
extern undefined4 DAT_803885cc;
extern undefined4 DAT_803885d0;
extern undefined4 DAT_803885d8;
extern undefined4 DAT_803885dc;
extern undefined4 DAT_803885e0;
extern undefined4 DAT_803885e4;
extern undefined4 DAT_803885ec;
extern undefined4 DAT_803885f0;
extern undefined4 DAT_803885f4;
extern undefined4 DAT_803885f8;
extern undefined4 DAT_80397480;
extern undefined4 DAT_803974b0;
extern undefined4 DAT_803dc290;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6dc;
extern undefined4* DAT_803dd6e0;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd730;
extern undefined4* DAT_803dd73c;
extern undefined4 DAT_803dda50;
extern undefined4 DAT_803dda54;
extern undefined4 DAT_803dda68;
extern undefined4 DAT_803dda70;
extern undefined4 DAT_803dda74;
extern undefined4 DAT_803dda75;
extern undefined4 DAT_803dda76;
extern undefined4 DAT_803dda77;
extern undefined4 DAT_803dda78;
extern undefined4 DAT_803dda79;
extern undefined4 DAT_803dda7a;
extern undefined4 DAT_803dda7b;
extern undefined4 DAT_803dda7c;
extern undefined4 DAT_803dda80;
extern undefined4 DAT_803dda85;
extern undefined4 DAT_803dda86;
extern undefined4 DAT_803ddab0;
extern undefined4 DAT_803ddab4;
extern undefined4 DAT_803ddab8;
extern undefined4 DAT_803ddac0;
extern undefined4 DAT_803ddae8;
extern undefined4 DAT_803ddaec;
extern undefined4 DAT_803ddaf8;
extern undefined4 DAT_803ddafc;
extern undefined4 DAT_803ddb00;
extern short* DAT_803ddb04;
extern undefined4 DAT_803ddb08;
extern undefined4 DAT_803ddb0c;
extern undefined4 DAT_803ddb10;
extern undefined4 DAT_803ddb14;
extern undefined4 DAT_803ddb18;
extern undefined4 DAT_803ddb1c;
extern undefined4 DAT_803ddb20;
extern undefined4 DAT_803ddb24;
extern undefined4 DAT_803ddb28;
extern undefined4 DAT_803ddb2c;
extern undefined4 DAT_803ddb2e;
extern undefined4 DAT_803ddb38;
extern undefined4 DAT_803ddb3a;
extern undefined4 DAT_803ddb40;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803df840;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc28c;
extern f32 FLOAT_803dc2d0;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803ddabc;
extern f32 FLOAT_803ddac4;
extern f32 FLOAT_803ddac8;
extern f32 FLOAT_803ddacc;
extern f32 FLOAT_803ddad0;
extern f32 FLOAT_803ddad4;
extern f32 FLOAT_803ddad8;
extern f32 FLOAT_803df834;
extern f32 FLOAT_803df84c;
extern f32 FLOAT_803df85c;
extern f32 FLOAT_803df878;
extern f32 FLOAT_803df87c;
extern f32 FLOAT_803df880;
extern f32 FLOAT_803df884;
extern f32 FLOAT_803df888;
extern f32 FLOAT_803df88c;
extern f32 FLOAT_803df890;
extern f32 FLOAT_803df894;
extern f32 FLOAT_803df898;
extern f32 FLOAT_803df89c;
extern f32 FLOAT_803df8a0;

/*
 * --INFO--
 *
 * Function: FUN_8005acec
 * EN v1.0 Address: 0x8005ACEC
 * EN v1.0 Size: 892b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005acec(void)
{
  float fVar1;
  undefined2 *puVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  float local_e8;
  float local_e4;
  float local_e0;
  ushort local_dc;
  short local_da;
  undefined2 local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float afStack_c4 [17];
  longlong local_80;
  
  puVar2 = FUN_8000facc();
  if (((DAT_803dda68 & 8) == 0) && ((DAT_803dda68 & 0x10000) == 0)) {
    dVar3 = FUN_8000fc54();
    dVar3 = dVar3 * (double)FLOAT_803df87c;
  }
  else {
    dVar3 = FUN_8000fc54();
    dVar3 = dVar3 / (double)FLOAT_803df878;
  }
  dVar3 = (double)(float)dVar3;
  dVar8 = (double)(*(float *)(puVar2 + 0x22) - FLOAT_803dda58);
  dVar7 = (double)*(float *)(puVar2 + 0x24);
  dVar6 = (double)(*(float *)(puVar2 + 0x26) - FLOAT_803dda5c);
  local_d0 = FLOAT_803df84c;
  local_cc = FLOAT_803df84c;
  local_c8 = FLOAT_803df84c;
  local_d4 = FLOAT_803df85c;
  local_dc = 0x8000 - puVar2[0x28];
  local_da = -puVar2[0x29];
  local_d8 = puVar2[0x2a];
  FUN_80021fac(afStack_c4,&local_dc);
  FUN_80022790((double)FLOAT_803df84c,(double)FLOAT_803df84c,(double)FLOAT_803df880,afStack_c4,
               &local_e0,&local_e4,&local_e8);
  DAT_8038859c = local_e0;
  DAT_803885a0 = local_e4;
  DAT_803885a4 = local_e8;
  DAT_803885a8 = -(float)(dVar6 * (double)local_e8 +
                         (double)(float)(dVar8 * (double)local_e0 +
                                        (double)(float)(dVar7 * (double)local_e4)));
  local_80 = (longlong)(int)((double)FLOAT_803df884 * dVar3);
  dVar3 = (double)FUN_80294224();
  dVar4 = (double)FUN_80293d0c();
  fVar1 = (float)(dVar4 / dVar3) * (float)(dVar4 / dVar3);
  FUN_80293900((double)(FLOAT_803df888 * FLOAT_803df888 * fVar1 + fVar1));
  FUN_802929a8();
  dVar3 = (double)FUN_802947f8();
  dVar4 = (double)FUN_80294b54();
  dVar3 = -dVar3;
  FUN_80022790(dVar4,(double)FLOAT_803df84c,dVar3,afStack_c4,&local_e0,&local_e4,&local_e8);
  DAT_803885b0 = local_e0;
  DAT_803885b4 = local_e4;
  DAT_803885b8 = local_e8;
  DAT_803885bc = -(float)(dVar6 * (double)local_e8 +
                         (double)(float)(dVar8 * (double)local_e0 +
                                        (double)(float)(dVar7 * (double)local_e4)));
  dVar5 = -dVar4;
  FUN_80022790(dVar5,(double)FLOAT_803df84c,dVar3,afStack_c4,&local_e0,&local_e4,&local_e8);
  DAT_803885c4 = local_e0;
  DAT_803885c8 = local_e4;
  DAT_803885cc = local_e8;
  DAT_803885d0 = -(float)(dVar6 * (double)local_e8 +
                         (double)(float)(dVar8 * (double)local_e0 +
                                        (double)(float)(dVar7 * (double)local_e4)));
  FUN_80022790((double)FLOAT_803df84c,dVar5,dVar3,afStack_c4,&local_e0,&local_e4,&local_e8);
  DAT_803885d8 = local_e0;
  DAT_803885dc = local_e4;
  DAT_803885e0 = local_e8;
  DAT_803885e4 = -(float)(dVar6 * (double)local_e8 +
                         (double)(float)(dVar8 * (double)local_e0 +
                                        (double)(float)(dVar7 * (double)local_e4)));
  FUN_80022790((double)FLOAT_803df84c,dVar4,dVar3,afStack_c4,&local_e0,&local_e4,&local_e8);
  DAT_803885ec = local_e0;
  DAT_803885f0 = local_e4;
  DAT_803885f4 = local_e8;
  DAT_803885f8 = -(float)(dVar6 * (double)local_e8 +
                         (double)(float)(dVar8 * (double)local_e0 +
                                        (double)(float)(dVar7 * (double)local_e4)));
  FUN_8005aa20(&DAT_8038859c,5);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005b068
 * EN v1.0 Address: 0x8005B068
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8005b068(int param_1)
{
  if ((-1 < param_1) && (param_1 < (int)(uint)DAT_803ddb18)) {
    return *(undefined4 *)(DAT_803ddb1c + param_1 * 4);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8005b094
 * EN v1.0 Address: 0x8005B094
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8005b094(int param_1)
{
  return (&DAT_80382f14)[param_1];
}

/*
 * --INFO--
 *
 * Function: FUN_8005b0a8
 * EN v1.0 Address: 0x8005B0A8
 * EN v1.0 Size: 116b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8005b0a8(int param_1,int param_2,int param_3)
{
  int iVar1;
  
  if ((((-1 < param_1) && (-1 < param_2)) && (param_1 < 0x10)) && (param_2 < 0x10)) {
    iVar1 = (int)*(char *)((&DAT_80382f14)[param_3] + param_1 + param_2 * 0x10);
    if ((-1 < iVar1) && (iVar1 < (int)(uint)DAT_803ddb18)) {
      return *(undefined4 *)(DAT_803ddb1c + iVar1 * 4);
    }
    return 0;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: fn_8005B11C
 * EN v1.0 Address: 0x8005B11C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int * fn_8005B11C(void)
{
  return &DAT_803870c8;
}

/*
 * --INFO--
 *
 * Function: FUN_8005b128
 * EN v1.0 Address: 0x8005B128
 * EN v1.0 Size: 252b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8005b128(void)
{
  int iVar1;
  int iVar2;
  double dVar3;
  
  dVar3 = (double)FUN_802925a0();
  iVar2 = (int)(dVar3 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dda50 ^ 0x80000000) -
                                       DOUBLE_803df840));
  dVar3 = (double)FUN_802925a0();
  iVar1 = (int)(dVar3 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dda54 ^ 0x80000000) -
                                       DOUBLE_803df840));
  if ((iVar2 < 0) || (0xf < iVar2)) {
    iVar2 = -1;
  }
  else if ((iVar1 < 0) || (0xf < iVar1)) {
    iVar2 = -1;
  }
  else {
    iVar2 = (int)*(short *)(DAT_80382f00 + (iVar2 + iVar1 * 0x10) * 0xc);
  }
  return iVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_8005b224
 * EN v1.0 Address: 0x8005B224
 * EN v1.0 Size: 196b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005b224(float *param_1,float *param_2)
{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar3 = (double)FUN_802925a0();
  dVar4 = (double)FUN_802925a0();
  dVar2 = DOUBLE_803df840;
  fVar1 = FLOAT_803df834;
  *param_1 = FLOAT_803df834 *
             (float)((double)CONCAT44(0x43300000,(int)dVar3 ^ 0x80000000) - DOUBLE_803df840);
  *param_2 = fVar1 * (float)((double)CONCAT44(0x43300000,(int)dVar4 ^ 0x80000000) - dVar2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005b2e8
 * EN v1.0 Address: 0x8005B2E8
 * EN v1.0 Size: 400b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8005b2e8(void)
{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  double dVar4;
  
  dVar4 = (double)FUN_802925a0();
  iVar3 = (int)(dVar4 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dda50 ^ 0x80000000) -
                                       DOUBLE_803df840));
  dVar4 = (double)FUN_802925a0();
  iVar1 = (int)(dVar4 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dda54 ^ 0x80000000) -
                                       DOUBLE_803df840));
  if ((iVar3 < 0) || (0xf < iVar3)) {
    uVar2 = 0xffffffff;
  }
  else if ((iVar1 < 0) || (0xf < iVar1)) {
    uVar2 = 0xffffffff;
  }
  else {
    iVar3 = iVar3 + iVar1 * 0x10;
    if (*(char *)(iVar3 + DAT_80382f14) < '\0') {
      if (*(char *)(iVar3 + DAT_80382f18) < '\0') {
        if (*(char *)(iVar3 + DAT_80382f1c) < '\0') {
          if (*(char *)(iVar3 + DAT_80382f20) < '\0') {
            if (*(char *)(iVar3 + DAT_80382f24) < '\0') {
              uVar2 = 0;
            }
            else {
              uVar2 = 1;
            }
          }
          else {
            uVar2 = 1;
          }
        }
        else {
          uVar2 = 1;
        }
      }
      else {
        uVar2 = 1;
      }
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
 * Function: FUN_8005b478
 * EN v1.0 Address: 0x8005B478
 * EN v1.0 Size: 404b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8005b478(undefined8 param_1,double param_2)
{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  undefined8 local_30;
  
  dVar5 = (double)FUN_802925a0();
  iVar3 = (int)(dVar5 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dda50 ^ 0x80000000) -
                                       DOUBLE_803df840));
  dVar5 = (double)FUN_802925a0();
  iVar4 = (int)(dVar5 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dda54 ^ 0x80000000) -
                                       DOUBLE_803df840));
  if ((((-1 < iVar3) && (iVar3 < 0x10)) && (-1 < iVar4)) && (iVar4 < 0x10)) {
    iVar3 = iVar3 + iVar4 * 0x10;
    piVar2 = &DAT_80382f14;
    iVar4 = 5;
    do {
      iVar1 = (int)*(char *)(iVar3 + *piVar2);
      if (-1 < iVar1) {
        iVar1 = *(int *)(DAT_803ddb1c + iVar1 * 4);
        local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar1 + 0x8a) - 0x32U ^ 0x80000000);
        if (((double)(float)(local_30 - DOUBLE_803df840) < param_2) &&
           (local_30 = (double)CONCAT44(0x43300000,
                                        (int)*(short *)(iVar1 + 0x8c) + 0x32U ^ 0x80000000),
           param_2 < (double)(float)(local_30 - DOUBLE_803df840))) {
          return (int)*(char *)(*piVar2 + iVar3);
        }
      }
      piVar2 = piVar2 + 1;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  return -1;
}

/*
 * --INFO--
 *
 * Function: FUN_8005b60c
 * EN v1.0 Address: 0x8005B60C
 * EN v1.0 Size: 220b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8005b60c(int param_1,int *param_2,int *param_3,int *param_4,uint *param_5)
{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  
  iVar5 = 0;
  piVar3 = &DAT_803870c8;
  iVar8 = 0x78;
  do {
    iVar2 = *piVar3;
    if (iVar2 != 0) {
      iVar7 = *(int *)(iVar2 + 0x20);
      iVar4 = 0;
      for (iVar6 = 0; DAT_803ddb20 = iVar2, iVar6 < (int)(uint)*(ushort *)(iVar2 + 8);
          iVar6 = iVar6 + iVar1) {
        if (*(int *)(iVar7 + 0x14) == param_1) {
          if (param_2 != (int *)0x0) {
            *param_2 = iVar4;
          }
          if (param_3 != (int *)0x0) {
            *param_3 = iVar5;
          }
          if (param_4 != (int *)0x0) {
            *param_4 = (int)*(char *)(DAT_803ddb20 + 0x19);
          }
          if (param_5 == (uint *)0x0) {
            return iVar7;
          }
          *param_5 = (uint)(0x4f < iVar5);
          return iVar7;
        }
        iVar1 = (uint)*(byte *)(iVar7 + 2) * 4;
        iVar7 = iVar7 + iVar1;
        iVar4 = iVar4 + 1;
      }
    }
    piVar3 = piVar3 + 1;
    iVar5 = iVar5 + 1;
    iVar8 = iVar8 + -1;
    if (iVar8 == 0) {
      return 0;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_8005b6e8
 * EN v1.0 Address: 0x8005B6E8
 * EN v1.0 Size: 232b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005b6e8(int param_1,int param_2)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  
  iVar1 = param_2 / 9 + (param_2 >> 0x1f);
  for (iVar9 = 1; iVar9 <= iVar1 - (iVar1 >> 0x1f); iVar9 = iVar9 * 3 + 1) {
  }
  for (; 0 < iVar9; iVar9 = iVar9 / 3) {
    iVar6 = iVar9 + 1;
    iVar1 = iVar6 * 4;
    iVar5 = param_1 + iVar1;
    iVar2 = (param_2 + 1) - iVar6;
    if (iVar6 <= param_2) {
      do {
        uVar8 = *(uint *)(iVar5 + -4);
        iVar4 = param_1 + iVar1;
        iVar7 = iVar6;
        while ((iVar9 < iVar7 &&
               (uVar3 = *(uint *)(param_1 + (iVar7 - iVar9) * 4 + -4), uVar3 < uVar8))) {
          *(uint *)(iVar4 + -4) = uVar3;
          iVar4 = iVar4 + iVar9 * -4;
          iVar7 = iVar7 - iVar9;
        }
        *(uint *)(param_1 + iVar7 * 4 + -4) = uVar8;
        iVar5 = iVar5 + 4;
        iVar6 = iVar6 + 1;
        iVar1 = iVar1 + 4;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005b7d0
 * EN v1.0 Address: 0x8005B7D0
 * EN v1.0 Size: 1132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005b7d0(void)
{
  float fVar1;
  short sVar2;
  char *pcVar3;
  undefined4 *puVar4;
  int iVar5;
  ushort *puVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  ushort *puVar12;
  float local_48;
  float fStack_44;
  float fStack_40;
  int local_3c [3];
  longlong local_30;
  
  pcVar3 = (char *)FUN_80286838();
  newshadows_updateFrameState();
  puVar4 = (undefined4 *)FUN_8002e1f4((undefined4 *)0x0,(undefined4 *)0x0);
  iVar5 = FUN_8002e288(local_3c);
  for (uVar11 = 0; (int)uVar11 < local_3c[0]; uVar11 = uVar11 + 1) {
    puVar12 = (ushort *)*puVar4;
    puVar12[0x58] = puVar12[0x58] & 0xf7ff;
    puVar6 = puVar12;
    for (iVar9 = 0; iVar9 < (int)(uint)*(byte *)((int)puVar12 + 0xeb); iVar9 = iVar9 + 1) {
      iVar8 = *(int *)(puVar6 + 100);
      if (iVar8 != 0) {
        *(ushort *)(iVar8 + 0xb0) = *(ushort *)(iVar8 + 0xb0) & 0xf7ff;
      }
      puVar6 = puVar6 + 2;
    }
    if (iVar5 <= (int)uVar11) {
      uVar7 = FUN_8005a310((int)puVar12);
      *pcVar3 = (char)uVar7;
      if ((*pcVar3 == '\0') && ((*(uint *)(*(int *)(puVar12 + 0x28) + 0x44) & 0x200000) == 0)) {
        iVar9 = *(int *)(puVar12 + 0x2a);
        if ((iVar9 != 0) && ((*(byte *)(iVar9 + 0x62) & 0x30) != 0)) {
          *(undefined *)(iVar9 + 0xaf) = 2;
        }
      }
      else {
        if ((*(uint *)(*(int *)(puVar12 + 0x28) + 0x44) & 0x80000) == 0) {
          if (*(int *)(puVar12 + 0x18) == 0) {
            FUN_8000ef68((double)(*(float *)(puVar12 + 6) - FLOAT_803dda58),
                         (double)*(float *)(puVar12 + 8),
                         (double)(*(float *)(puVar12 + 10) - FLOAT_803dda5c),&fStack_40,&fStack_44,
                         &local_48,(float *)(puVar12 + 0x52));
          }
          else {
            FUN_8000ef68((double)*(float *)(puVar12 + 0xc),(double)*(float *)(puVar12 + 0xe),
                         (double)*(float *)(puVar12 + 0x10),&fStack_40,&fStack_44,&local_48,
                         (float *)(puVar12 + 0x52));
          }
          fVar1 = FLOAT_803df88c * (FLOAT_803df85c + local_48);
        }
        else {
          local_3c[2] = (uint)*(byte *)(*(int *)(puVar12 + 0x28) + 0x74) * 100 ^ 0x80000000;
          local_3c[1] = 0x43300000;
          *(float *)(puVar12 + 0x52) =
               (float)((double)CONCAT44(0x43300000,local_3c[2]) - DOUBLE_803df840);
          fVar1 = *(float *)(puVar12 + 0x52);
        }
        local_30 = (longlong)(int)fVar1;
        if ((((puVar12[3] & 0x4000) == 0) && (*(int *)(puVar12 + 0x32) != 0)) &&
           ((*(uint *)(*(int *)(puVar12 + 0x32) + 0x30) & 4) != 0)) {
          sVar2 = *(short *)(*(int *)(puVar12 + 0x28) + 0x48);
          if ((sVar2 == 2) || (sVar2 == 1)) {
            newshadows_queueShadowCaster((int)puVar12);
          }
          else if (sVar2 == 4) {
            FUN_8006b6d4(puVar12);
          }
        }
        if (DAT_803ddb2e < 1000) {
          iVar9 = FUN_8002b660((int)puVar12);
          if (((*(char *)((int)puVar12 + 0x37) == -1) && ((puVar12[3] & 0x80) == 0)) &&
             (((*(uint *)(*(int *)(puVar12 + 0x28) + 0x44) & 0x40000) == 0 &&
              (*(int *)(iVar9 + 0x58) == 0)))) {
            uVar10 = 0x80000000;
            if (((*(uint *)(*(int *)(puVar12 + 0x28) + 0x44) & 0x800000) != 0) &&
               ((*(byte *)((int)puVar12 + 0xe5) & 2) == 0)) {
              uVar10 = ((int)(short)puVar12[0x23] & 0x3ffU) << 0x14 | 0xc0000000;
            }
            (&DAT_80387538)[DAT_803ddb2e] =
                 uVar11 & 0x3ff | (1000 - ((int)fVar1 & 0xffffU) & 0x3ff) << 10 | uVar10;
            DAT_803ddb2e = DAT_803ddb2e + 1;
            if ((((*(byte *)(*(int *)(puVar12 + 0x28) + 0x5f) & 0x20) != 0) &&
                ((puVar12[0x58] & 0x400) == 0)) && ((puVar12[3] & 0x4000) == 0)) {
              FUN_8005d2cc((int)puVar12,7,0x50);
              (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 1;
              DAT_803ddab0 = DAT_803ddab0 + 1;
            }
          }
          else {
            if (((*(uint *)(*(int *)(puVar12 + 0x28) + 0x44) & 0x800) == 0) &&
               ((*(byte *)(*(int *)(puVar12 + 0x28) + 0x5f) & 0x10) == 0)) {
              iVar9 = 7;
            }
            else {
              iVar9 = 0x1f;
            }
            FUN_8005d2cc((int)puVar12,iVar9,0);
            (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 0;
            DAT_803ddab0 = DAT_803ddab0 + 1;
            if (((*(byte *)(*(int *)(puVar12 + 0x28) + 0x5f) & 0x20) != 0) &&
               ((puVar12[3] & 0x4000) == 0)) {
              FUN_8005d2cc((int)puVar12,7,0x50);
              (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 1;
              DAT_803ddab0 = DAT_803ddab0 + 1;
            }
          }
        }
      }
    }
    puVar4 = puVar4 + 1;
    pcVar3 = pcVar3 + 1;
  }
  if (1 < DAT_803ddb2e) {
    FUN_8005b6e8(-0x7fc78ac8,(int)DAT_803ddb2e);
  }
  newshadows_renderQueuedShadowCasters();
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005bc3c
 * EN v1.0 Address: 0x8005BC3C
 * EN v1.0 Size: 456b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005bc3c(void)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  uint *puVar8;
  
  iVar2 = FUN_8028683c();
  iVar3 = FUN_8002e1f4((undefined4 *)0x0,(undefined4 *)0x0);
  puVar8 = &DAT_8038753c;
  for (iVar7 = 1; iVar7 < DAT_803ddb2e; iVar7 = iVar7 + 1) {
    iVar6 = *(int *)(iVar3 + (*puVar8 & 0x3ff) * 4);
    uVar4 = *(uint *)(*(int *)(iVar6 + 0x50) + 0x44);
    if (((uVar4 & 0x800) == 0) && ((*(byte *)(*(int *)(iVar6 + 0x50) + 0x5f) & 0x10) == 0)) {
      if ((uVar4 & 0x800000) == 0) {
        (**(code **)(*DAT_803dd6fc + 0x1c))(0,0,0,1,iVar6);
      }
      FUN_8003ba50(0,0,0,0,iVar6,1);
      iVar5 = *(int *)(iVar6 + 100);
      if ((iVar5 == 0) || (*(int *)(iVar5 + 0xc) == 0)) {
        if ((*(short *)(*(int *)(iVar6 + 0x50) + 0x48) == 3) &&
           (((*(ushort *)(iVar6 + 6) & 0x4000) == 0 && ((*(uint *)(iVar5 + 0x30) & 4) != 0)))) {
          FUN_8005d2cc(iVar6,0x13,0);
          (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 3;
          DAT_803ddab0 = DAT_803ddab0 + 1;
        }
      }
      else {
        FUN_8005d2cc(iVar6,0x13,0);
        (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 2;
        DAT_803ddab0 = DAT_803ddab0 + 1;
      }
    }
    else if ((*(char *)(iVar2 + (*puVar8 & 0x3ff)) != '\0') && (DAT_803dda70 < 0x14)) {
      piVar1 = &DAT_80382e34 + DAT_803dda70;
      DAT_803dda70 = DAT_803dda70 + 1;
      *piVar1 = iVar6;
    }
    puVar8 = puVar8 + 1;
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005be04
 * EN v1.0 Address: 0x8005BE04
 * EN v1.0 Size: 1260b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005be04(void)
{
  char *extraout_r4;
  char *pcVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  undefined4 *puVar11;
  int *piVar12;
  int iVar13;
  double in_f29;
  double dVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_1c0;
  int local_1bc;
  int local_1b8;
  int local_1b4;
  int local_1b0;
  int local_1ac;
  int local_1a8;
  int local_1a4;
  int local_1a0;
  int local_19c;
  int local_198;
  int local_194;
  int local_190;
  int local_18c;
  int local_188;
  int local_184;
  char local_180 [256];
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
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
  FUN_80286818();
  iVar7 = 4;
  piVar12 = &DAT_80382f24;
  puVar11 = &DAT_80382efc;
  dVar15 = (double)FLOAT_803df834;
  dVar16 = DOUBLE_803df840;
  do {
    iVar5 = *piVar12;
    DAT_803ddb08 = *puVar11;
    FUN_80057ea0(DAT_803dda50 + 7,DAT_803dda54 + 7,&local_190,&local_1a0,&local_1b0,&local_1c0,iVar7
                 ,1,DAT_803ddb40);
    pcVar1 = local_180;
    iVar13 = 8;
    do {
      *pcVar1 = '\0';
      pcVar1[1] = '\0';
      pcVar1[2] = '\0';
      pcVar1[3] = '\0';
      pcVar1[4] = '\0';
      pcVar1[5] = '\0';
      pcVar1[6] = '\0';
      pcVar1[7] = '\0';
      pcVar1[8] = '\0';
      pcVar1[9] = '\0';
      pcVar1[10] = '\0';
      pcVar1[0xb] = '\0';
      pcVar1[0xc] = '\0';
      pcVar1[0xd] = '\0';
      pcVar1[0xe] = '\0';
      pcVar1[0xf] = '\0';
      pcVar1[0x10] = '\0';
      pcVar1[0x11] = '\0';
      pcVar1[0x12] = '\0';
      pcVar1[0x13] = '\0';
      pcVar1[0x14] = '\0';
      pcVar1[0x15] = '\0';
      pcVar1[0x16] = '\0';
      pcVar1[0x17] = '\0';
      pcVar1[0x18] = '\0';
      pcVar1[0x19] = '\0';
      pcVar1[0x1a] = '\0';
      pcVar1[0x1b] = '\0';
      pcVar1[0x1c] = '\0';
      pcVar1[0x1d] = '\0';
      pcVar1[0x1e] = '\0';
      pcVar1[0x1f] = '\0';
      pcVar1 = pcVar1 + 0x20;
      iVar13 = iVar13 + -1;
      iVar8 = local_188;
    } while (iVar13 != 0);
    for (; iVar13 = local_198, iVar8 <= local_184; iVar8 = iVar8 + 1) {
      pcVar1 = local_180 + (iVar8 + 7) * 0x10 + local_190;
      uVar10 = (local_18c + 1) - local_190;
      if (local_190 <= local_18c) {
        uVar9 = uVar10 >> 3;
        if (uVar9 != 0) {
          do {
            builtin_strncpy(pcVar1 + 7,"\x01\x01\x01\x01\x01\x01\x01\x01",8);
            pcVar1 = pcVar1 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
          uVar10 = uVar10 & 7;
          if (uVar10 == 0) goto LAB_8005bfc4;
        }
        do {
          pcVar1[7] = '\x01';
          pcVar1 = pcVar1 + 1;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
LAB_8005bfc4:
;
    }
    for (; iVar8 = local_1a8, iVar13 <= local_194; iVar13 = iVar13 + 1) {
      pcVar1 = local_180 + (iVar13 + 7) * 0x10 + local_1a0;
      uVar10 = (local_19c + 1) - local_1a0;
      if (local_1a0 <= local_19c) {
        uVar9 = uVar10 >> 3;
        if (uVar9 != 0) {
          do {
            builtin_strncpy(pcVar1 + 7,"\x01\x01\x01\x01\x01\x01\x01\x01",8);
            pcVar1 = pcVar1 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
          uVar10 = uVar10 & 7;
          if (uVar10 == 0) goto LAB_8005c058;
        }
        do {
          pcVar1[7] = '\x01';
          pcVar1 = pcVar1 + 1;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
LAB_8005c058:
;
    }
    for (; iVar13 = local_1b8, iVar8 <= local_1a4; iVar8 = iVar8 + 1) {
      pcVar1 = local_180 + (iVar8 + 7) * 0x10 + local_1b0;
      uVar10 = (local_1ac + 1) - local_1b0;
      if (local_1b0 <= local_1ac) {
        uVar9 = uVar10 >> 3;
        if (uVar9 != 0) {
          do {
            builtin_strncpy(pcVar1 + 7,"\x01\x01\x01\x01\x01\x01\x01\x01",8);
            pcVar1 = pcVar1 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
          uVar10 = uVar10 & 7;
          if (uVar10 == 0) goto LAB_8005c0ec;
        }
        do {
          pcVar1[7] = '\x01';
          pcVar1 = pcVar1 + 1;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
LAB_8005c0ec:
;
    }
    for (; iVar13 <= local_1b4; iVar13 = iVar13 + 1) {
      pcVar1 = local_180 + (iVar13 + 7) * 0x10 + local_1c0;
      uVar10 = (local_1bc + 1) - local_1c0;
      if (local_1c0 <= local_1bc) {
        uVar9 = uVar10 >> 3;
        if (uVar9 != 0) {
          do {
            builtin_strncpy(pcVar1 + 7,"\x01\x01\x01\x01\x01\x01\x01\x01",8);
            pcVar1 = pcVar1 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
          uVar10 = uVar10 & 7;
          if (uVar10 == 0) goto LAB_8005c180;
        }
        do {
          pcVar1[7] = '\x01';
          pcVar1 = pcVar1 + 1;
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
LAB_8005c180:
;
    }
    iVar13 = 0;
    pcVar1 = extraout_r4;
    do {
      uVar10 = (uint)*pcVar1;
      iVar8 = 0;
      uStack_7c = uVar10 ^ 0x80000000;
      local_80 = 0x43300000;
      dVar14 = (double)(float)(dVar15 * (double)(float)((double)CONCAT44(0x43300000,
                                                                         uVar10 ^ 0x80000000) -
                                                       dVar16));
      pcVar4 = extraout_r4;
      do {
        uVar9 = (uint)*pcVar4;
        iVar3 = uVar10 + uVar9 * 0x10;
        iVar2 = (int)*(char *)(iVar5 + iVar3);
        if (iVar2 < 0) {
          iVar6 = 0;
LAB_8005c210:
          if ((-1 < iVar2) && (iVar2 = FUN_8005a8a4(uVar10,uVar9,iVar6), iVar2 != 0)) {
            FLOAT_803ddad8 = (float)dVar14;
            uStack_7c = uVar9 ^ 0x80000000;
            local_80 = 0x43300000;
            FLOAT_803ddad4 =
                 FLOAT_803df834 * (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803df840);
            uStack_74 = (int)*(short *)(iVar6 + 0x8e) ^ 0x80000000;
            local_78 = 0x43300000;
            FUN_80247a48(dVar14,(double)(float)((double)CONCAT44(0x43300000,uStack_74) -
                                               DOUBLE_803df840),(double)FLOAT_803ddad4,
                         (undefined4 *)(iVar6 + 0xc));
            FUN_8005fd40();
          }
        }
        else {
          iVar6 = *(int *)(DAT_803ddb1c + iVar2 * 4);
          *(ushort *)(iVar6 + 4) = *(ushort *)(iVar6 + 4) ^ 1;
          if (local_180[iVar3] != '\0') goto LAB_8005c210;
        }
        iVar8 = iVar8 + 1;
        pcVar4 = pcVar4 + 1;
      } while (iVar8 < 0x10);
      iVar13 = iVar13 + 1;
      pcVar1 = pcVar1 + 1;
    } while (iVar13 < 0x10);
    piVar12 = piVar12 + -1;
    puVar11 = puVar11 + -1;
    iVar7 = iVar7 + -1;
    if (iVar7 < 0) {
      FUN_80286864();
      return;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_8005c2f0
 * EN v1.0 Address: 0x8005C2F0
 * EN v1.0 Size: 1500b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005c2f0(void)
{
  float *pfVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  uint local_288;
  float local_284;
  float local_280;
  undefined4 local_27c;
  undefined auStack_278 [616];
  
  DAT_803ddab4 = FUN_8009461c(&local_280,&local_284);
  if (DAT_803ddab4 != 0) {
    DAT_80382c68 = FLOAT_803df890;
    DAT_80382c6c = FLOAT_803df84c;
    DAT_80382c70 = FLOAT_803df84c;
    DAT_80382c74 = FLOAT_803df890 * FLOAT_803dda58 + local_280;
    DAT_80382c78 = FLOAT_803df84c;
    DAT_80382c7c = FLOAT_803df84c;
    DAT_80382c80 = FLOAT_803df890;
    DAT_80382c84 = FLOAT_803df890 * FLOAT_803dda5c + local_284;
    DAT_80382c88 = FLOAT_803df84c;
    DAT_80382c8c = FLOAT_803df84c;
    DAT_80382c90 = FLOAT_803df84c;
    DAT_80382c94 = FLOAT_803df85c;
    pfVar1 = (float *)FUN_8000f578();
    FUN_80247618(&DAT_80382c68,pfVar1,&DAT_80382c68);
  }
  FUN_8005a5d8((undefined4 *)&DAT_80382e84);
  FUN_80062a10();
  FUN_80062984();
  DAT_803ddb2e = 1;
  DAT_803ddb2c = 0;
  DAT_803dda86 = 0;
  newshadows_refreshShadowCaptureTexture();
  DAT_803ddab0 = 0;
  FUN_8005b7d0();
  FUN_80053078();
  FUN_8012a0f0();
  FUN_80258c24();
  FUN_8000f11c();
  FUN_8000f584();
  FUN_8000fb20();
  iVar2 = 0;
  if (((DAT_803dda68 & 0x40) != 0) && ((DAT_803dda68 & 0x80000) == 0)) {
    iVar2 = 1;
  }
  if ((DAT_803dda68 & 0x40000) == 0) {
    (**(code **)(*DAT_803dd6d8 + 0x10))(0,0,0,0,iVar2);
    (**(code **)(*DAT_803dd6e4 + 0x10))(0,0,0,0);
    FUN_80093d6c();
  }
  else {
    (**(code **)(*DAT_803dd6d8 + 0x38))(0,0);
    if (iVar2 != 0) {
      FUN_80093d6c();
    }
    (**(code **)(*DAT_803dd6d8 + 0x10))(0,0,0,0,iVar2);
    if ((DAT_803dda68 & 0x10) != 0) {
      (**(code **)(*DAT_803dd6e4 + 0x10))(0,0,0,0);
    }
  }
  if (DAT_803dda85 != '\0') {
    FUN_80071050(DAT_803dda85);
  }
  FUN_8008fd80();
  (**(code **)(*DAT_803dd6dc + 0x10))(0);
  DAT_803dda70 = 0;
  FUN_80089b54(0,(undefined *)&local_27c,(undefined *)((int)&local_27c + 1),
               (undefined *)((int)&local_27c + 2));
  FUN_8025a608(0,1,0,1,0,0,2);
  FUN_8025a608(2,0,0,1,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  local_288 = local_27c;
  FUN_8025a2ec(0,&local_288);
  FUN_8025a5bc(1);
  FUN_8005be04();
  FUN_8003fd58();
  FUN_8005bc3c();
  uVar3 = FUN_8000e640();
  if (((uVar3 & 0xff) != 0) || (DAT_803dda77 != '\0')) {
    FUN_8007ae8c((double)FLOAT_803dc28c);
  }
  iVar2 = FUN_80020800();
  if (iVar2 == 0) {
    newshadows_flushShadowRenderTargets();
  }
  if (DAT_803dda74 != '\0') {
    FUN_8007b198((double)FLOAT_803ddad0,(double)FLOAT_803ddacc,(double)FLOAT_803ddac8,DAT_803dda75,
                 DAT_803dda7b);
  }
  if (DAT_803dda7c != 0) {
    FUN_8007a898(DAT_803dda7c & 0xff);
  }
  piVar5 = &DAT_80382e34;
  for (iVar2 = 0; iVar2 < DAT_803dda70; iVar2 = iVar2 + 1) {
    (**(code **)(*DAT_803dd6fc + 0x1c))(0,0,0,1,*piVar5);
    FUN_8003ba50(0,0,0,0,*piVar5,1);
    piVar5 = piVar5 + 1;
  }
  FUN_8009ef70();
  FUN_8005be04();
  FUN_8005be04();
  if (DAT_803ddab0 == 1000) {
    FUN_8005dcb4();
    DAT_803ddab0 = 0;
  }
  iVar2 = DAT_803ddab0;
  (&DAT_8037ed28)[DAT_803ddab0 * 4] = 0x78000000;
  (&DAT_8037ed2c)[iVar2 * 4] = 8;
  DAT_803ddab0 = DAT_803ddab0 + 1;
  if (DAT_803ddab0 == 1000) {
    FUN_8005dcb4();
    DAT_803ddab0 = 0;
  }
  iVar2 = DAT_803ddab0;
  (&DAT_8037ed28)[DAT_803ddab0 * 4] = 0x50000000;
  (&DAT_8037ed2c)[iVar2 * 4] = 9;
  DAT_803ddab0 = DAT_803ddab0 + 1;
  FUN_8005dcb4();
  (**(code **)(*DAT_803dd6fc + 0x30))(auStack_278);
  (**(code **)(*DAT_803dd6fc + 0x1c))(0,0,0,0,0);
  iVar2 = FUN_8002bac4();
  if (iVar2 != 0) {
    iVar6 = iVar2;
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar2 + 0xeb); iVar4 = iVar4 + 1) {
      if (*(short *)(*(int *)(iVar6 + 200) + 0x44) == 0x2d) {
        (**(code **)(**(int **)(*(int *)(iVar6 + 200) + 0x68) + 0x2c))();
      }
      iVar6 = iVar6 + 4;
    }
  }
  FUN_8016e0a0();
  (**(code **)(*DAT_803dd6e0 + 0x14))(0);
  if (DAT_803dda76 != '\0') {
    newshadows_flushShadowRenderTargets();
    FUN_8007242c((double)FLOAT_803ddac4,(double)FLOAT_803ddabc,(float *)&DAT_80382e28,&DAT_803ddac0)
    ;
  }
  FUN_8005ffa4();
  (**(code **)(*DAT_803dd6d0 + 0x58))(0,0,0,0);
  if (DAT_803dda78 == '\0') {
    if (DAT_803dda79 != '\0') {
      FUN_80071978();
    }
  }
  else {
    FUN_80071ed0(&DAT_803dc290);
  }
  if (DAT_803dda7a != '\0') {
    FUN_80079be0((double)FLOAT_803df894,(double)FLOAT_803df898,0x40,'\0');
  }
  if (DAT_803ddab8 == 1) {
    FUN_80071ed0(&DAT_803dc290);
  }
  FUN_80062a54(0);
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8005C8CC
 * EN v1.0 Address: 0x8005C8CC
 * EN v1.0 Size: 152b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8005C8CC(void)
{
  DAT_803dda68 = DAT_803dda68 | 0x21;
  if ((DAT_803ddb24 == '\x01') || (DAT_803ddb24 == '\x03')) {
    DAT_803dda68 = DAT_803dda68 & 0xfffffffe;
  }
  FUN_8000f11c();
  FUN_8005acec();
  FUN_8005ab2c();
  FUN_8000faf8();
  FUN_8000f584();
  FUN_8000fb20();
  FUN_8001f0c0();
  DAT_803ddb28 = (int)FUN_8000facc();
  FUN_8005c2f0();
  FUN_8000e964();
  DAT_803dda68 = DAT_803dda68 & 0xfffffffd;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005c964
 * EN v1.0 Address: 0x8005C964
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005c964(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005c968
 * EN v1.0 Address: 0x8005C968
 * EN v1.0 Size: 608b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005c968(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)
{
  double dVar1;
  int iVar2;
  int *piVar3;
  float *pfVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  
  if (param_9 == 0) {
    FUN_80088b10(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    (**(code **)(*DAT_803dd6e4 + 0xc))();
    (**(code **)(*DAT_803dd6dc + 0xc))();
    (**(code **)(*DAT_803dd6d8 + 0xc))();
    dVar7 = (double)(**(code **)(*DAT_803dd6e0 + 0x10))();
    iVar6 = 0;
    iVar5 = 0;
    do {
      piVar3 = (int *)(DAT_803ddaec + iVar5);
      if ((((*(short *)(piVar3 + 3) != 0) && (iVar2 = *piVar3, iVar2 != 0)) &&
          (*(short *)(iVar2 + 0x10) != 0x100)) && (*(short *)(iVar2 + 0x14) != 0)) {
        dVar7 = (double)FUN_800540a8(iVar2,(uint *)(piVar3 + 2),piVar3 + 1);
      }
      iVar5 = iVar5 + 0x10;
      iVar6 = iVar6 + 1;
    } while (iVar6 < 0x50);
    iVar5 = 0;
    iVar6 = 0x1d;
    do {
      dVar1 = DOUBLE_803df840;
      pfVar4 = (float *)(DAT_803ddae8 + iVar5);
      if (*(char *)(pfVar4 + 3) != '\0') {
        param_4 = (double)FLOAT_803dc074;
        param_3 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (int)*(short *)((int)pfVar4 + 10)
                                                                   ^ 0x80000000) - DOUBLE_803df840)
                                 * param_4);
        dVar7 = (double)*pfVar4;
        *pfVar4 = (float)(dVar7 + (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                   (int)*(short *)(pfVar4 + 2)
                                                                                   ^ 0x80000000) - DOUBLE_803df840)
                                                 * param_4));
        pfVar4[1] = (float)((double)pfVar4[1] + param_3);
        param_2 = dVar1;
      }
      dVar1 = DOUBLE_803df840;
      pfVar4 = (float *)(DAT_803ddae8 + iVar5 + 0x10);
      if (*(char *)(pfVar4 + 3) != '\0') {
        param_4 = (double)FLOAT_803dc074;
        param_3 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (int)*(short *)((int)pfVar4 + 10)
                                                                   ^ 0x80000000) - DOUBLE_803df840)
                                 * param_4);
        dVar7 = (double)*pfVar4;
        *pfVar4 = (float)(dVar7 + (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                   (int)*(short *)(pfVar4 + 2)
                                                                                   ^ 0x80000000) - DOUBLE_803df840)
                                                 * param_4));
        pfVar4[1] = (float)((double)pfVar4[1] + param_3);
        param_2 = dVar1;
      }
      iVar5 = iVar5 + 0x20;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    FUN_800552ac(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (DAT_803dd730 != (undefined4 *)0x0) {
      (**(code **)(*DAT_803dd730 + 8))();
    }
    (**(code **)(*DAT_803dd73c + 4))();
    if (DAT_803dda80 != 0) {
      DAT_803dda7c = DAT_803dda7c + DAT_803dda80;
      if ((int)DAT_803dda7c < 0) {
        DAT_803dda7c = 0;
        DAT_803dda80 = 0;
      }
      else if (0xff < (int)DAT_803dda7c) {
        DAT_803dda7c = 0xff;
        DAT_803dda80 = 0;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005cbc8
 * EN v1.0 Address: 0x8005CBC8
 * EN v1.0 Size: 728b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005cbc8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int *puVar1;
  short *psVar2;
  undefined4 uVar3;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  undefined8 uVar5;
  
  DAT_803dda68 = 0;
  DAT_803ddb1c = FUN_80023d8c(0x100,5);
  DAT_803ddb14 = FUN_80023d8c(0x80,5);
  DAT_803ddb0c = FUN_80023d8c(0x40,5);
  DAT_803ddaf8 = FUN_80023d8c(0xd48,5);
  DAT_80382f14 = FUN_80023d8c(0x500,5);
  DAT_80382f00 = FUN_80023d8c(0x3c00,5);
  uVar3 = 0;
  DAT_80382eec = FUN_80023d8c(0x500,5);
  DAT_80382f18 = DAT_80382f14 + 0x100;
  DAT_80382f04 = DAT_80382f00 + 0xc00;
  DAT_80382ef0 = DAT_80382eec + 0x100;
  DAT_80382f1c = DAT_80382f14 + 0x200;
  DAT_80382f08 = DAT_80382f00 + 0x1800;
  DAT_80382ef4 = DAT_80382eec + 0x200;
  DAT_80382f20 = DAT_80382f14 + 0x300;
  DAT_80382f0c = DAT_80382f00 + 0x2400;
  DAT_80382ef8 = DAT_80382eec + 0x300;
  DAT_80382f24 = DAT_80382f14 + 0x400;
  DAT_80382f10 = DAT_80382f00 + 0x3000;
  DAT_80382efc = DAT_80382eec + 0x400;
  uVar5 = FUN_8001f82c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803ddafc
                       ,0x1e,uVar3,in_r6,in_r7,in_r8,in_r9,in_r10);
  uVar5 = FUN_8001f82c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803ddb00,
                       0x29,uVar3,in_r6,in_r7,in_r8,in_r9,in_r10);
  puVar1 = &DAT_803870c8;
  iVar4 = 3;
  do {
    *puVar1 = 0;
    puVar1[1] = 0;
    puVar1[2] = 0;
    puVar1[3] = 0;
    puVar1[4] = 0;
    puVar1[5] = 0;
    puVar1[6] = 0;
    puVar1[7] = 0;
    puVar1[8] = 0;
    puVar1[9] = 0;
    puVar1[10] = 0;
    puVar1[0xb] = 0;
    puVar1[0xc] = 0;
    puVar1[0xd] = 0;
    puVar1[0xe] = 0;
    puVar1[0xf] = 0;
    puVar1[0x10] = 0;
    puVar1[0x11] = 0;
    puVar1[0x12] = 0;
    puVar1[0x13] = 0;
    puVar1[0x14] = 0;
    puVar1[0x15] = 0;
    puVar1[0x16] = 0;
    puVar1[0x17] = 0;
    puVar1[0x18] = 0;
    puVar1[0x19] = 0;
    puVar1[0x1a] = 0;
    puVar1[0x1b] = 0;
    puVar1[0x1c] = 0;
    puVar1[0x1d] = 0;
    puVar1[0x1e] = 0;
    puVar1[0x1f] = 0;
    puVar1[0x20] = 0;
    puVar1[0x21] = 0;
    puVar1[0x22] = 0;
    puVar1[0x23] = 0;
    puVar1[0x24] = 0;
    puVar1[0x25] = 0;
    puVar1[0x26] = 0;
    puVar1[0x27] = 0;
    puVar1 = puVar1 + 0x28;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  FUN_8001f82c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803ddb04,0x27,
               uVar3,in_r6,in_r7,in_r8,in_r9,in_r10);
  DAT_803ddb10 = 0;
  for (psVar2 = DAT_803ddb04; *psVar2 != -1; psVar2 = psVar2 + 1) {
    DAT_803ddb10 = DAT_803ddb10 + 1;
  }
  DAT_803ddb10 = DAT_803ddb10 + -1;
  DAT_803ddb3a = 0xffff;
  DAT_803ddb38 = 0xfffe;
  DAT_803ddaec = FUN_80023d8c(0x500,5);
  FUN_800033a8(DAT_803ddaec,0,0x500);
  DAT_803ddae8 = FUN_80023d8c(0x3a0,5);
  FUN_800033a8(DAT_803ddae8,0,0x3a0);
  FUN_800033a8(&DAT_80387538,0,4000);
  DAT_80387538 = 0xffffffff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005cea0
 * EN v1.0 Address: 0x8005CEA0
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005cea0(int param_1)
{
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xfffdffff;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x20000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005cec4
 * EN v1.0 Address: 0x8005CEC4
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8005cec4(void)
{
  return DAT_803dda68 & 0x10000;
}

/*
 * --INFO--
 *
 * Function: FUN_8005ced0
 * EN v1.0 Address: 0x8005CED0
 * EN v1.0 Size: 92b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8005ced0(char param_1)
{
  if (param_1 == '\0') {
    DAT_803dda68 = DAT_803dda68 & 0xfffffff7;
    FUN_8000fc4c((double)FLOAT_803dc2d0);
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 8;
    FUN_8000fc4c((double)FLOAT_803df89c);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8005cf2c
 * EN v1.0 Address: 0x8005CF2C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8005cf2c(void)
{
  return DAT_803dda68 & 8;
}

/*
 * --INFO--
 *
 * Function: FUN_8005cf38
 * EN v1.0 Address: 0x8005CF38
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8005cf38(void)
{
  return DAT_803dda68 & 0x80;
}

/*
 * --INFO--
 *
 * Function: FUN_8005cf44
 * EN v1.0 Address: 0x8005CF44
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8005cf44(void)
{
  return DAT_803dda68 & 0x10;
}

/*
 * --INFO--
 *
 * Function: FUN_8005cf50
 * EN v1.0 Address: 0x8005CF50
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005cf50(int param_1)
{
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 | 0x2000;
  }
  else {
    DAT_803dda68 = DAT_803dda68 & 0xffffdfff;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005cf74
 * EN v1.0 Address: 0x8005CF74
 * EN v1.0 Size: 116b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005cf74(int param_1)
{
  undefined4 *puVar1;
  
  puVar1 = FUN_800e877c();
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xffffffbf;
    *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) & 0xf7;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x40;
    *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) | 8;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005cfe8
 * EN v1.0 Address: 0x8005CFE8
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005cfe8(int param_1)
{
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xffffffdf;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x20;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d00c
 * EN v1.0 Address: 0x8005D00C
 * EN v1.0 Size: 24b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8005d00c(void)
{
  return -(DAT_803dda68 & 0x40000) >> 0x1f;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d024
 * EN v1.0 Address: 0x8005D024
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d024(int param_1)
{
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xfffbffff;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x40000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d048
 * EN v1.0 Address: 0x8005D048
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d048(int param_1)
{
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xfff7ffff;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x80000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d06c
 * EN v1.0 Address: 0x8005D06C
 * EN v1.0 Size: 120b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d06c(int param_1)
{
  undefined4 *puVar1;
  
  puVar1 = FUN_800e877c();
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xffffffaf;
    *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) & 0xf6;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x50;
    *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) | 9;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d0e4
 * EN v1.0 Address: 0x8005D0E4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d0e4(int param_1)
{
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xffffefff;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x1000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8005D108
 * EN v1.0 Address: 0x8005D108
 * EN v1.0 Size: 304b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8005D108(int param_1,int param_2,int param_3)
{
  volatile byte *fifo8;
  volatile ushort *fifo16;
  undefined2 *puVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  fifo8 = (volatile byte *)&DAT_cc008000;
  fifo16 = (volatile ushort *)&DAT_cc008000;
  FUN_80257b5c();
  FUN_802570dc(0,1);
  FUN_802570dc(9,1);
  FUN_802570dc(0xb,1);
  FUN_802570dc(0xd,1);
  FUN_80259000(0x90,0,param_3 * 3 & 0xffff);
  for (iVar4 = 0; iVar4 < param_3; iVar4 = iVar4 + 1) {
    iVar5 = 0;
    iVar6 = 3;
    do {
      *fifo8 = 0;
      iVar2 = iVar5 + 1;
      puVar1 = (undefined2 *)(param_1 + (uint)*(byte *)(param_2 + iVar2) * 0x10);
      *fifo16 = *puVar1;
      *fifo16 = puVar1[1];
      *fifo16 = puVar1[2];
      iVar3 = param_1 + (uint)*(byte *)(param_2 + iVar2) * 0x10;
      *fifo8 = *(undefined *)(iVar3 + 0xc);
      *fifo8 = *(undefined *)(iVar3 + 0xd);
      *fifo8 = *(undefined *)(iVar3 + 0xe);
      *fifo8 = *(undefined *)(iVar3 + 0xf);
      iVar2 = param_1 + (uint)*(byte *)(param_2 + iVar2) * 0x10;
      *fifo16 = *(undefined2 *)(iVar2 + 8);
      *fifo16 = *(undefined2 *)(iVar2 + 10);
      iVar5 = iVar5 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    param_2 = param_2 + 0x10;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d238
 * EN v1.0 Address: 0x8005D238
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d238(undefined4 param_1,undefined param_2,undefined param_3,undefined param_4)
{
  trackIntersect_setColorRgb(param_2,param_3,param_4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d264
 * EN v1.0 Address: 0x8005D264
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d264(undefined4 param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5)
{
  FUN_80079ba0(param_2,param_3,param_4,param_5);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d294
 * EN v1.0 Address: 0x8005D294
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d294(undefined4 param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5)
{
  FUN_80079b60(param_2,param_3,param_4,param_5);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d2c4
 * EN v1.0 Address: 0x8005D2C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d2c4(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d2c8
 * EN v1.0 Address: 0x8005D2C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d2c8(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d2cc
 * EN v1.0 Address: 0x8005D2CC
 * EN v1.0 Size: 288b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d2cc(int param_1,int param_2,int param_3)
{
  int iVar1;
  uint uVar2;
  float *pfVar3;
  float local_28;
  undefined4 local_24;
  float local_20;
  
  if (DAT_803ddab0 == 1000) {
    FUN_8005dcb4();
    DAT_803ddab0 = 0;
  }
  if (*(int *)(param_1 + 0x30) == 0) {
    local_28 = *(float *)(param_1 + 0x18) - FLOAT_803dda58;
    local_24 = *(undefined4 *)(param_1 + 0x1c);
    local_20 = *(float *)(param_1 + 0x20) - FLOAT_803dda5c;
  }
  else {
    local_28 = *(float *)(param_1 + 0x18);
    local_24 = *(undefined4 *)(param_1 + 0x1c);
    local_20 = *(float *)(param_1 + 0x20);
  }
  pfVar3 = (float *)FUN_8000f56c();
  FUN_80247bf8(pfVar3,&local_28,&local_28);
  iVar1 = DAT_803ddab0;
  uVar2 = (int)-local_20 + param_3;
  if ((int)uVar2 < 0) {
    uVar2 = 0;
  }
  else if (0x7ffffff < (int)uVar2) {
    uVar2 = 0x7ffffff;
  }
  (&DAT_8037ed20)[DAT_803ddab0 * 4] = param_1;
  (&DAT_8037ed28)[iVar1 * 4] = uVar2 | param_2 << 0x1b;
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8005D3EC
 * EN v1.0 Address: 0x8005D3EC
 * EN v1.0 Size: 324b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8005D3EC(void)
{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  uint uVar9;
  int iVar10;
  undefined4 *puVar11;
  undefined4 *puVar12;
  int iVar12;
  
  puVar12 = &DAT_8037ed10;
  iVar1 = (DAT_803ddab0 + -1) / 9 + (DAT_803ddab0 + -1 >> 0x1f);
  for (iVar7 = 1; iVar7 <= iVar1 - (iVar1 >> 0x1f); iVar7 = iVar7 * 3 + 1) {
  }
  for (; 0 < iVar7; iVar7 = iVar7 / 3) {
    iVar6 = iVar7 + 1;
    iVar1 = iVar6 * 0x10;
    puVar11 = puVar12 + iVar6 * 4;
    for (; iVar6 <= DAT_803ddab0; iVar6 = iVar6 + 1) {
      uVar8 = puVar11[-4];
      uVar2 = puVar11[-3];
      uVar9 = puVar11[-2];
      uVar3 = puVar11[-1];
      iVar10 = (int)(puVar12 + iVar6 * 4);
      iVar12 = iVar6;
      while ((iVar7 < iVar12 &&
             (iVar5 = iVar12 - iVar7, (uint)puVar12[iVar5 * 4 + 2] < uVar9))) {
        uVar4 = puVar12[iVar5 * 4 + 1];
        *(undefined4 *)(iVar10 + -0x10) = puVar12[iVar5 * 4];
        *(undefined4 *)(iVar10 + -0xc) = uVar4;
        uVar4 = puVar12[iVar5 * 4 + 3];
        *(undefined4 *)(iVar10 + -8) = puVar12[iVar5 * 4 + 2];
        *(undefined4 *)(iVar10 + -4) = uVar4;
        iVar10 = iVar10 + iVar7 * -0x10;
        iVar12 = iVar12 - iVar7;
      }
      puVar12[iVar12 * 4] = uVar8;
      puVar12[iVar12 * 4 + 1] = uVar2;
      puVar12[iVar12 * 4 + 2] = uVar9;
      puVar12[iVar12 * 4 + 3] = uVar3;
      puVar11 = puVar11 + 4;
      iVar1 = iVar1 + 0x10;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d530
 * EN v1.0 Address: 0x8005D530
 * EN v1.0 Size: 312b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d530(int param_1,int param_2,int param_3)
{
  int iVar1;
  float *pfVar2;
  uint uVar3;
  double dVar4;
  float local_28;
  float local_24;
  float local_20;
  
  if (DAT_803ddab0 == 1000) {
    FUN_8005dcb4();
    DAT_803ddab0 = 0;
  }
  dVar4 = (double)FLOAT_803df8a0;
  local_28 = FLOAT_803df87c *
             ((float)((double)((longlong)(double)*(short *)(param_1 + 6) * 0x3ff0000000000000) *
                      dVar4 + (double)*(float *)(param_2 + 0x18)) +
             (float)((double)((longlong)(double)*(short *)(param_1 + 0xc) * 0x3ff0000000000000) *
                     dVar4 + (double)*(float *)(param_2 + 0x18)));
  local_24 = FLOAT_803df87c *
             ((float)((double)((longlong)(double)*(short *)(param_1 + 8) * 0x3ff0000000000000) *
                      dVar4 + (double)*(float *)(param_2 + 0x28)) +
             (float)((double)((longlong)(double)*(short *)(param_1 + 0xe) * 0x3ff0000000000000) *
                     dVar4 + (double)*(float *)(param_2 + 0x28)));
  local_20 = FLOAT_803df87c *
             ((float)((double)((longlong)(double)*(short *)(param_1 + 10) * 0x3ff0000000000000) *
                      dVar4 + (double)*(float *)(param_2 + 0x38)) +
             (float)((double)((longlong)(double)*(short *)(param_1 + 0x10) * 0x3ff0000000000000) *
                     dVar4 + (double)*(float *)(param_2 + 0x38)));
  pfVar2 = (float *)FUN_8000f56c();
  FUN_80247bf8(pfVar2,&local_28,&local_28);
  iVar1 = DAT_803ddab0;
  uVar3 = (uint)-local_20;
  if ((int)uVar3 < 0) {
    uVar3 = 0;
  }
  else if (0x7ffffff < (int)uVar3) {
    uVar3 = 0x7ffffff;
  }
  (&DAT_8037ed20)[DAT_803ddab0 * 4] = param_1;
  (&DAT_8037ed24)[iVar1 * 4] = param_2;
  (&DAT_8037ed28)[iVar1 * 4] = uVar3 | param_3 << 0x1b;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d668
 * EN v1.0 Address: 0x8005D668
 * EN v1.0 Size: 432b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d668(int param_1,int param_2,float *param_3)
{
  uint3 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int local_28 [4];
  int local_18;
  
  uVar5 = (uint)*(ushort *)(param_2 + 0x84) << 3;
  FUN_80013a84(local_28,*(undefined4 *)(param_2 + 0x78),uVar5,uVar5);
  FUN_80013a7c((int)local_28,(uint)*(ushort *)(param_1 + 0x14));
  local_18 = local_18 + 4;
  FUN_8005e8ac(param_1,param_2,param_3);
  iVar3 = FUN_8005e6dc(param_2,local_28);
  local_18 = local_18 + 4;
  FUN_8005fa9c('\x01',param_2,iVar3,local_28);
  uVar5 = local_18 + 4;
  iVar2 = (int)uVar5 >> 3;
  iVar4 = local_28[0] + iVar2;
  local_18 = local_18 + 8;
  uVar1 = CONCAT12(*(undefined *)(iVar4 + 2),
                   CONCAT11(*(undefined *)(iVar4 + 1),*(undefined *)(local_28[0] + iVar2))) >>
          (uVar5 & 7);
  uVar5 = uVar1 & 0xf;
  iVar2 = 0;
  if ((uVar1 & 0xf) != 0) {
    if ((8 < uVar5) && (uVar6 = uVar5 - 1 >> 3, 0 < (int)(uVar5 - 8))) {
      do {
        local_18 = local_18 + 0x40;
        iVar2 = iVar2 + 8;
        uVar6 = uVar6 - 1;
      } while (uVar6 != 0);
    }
    iVar4 = uVar5 - iVar2;
    if (iVar2 < (int)uVar5) {
      do {
        local_18 = local_18 + 8;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  local_18 = local_18 + 4;
  FUN_8005e4c4(param_2,iVar3,local_28,param_3);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005d818
 * EN v1.0 Address: 0x8005D818
 * EN v1.0 Size: 504b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005d818(int param_1,int param_2,float *param_3)
{
  uint3 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int local_58 [4];
  int local_48;
  float afStack_44 [14];
  
  FUN_80247618((float *)&DAT_803974b0,param_3,afStack_44);
  FUN_8025d8c4(afStack_44,0x1e,0);
  FUN_80247618((float *)&DAT_80397480,param_3,afStack_44);
  FUN_8025d8c4(afStack_44,0x21,0);
  FUN_8007d0f8();
  uVar5 = (uint)*(ushort *)(param_2 + 0x88) << 3;
  FUN_80013a84(local_58,*(undefined4 *)(param_2 + 0x80),uVar5,uVar5);
  FUN_80013a7c((int)local_58,(uint)*(ushort *)(param_1 + 0x14));
  local_48 = local_48 + 4;
  iVar3 = FUN_8005f6d4('\x01',param_2,local_58);
  local_48 = local_48 + 4;
  FUN_8005fa9c('\x01',param_2,iVar3,local_58);
  uVar5 = local_48 + 4;
  iVar2 = (int)uVar5 >> 3;
  iVar4 = local_58[0] + iVar2;
  local_48 = local_48 + 8;
  uVar1 = CONCAT12(*(undefined *)(iVar4 + 2),
                   CONCAT11(*(undefined *)(iVar4 + 1),*(undefined *)(local_58[0] + iVar2))) >>
          (uVar5 & 7);
  uVar5 = uVar1 & 0xf;
  iVar2 = 0;
  if ((uVar1 & 0xf) != 0) {
    if ((8 < uVar5) && (uVar6 = uVar5 - 1 >> 3, 0 < (int)(uVar5 - 8))) {
      do {
        local_48 = local_48 + 0x40;
        iVar2 = iVar2 + 8;
        uVar6 = uVar6 - 1;
      } while (uVar6 != 0);
    }
    iVar4 = uVar5 - iVar2;
    if (iVar2 < (int)uVar5) {
      do {
        local_48 = local_48 + 8;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  local_48 = local_48 + 4;
  FUN_8005edfc(1,1,param_2,iVar3,local_58,param_3);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005da10
 * EN v1.0 Address: 0x8005DA10
 * EN v1.0 Size: 436b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005da10(int param_1,int param_2,float *param_3)
{
  uint3 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int local_28 [4];
  int local_18;
  
  FUN_8000f918();
  uVar5 = (uint)*(ushort *)(param_2 + 0x86) << 3;
  FUN_80013a84(local_28,*(undefined4 *)(param_2 + 0x7c),uVar5,uVar5);
  FUN_80013a7c((int)local_28,(uint)*(ushort *)(param_1 + 0x14));
  local_18 = local_18 + 4;
  iVar3 = FUN_8005f6d4('\x01',param_2,local_28);
  local_18 = local_18 + 4;
  FUN_8005fa9c('\x01',param_2,iVar3,local_28);
  uVar5 = local_18 + 4;
  iVar2 = (int)uVar5 >> 3;
  iVar4 = local_28[0] + iVar2;
  local_18 = local_18 + 8;
  uVar1 = CONCAT12(*(undefined *)(iVar4 + 2),
                   CONCAT11(*(undefined *)(iVar4 + 1),*(undefined *)(local_28[0] + iVar2))) >>
          (uVar5 & 7);
  uVar5 = uVar1 & 0xf;
  iVar2 = 0;
  if ((uVar1 & 0xf) != 0) {
    if ((8 < uVar5) && (uVar6 = uVar5 - 1 >> 3, 0 < (int)(uVar5 - 8))) {
      do {
        local_18 = local_18 + 0x40;
        iVar2 = iVar2 + 8;
        uVar6 = uVar6 - 1;
      } while (uVar6 != 0);
    }
    iVar4 = uVar5 - iVar2;
    if (iVar2 < (int)uVar5) {
      do {
        local_18 = local_18 + 8;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  local_18 = local_18 + 4;
  FUN_8005edfc(1,1,param_2,iVar3,local_28,param_3);
  FUN_8000f7a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005dbc4
 * EN v1.0 Address: 0x8005DBC4
 * EN v1.0 Size: 240b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005dbc4(ushort *param_1)
{
  int iVar1;
  
  iVar1 = FUN_8002b660((int)param_1);
  if (*(int *)(iVar1 + 0x58) == 0) {
    (**(code **)(*DAT_803dd6fc + 0x1c))(0,0,0,1,param_1);
    FUN_8003fd58();
    FUN_8003ba50(0,0,0,0,(int)param_1,1);
    FUN_8000f9d4();
    if ((*(int *)(param_1 + 0x32) == 0) || (*(int *)(*(int *)(param_1 + 0x32) + 0xc) == 0)) {
      if (*(short *)(*(int *)(param_1 + 0x28) + 0x48) == 3) {
        FUN_800617d0(param_1,iVar1);
      }
    }
    else {
      FUN_80062614();
    }
    FUN_8000f7a0();
  }
  else {
    FUN_8003da78(param_1,iVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005dcb4
 * EN v1.0 Address: 0x8005DCB4
 * EN v1.0 Size: 860b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005dcb4(void)
{
  byte bVar2;
  float *pfVar1;
  int iVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  undefined4 local_88;
  uint local_84;
  undefined4 local_80;
  uint local_7c;
  undefined4 local_78;
  uint local_74;
  float afStack_70 [28];
  
  FUN_80286830();
  fn_8005D3EC();
  piVar6 = &DAT_8037ed20;
  for (iVar5 = 0; iVar5 < DAT_803ddab0; iVar5 = iVar5 + 1) {
    switch(piVar6[3]) {
    case 0:
      FUN_8009e2c0();
      FUN_8005dbc4((ushort *)*piVar6);
      FUN_8009e2c0();
      break;
    case 1:
      iVar3 = *piVar6;
      FUN_8002b660(iVar3);
      iVar4 = FUN_8002bac4();
      if (iVar3 == iVar4) {
        bVar2 = FUN_80296434(iVar3);
        if (bVar2 == 0) {
          FUN_802b5638(iVar3,'\x01','\x01');
        }
      }
      else {
        FUN_800415ac(iVar3);
      }
      break;
    case 2:
      FUN_8000f9d4();
      FUN_80062614();
      FUN_8000f7a0();
      break;
    case 3:
      FUN_8000f9d4();
      iVar4 = FUN_8002b660(*piVar6);
      FUN_800617d0((ushort *)*piVar6,iVar4);
      FUN_8000f7a0();
      break;
    case 4:
      iVar4 = piVar6[1];
      FUN_8025a608(0,1,0,1,0,0,2);
      FUN_8025a608(2,0,0,1,0,0,2);
      FUN_80089ab8(0,(byte *)&local_78,(byte *)((int)&local_78 + 1),(byte *)((int)&local_78 + 2));
      local_74 = local_78;
      FUN_8025a2ec(0,&local_74);
      FUN_8025a5bc(1);
      pfVar1 = (float *)FUN_8000f56c();
      FUN_80247618(pfVar1,(float *)(iVar4 + 0xc),afStack_70);
      FUN_8005fc74(iVar4,afStack_70);
      FUN_8005da10(*piVar6,piVar6[1],afStack_70);
      break;
    case 5:
      iVar4 = piVar6[1];
      FUN_8025a608(0,1,0,1,0,0,2);
      FUN_8025a608(2,0,0,1,0,0,2);
      FUN_80089ab8(0,(byte *)&local_80,(byte *)((int)&local_80 + 1),(byte *)((int)&local_80 + 2));
      local_7c = local_80;
      FUN_8025a2ec(0,&local_7c);
      FUN_8025a5bc(1);
      pfVar1 = (float *)FUN_8000f56c();
      FUN_80247618(pfVar1,(float *)(iVar4 + 0xc),afStack_70);
      FUN_8005fc74(iVar4,afStack_70);
      FUN_8005d818(*piVar6,piVar6[1],afStack_70);
      break;
    case 6:
      iVar4 = piVar6[1];
      FUN_8025a608(0,1,0,1,0,0,2);
      FUN_8025a608(2,0,0,1,0,0,2);
      FUN_80089ab8(0,(byte *)&local_88,(byte *)((int)&local_88 + 1),(byte *)((int)&local_88 + 2));
      local_84 = local_88;
      FUN_8025a2ec(0,&local_84);
      FUN_8025a5bc(1);
      pfVar1 = (float *)FUN_8000f56c();
      FUN_80247618(pfVar1,(float *)(iVar4 + 0xc),afStack_70);
      FUN_8005fc74(iVar4,afStack_70);
      FUN_8005d668(*piVar6,piVar6[1],afStack_70);
      break;
    case 7:
      FUN_8009e3c8();
      break;
    case 8:
      FUN_8006f67c();
      break;
    case 9:
      (**(code **)(*DAT_803dd718 + 0xc))(0,0);
    }
    piVar6 = piVar6 + 4;
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005e010
 * EN v1.0 Address: 0x8005E010
 * EN v1.0 Size: 200b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005e010(undefined4 param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  
  if (DAT_803ddab0 == 1000) {
    FUN_8005dcb4();
    DAT_803ddab0 = 0;
  }
  uVar1 = (uint)-*(float *)(param_3 + 8);
  if ((int)uVar1 < 0) {
    uVar1 = 0;
  }
  else if (0x7ffffff < (int)uVar1) {
    uVar1 = 0x7ffffff;
  }
  (&DAT_8037ed20)[DAT_803ddab0 * 4] = param_1;
  (&DAT_8037ed24)[DAT_803ddab0 * 4] = param_2;
  (&DAT_8037ed28)[DAT_803ddab0 * 4] = uVar1 | 0x38000000;
  (&DAT_8037ed2c)[DAT_803ddab0 * 4] = 7;
  DAT_803ddab0 = DAT_803ddab0 + 1;
  return;
}
