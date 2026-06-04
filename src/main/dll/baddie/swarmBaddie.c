#include "ghidra_import.h"
#include "main/dll/baddie/swarmBaddie.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_80006868();
extern char FUN_80006884();
extern undefined4 FUN_80006894();
extern undefined4 FUN_800068a0();
extern undefined4 FUN_80006954();
extern undefined4 FUN_8000695c();
extern undefined4 FUN_80006960();
extern undefined4 FUN_80006984();
extern undefined4 FUN_80006988();
extern undefined4 FUN_800069b0();
extern undefined4 FUN_800069b8();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_800069d4();
extern double FUN_800069f8();
extern undefined4 FUN_80006a00();
extern undefined4 FUN_80006c64();
extern undefined4 FUN_80006c94();
extern undefined4 FUN_80006c9c();
extern undefined4 FUN_80017484();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a54();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_8003b878();
extern undefined4 FUN_800709d8();
extern undefined4 FUN_800709dc();
extern undefined4 FUN_800709e0();
extern undefined8 FUN_800709e8();
extern int FUN_8020a68c();
extern int FUN_8020a694();
extern ushort FUN_8020a6a0();
extern int FUN_8020a6a8();
extern int FUN_8020a6b0();
extern uint FUN_8020a6b8();
extern int FUN_8020a6fc();
extern undefined4 FUN_8025da64();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_80286824();
extern undefined4 FUN_8028682c();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028fde8();
extern undefined4 FUN_80293994();

extern undefined4 DAT_8031bb84;
extern undefined4 DAT_8031bb8a;
extern undefined4 DAT_8031cbe0;
extern undefined4 DAT_8031cbf8;
extern undefined4 DAT_803a9610;
extern undefined4 DAT_803a9638;
extern undefined4 DAT_803a963c;
extern undefined4 DAT_803a9644;
extern undefined4 DAT_803a96f0;
extern undefined4 DAT_803a96f4;
extern undefined4 DAT_803a96f8;
extern undefined4 DAT_803a96fc;
extern undefined4 DAT_803a9700;
extern undefined4 DAT_803a9704;
extern undefined4 DAT_803a9760;
extern int DAT_803aa058;
extern undefined4 DAT_803aa0a0;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc6d8;
extern undefined4 DAT_803dc7c8;
extern undefined4* DAT_803dd6e8;
extern undefined4 DAT_803dd970;
extern undefined4 DAT_803de3fc;
extern undefined4 DAT_803de428;
extern undefined4 DAT_803de429;
extern undefined4 DAT_803de44c;
extern undefined4 DAT_803de460;
extern undefined4 DAT_803de4b8;
extern undefined4 DAT_803de4d4;
extern undefined4 DAT_803de4d6;
extern undefined4 DAT_803de4d8;
extern undefined4 DAT_803de4da;
extern undefined4 DAT_803de4db;
extern undefined4 DAT_803de548;
extern undefined4 DAT_803de54a;
extern undefined4 DAT_803de550;
extern undefined4 DAT_803e2a88;
extern undefined4 DAT_803e2a8c;
extern f64 DOUBLE_803e2af8;
extern f64 DOUBLE_803e2b08;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc70c;
extern f32 FLOAT_803de54c;
extern f32 FLOAT_803e2abc;
extern f32 FLOAT_803e2adc;
extern f32 FLOAT_803e2ae8;
extern f32 FLOAT_803e2c1c;
extern f32 FLOAT_803e2c20;
extern f32 FLOAT_803e2c2c;
extern f32 FLOAT_803e2c90;
extern f32 FLOAT_803e2ca4;
extern f32 FLOAT_803e2cc0;
extern f32 FLOAT_803e2cc4;
extern f32 FLOAT_803e2cc8;
extern f32 FLOAT_803e2ccc;
extern f32 FLOAT_803e2cd0;
extern f32 FLOAT_803e2cd4;
extern f32 FLOAT_803e2cd8;
extern f32 FLOAT_803e2cdc;
extern f32 FLOAT_803e2ce0;
extern f32 FLOAT_803e2ce4;
extern f32 FLOAT_803e2ce8;

/*
 * --INFO--
 *
 * Function: drawFn_80125424
 * EN v1.0 Address: 0x80125424
 * EN v1.0 Size: 1880b
 * EN v1.1 Address: 0x80125708
 * EN v1.1 Size: 1920b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void AudioStream_StopCurrent(void);
extern void doNothing_8000CF54(int a);
extern void GXSetScissor(int x, int y, int w, int h);
extern void drawRect(f32 a, f32 b, int c, int d);
extern f32 Camera_GetFovY(void);
extern void Camera_SetFovY(f32 fov);
extern void Camera_SetCurrentViewIndex(int idx);
extern int Camera_IsViewYOffsetEnabled(void);
extern void Camera_DisableViewYOffset(void);
extern void Camera_EnableViewYOffset(void);
extern void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z);
extern void Camera_SetCurrentViewRotation(int x, int y, int z);
extern void Camera_UpdateViewMatrices(void);
extern void Camera_RebuildProjectionMatrix(void);
extern void Camera_ApplyFullViewport(void);
extern void GXSetViewport(f32 a, f32 b, f32 c, f32 d, f32 e, f32 f);
extern void ObjAnim_AdvanceCurrentMove(int obj, f32 a, f32 b, u8 *buf);
extern void objRender(int a, int b, int c, int d, int obj, int e);
extern int Obj_GetActiveModel(int obj);
extern f32 fsin16Approx(u16 angle);
extern void drawPartialTexture(int tex, f32 a, f32 b, int alpha, int scale, int c, int d, int e, int f);
extern void drawScaledTexture(int tex, f32 a, f32 b, int alpha, int scale, int c, int d, int e);
extern void drawTexture(int tex, f32 x, f32 y, int alpha, int scale);
extern u8 lbl_803DD85A;
extern u8 lbl_803DD85B;
extern u8 lbl_803DD7A8;
extern u16 lbl_803DD858;
extern u16 lbl_803DD856;
extern s16 lbl_803DD854;
extern u16 lbl_803DD77C;
extern int lbl_803DD7E0;
extern f32 lbl_803DBAA4;
extern u8 *lbl_803DCCF0;
extern u8 framesThisStep;
extern u8 lbl_8031AF34[];
extern int lbl_803A93F8[];
extern f32 lbl_8031BFA8[];
extern int hudTextures[];
extern u32 randomGetRange(int min, int max);
extern f32 timeDelta;
extern f32 lbl_803E1E3C;
extern f32 lbl_803E1E68;
extern f32 lbl_803E2010;
extern f32 lbl_803E2024;
extern f32 lbl_803E2040;
extern f32 lbl_803E2044;
extern f32 lbl_803E2048;
extern f32 lbl_803E204C;
extern f32 lbl_803E2050;
extern f32 lbl_803E2054;
extern f32 lbl_803E2058;

void drawFn_80125424(void)
{
    s16 alpha;
    u32 height;
    u32 width;
    int type;
    int ypos;
    int i;
    int a1;
    int rx;
    int ry;
    s16 sw;
    s16 sh;
    int x2;
    int x5;
    f32 wave;
    f32 zz;
    f32 k;
    f32 base1;
    f32 base2;

    if (lbl_803DD85A != 0) {
        if ((s8)lbl_803DD7A8 == 0) {
            lbl_803DD858 = lbl_803DD858 + framesThisStep * 5;
            if (lbl_803DD858 > 0x152) {
                lbl_803DD858 = 0x152;
                lbl_803DD85A = 0;
                if (*(int *)(lbl_8031AF34 + lbl_803DD85B * 0xc) != -1) {
                    AudioStream_StopCurrent();
                    doNothing_8000CF54(0);
                }
            }
            lbl_803DD856 = lbl_803DD856 - framesThisStep * 10;
            lbl_803DD854 = lbl_803DD854 - framesThisStep * 0x17;
        } else {
            lbl_803DD858 = lbl_803DD858 - framesThisStep * 5;
            if (lbl_803DD858 < 0x122) {
                lbl_803DD858 = 0x122;
            }
            lbl_803DD856 = lbl_803DD856 + framesThisStep * 10;
            lbl_803DD854 = lbl_803DD854 + framesThisStep * 0x17;
        }
        a1 = lbl_803DD854;
        if (a1 < 0) {
            a1 = 0;
        } else if (a1 > 0xff) {
            a1 = 0xff;
        }
        alpha = a1;
        lbl_803DD854 = alpha;
        height = lbl_803DD856;
        if (height > 0x6e) {
            height = 0x6e;
        }
        lbl_803DD856 = height;
        width = lbl_803DD858;
        type = *(u8 *)(lbl_8031AF34 + lbl_803DD85B * 0xc + 6);
        switch (type) {
        default:
        case 1:
            ypos = 0x19a;
            break;
        case 3:
            ypos = 0x195;
            break;
        case 2:
            ypos = 0x186;
            break;
        }
        GXSetScissor(0x1ea, width, 0x78, height);
        drawRect(lbl_803E2040, (f32)(int)width, 0x78, height);
        lbl_803DBAA4 = Camera_GetFovY();
        Camera_SetFovY(lbl_803E2044);
        Camera_SetCurrentViewIndex(1);
        lbl_803DD7E0 = Camera_IsViewYOffsetEnabled();
        Camera_DisableViewYOffset();
        zz = lbl_803E1E3C;
        Camera_SetCurrentViewPosition(zz, zz, zz);
        Camera_SetCurrentViewRotation(0x8000, 0, 0);
        Camera_UpdateViewMatrices();
        Camera_RebuildProjectionMatrix();
        GXSetViewport(lbl_803E2048, (f32)ypos - lbl_803E2024,
                      (f32)(u32)*(u16 *)(lbl_803DCCF0 + 4), (f32)(u32)*(u16 *)(lbl_803DCCF0 + 8),
                      lbl_803E1E3C, lbl_803E1E68);
        if (*(u8 **)&lbl_803A93F8[type] != NULL) {
            ObjAnim_AdvanceCurrentMove(lbl_803A93F8[type], lbl_8031BFA8[type], timeDelta, 0);
            if (*(u32 *)(lbl_803A93F8[type] + 0x4c) > 0x90000000u) {
                *(u32 *)(lbl_803A93F8[type] + 0x4c) = 0;
            }
            *(u8 *)(lbl_803A93F8[type] + 0x37) = 0xff;
            objRender(0, 0, 0, 0, lbl_803A93F8[type], 1);
            *(u16 *)(Obj_GetActiveModel(lbl_803A93F8[type]) + 0x18) &= ~8;
        }
        Camera_SetCurrentViewIndex(0);
        if (lbl_803DD7E0 != 0) {
            Camera_EnableViewYOffset();
        }
        Camera_UpdateViewMatrices();
        Camera_SetFovY(lbl_803DBAA4);
        Camera_RebuildProjectionMatrix();
        Camera_ApplyFullViewport();
        GXSetScissor(0, 0, 0x280, 0x1e0);
        lbl_803DD77C += 1;
        k = lbl_803E204C;
        base1 = lbl_803E2050;
        base2 = lbl_803E2010;
        for (i = 0; i < (int)height; i += 4) {
            wave = k * fsin16Approx((u16)(i * 0xd48 + lbl_803DD77C * 0x1838));
            wave = k * fsin16Approx((u16)(i * 0x7d0 + lbl_803DD77C * 0xfa0)) + wave;
            a1 = (int)((f32)alpha * (base1 + wave));
            if (a1 < 0) {
                a1 = 0;
            }
            rx = (int)randomGetRange(0, 0x1e) << 1;
            ry = (int)randomGetRange(0, 0x1e) << 1;
            if (a1 > 0xff) {
                a1 = 0xff;
            }
            drawPartialTexture(hudTextures[84], lbl_803E2040, (f32)(int)(width + i), a1 & 0xff, 0x100, 0x78, 2, ry, rx);
            a1 = (int)((f32)alpha * (base2 + wave));
            if (a1 < 0) {
                a1 = 0;
            }
            rx = (int)randomGetRange(0, 0x1e) << 1;
            ry = (int)randomGetRange(0, 0x1e) << 1;
            if (a1 > 0xff) {
                a1 = 0xff;
            }
            drawPartialTexture(hudTextures[84], lbl_803E2040, (f32)(int)(width + i + 2), a1 & 0xff, 0x100, 0x78, 2, ry, rx);
        }
        sw = (s16)width;
        x5 = sw - 5;
        drawTexture(hudTextures[10], lbl_803E2054, (f32)x5, alpha & 0xff, 0x100);
        drawScaledTexture(hudTextures[13], lbl_803E2040, (f32)x5, alpha & 0xff, 0x100, 0x78, 5, 0);
        sh = (s16)height;
        drawScaledTexture(hudTextures[11], lbl_803E2054, (f32)sw, alpha & 0xff, 0x100, 5, sh, 0);
        x2 = sw + sh;
        drawScaledTexture(hudTextures[13], lbl_803E2040, (f32)x2, alpha & 0xff, 0x100, 0x78, 5, 2);
        drawScaledTexture(hudTextures[11], lbl_803E2058, (f32)sw, alpha & 0xff, 0x100, 5, sh, 1);
        drawScaledTexture(hudTextures[10], lbl_803E2058, (f32)x2, alpha & 0xff, 0x100, 5, 5, 3);
        drawScaledTexture(hudTextures[10], lbl_803E2058, (f32)x5, alpha & 0xff, 0x100, 5, 5, 1);
        drawScaledTexture(hudTextures[10], lbl_803E2054, (f32)x2, alpha & 0xff, 0x100, 5, 5, 2);
    }
}

/*
 * --INFO--
 *
 * Function: FUN_80125b7c
 * EN v1.0 Address: 0x80125B7C
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x80125E88
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80125b7c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  short sVar1;
  ushort uVar2;
  char cVar3;
  int iVar4;
  undefined8 extraout_f1;
  
  if (DAT_803de4da == '\0') {
    if ((param_9 < 0) || (0x14 < param_9)) {
      param_9 = 0x14;
    }
    DAT_803de4da = '\x01';
    DAT_803de4db = (undefined)param_9;
    iVar4 = param_9 * 0xc;
    if ((*(int *)(&DAT_8031bb84 + iVar4) != -1) && (cVar3 = FUN_80006884(), cVar3 == '\0')) {
      FUN_800068a0(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    if (*(char *)(iVar4 + -0x7fce4475) == '\0') {
      sVar1 = *(short *)(iVar4 + -0x7fce4474);
      uVar2 = *(ushort *)(iVar4 + -0x7fce4478);
      if ((uVar2 != 0xffffffff) && (DAT_803dc6d8 == 0xffff)) {
        FUN_80006c9c(0x7c);
        DAT_803de428 = 1;
        DAT_803de550 = 0;
        DAT_803de548 = 0;
        FLOAT_803de54c =
             (float)((double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000) - DOUBLE_803e2af8);
        DAT_803dc6d8 = uVar2;
        DAT_803de54a = sVar1;
        FUN_80006c94((undefined4 *)&DAT_803aa0a0);
        DAT_803de429 = 0;
      }
    }
    else {
      (**(code **)(*DAT_803dd6e8 + 0x38))(*(undefined2 *)(iVar4 + -0x7fce4478),0,0,0);
    }
    DAT_803de4d8 = 0x159;
    DAT_803de4d6 = 0;
    DAT_803de4d4 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80125d3c
 * EN v1.0 Address: 0x80125D3C
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x80125FE8
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80125d3c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  iVar2 = 0;
  piVar3 = &DAT_803aa058;
  do {
    iVar1 = *piVar3;
    if (iVar1 != 0) {
      if (0x90000000 < *(uint *)(iVar1 + 0x4c)) {
        *(undefined4 *)(iVar1 + 0x4c) = 0;
      }
      param_1 = FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar3
                            );
      *piVar3 = 0;
    }
    piVar3 = piVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 6);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80125e30
 * EN v1.0 Address: 0x80125E30
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x80126070
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80125e30(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 *puVar6;
  int *piVar7;
  int iVar8;
  
  iVar8 = 0;
  piVar7 = &DAT_803aa058;
  puVar6 = &DAT_8031cbe0;
  do {
    if (((iVar8 == 3) || (iVar8 == 2)) || (iVar8 == 1)) {
      if (*piVar7 == 0) {
        puVar2 = FUN_80017aa4(0x20,(short)*puVar6);
        uVar4 = 0xffffffff;
        uVar5 = 0;
        iVar3 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                             4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
        *piVar7 = iVar3;
        fVar1 = FLOAT_803e2abc;
        *(float *)(*piVar7 + 0xc) = FLOAT_803e2abc;
        *(float *)(*piVar7 + 0x10) = fVar1;
        *(float *)(*piVar7 + 0x14) = FLOAT_803e2adc;
        *(undefined2 *)*piVar7 = 0x7447;
        *(float *)(*piVar7 + 8) = FLOAT_803e2cdc;
        if (0x90000000 < *(uint *)(*piVar7 + 0x4c)) {
          *(undefined4 *)(*piVar7 + 0x4c) = 0;
        }
        param_1 = FUN_800305f8((double)FLOAT_803e2abc,param_2,param_3,param_4,param_5,param_6,
                               param_7,param_8,*piVar7,1,0,uVar4,uVar5,in_r8,in_r9,in_r10);
      }
    }
    else {
      *piVar7 = 0;
    }
    piVar7 = piVar7 + 1;
    puVar6 = puVar6 + 1;
    iVar8 = iVar8 + 1;
  } while (iVar8 < 6);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80126044
 * EN v1.0 Address: 0x80126044
 * EN v1.0 Size: 1184b
 * EN v1.1 Address: 0x80126188
 * EN v1.1 Size: 1064b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80126044(void)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  ushort uVar9;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar10;
  byte bVar11;
  undefined8 uVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f31;
  double dVar15;
  double in_ps31_1;
  undefined4 local_58;
  undefined local_54;
  undefined8 local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined8 local_40;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  FUN_8028682c();
  iVar3 = FUN_8020a6fc();
  local_58 = DAT_803e2a88;
  local_54 = DAT_803e2a8c;
  if (iVar3 != 0) {
    if (DAT_803de44c == '\0') {
      local_40 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
      uStack_44 = (int)DAT_803de4b8 ^ 0x80000000;
      iVar7 = (int)-(FLOAT_803e2c20 * (float)(local_40 - DOUBLE_803e2b08) -
                    (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e2af8));
      local_50 = (double)(longlong)iVar7;
      DAT_803de4b8 = (short)iVar7;
      if (DAT_803de4b8 < 0) {
        DAT_803de4b8 = 0;
      }
    }
    else {
      local_50 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
      uStack_44 = (int)DAT_803de4b8 ^ 0x80000000;
      iVar7 = (int)(FLOAT_803e2c20 * (float)(local_50 - DOUBLE_803e2b08) +
                   (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e2af8));
      local_40 = (double)(longlong)iVar7;
      DAT_803de4b8 = (short)iVar7;
      if (0xff < DAT_803de4b8) {
        DAT_803de4b8 = 0xff;
      }
    }
    local_48 = 0x43300000;
    dVar14 = (double)FLOAT_803e2c20;
    uVar4 = FUN_8020a6b8(iVar3);
    iVar5 = FUN_8020a6b0(iVar3);
    iVar6 = FUN_8020a6a8(iVar3);
    iVar7 = FUN_8020a694(iVar3);
    iVar8 = FUN_8020a68c(iVar3);
    if (iVar8 < iVar7) {
      iVar7 = iVar8;
    }
    dVar13 = DOUBLE_803e2af8;
    for (uVar10 = 0; uVar1 = uVar10 & 0xff, (int)uVar1 < iVar5 >> 2; uVar10 = uVar10 + 1) {
      if ((int)uVar1 < (int)uVar4 >> 2) {
        iVar2 = 0x16;
      }
      else {
        iVar2 = (uVar4 & 3) + 0x12;
        if ((int)uVar4 >> 2 < (int)uVar1) {
          iVar2 = 0x12;
        }
      }
      local_40 = (double)CONCAT44(0x43300000,uVar1 * 0x21 + 0x1e ^ 0x80000000);
      FUN_800709e8((double)(float)(local_40 - dVar13),(double)FLOAT_803e2c2c,(&DAT_803a9610)[iVar2],
                   (int)DAT_803de4b8 & 0xff,0x100);
    }
    dVar13 = DOUBLE_803e2af8;
    for (bVar11 = 0; bVar11 < 3; bVar11 = bVar11 + 1) {
      iVar5 = (uint)bVar11 * 0x1c;
      local_40 = (double)CONCAT44(0x43300000,iVar5 + 0x1eU ^ 0x80000000);
      FUN_800709e8((double)(float)(local_40 - dVar13),(double)FLOAT_803e2ce0,DAT_803a96f0,
                   (int)DAT_803de4b8 & 0xff,0x100);
      if ((int)(uint)bVar11 < iVar6) {
        local_40 = (double)CONCAT44(0x43300000,iVar5 + 0x23U ^ 0x80000000);
        FUN_800709e8((double)(float)(local_40 - DOUBLE_803e2af8),(double)FLOAT_803e2ce4,DAT_803a96f4
                     ,(int)DAT_803de4b8 & 0xff,0x100);
      }
    }
    if (*(char *)(iVar3 + 0xac) != '&') {
      FUN_800709e8((double)FLOAT_803e2ce8,(double)FLOAT_803e2c2c,DAT_803a9704,
                   (int)DAT_803de4b8 & 0xff,0x100);
      dVar13 = DOUBLE_803e2af8;
      for (uVar4 = 0; dVar15 = DOUBLE_803e2af8, (int)(uVar4 & 0xff) < iVar7; uVar4 = uVar4 + 1) {
        local_40 = (double)CONCAT44(0x43300000,(uVar4 & 0xff) * -0x14 + 0x244 ^ 0x80000000);
        FUN_800709e8((double)(float)(local_40 - dVar13),(double)FLOAT_803e2c1c,DAT_803a9700,
                     (int)DAT_803de4b8 & 0xff,0x100);
      }
      for (; uVar10 = uVar4 & 0xff, (int)uVar10 < iVar8; uVar4 = uVar4 + 1) {
        local_40 = (double)CONCAT44(0x43300000,uVar10 * -0x14 + 0x244 ^ 0x80000000);
        FUN_800709e8((double)(float)(local_40 - dVar15),(double)FLOAT_803e2c1c,DAT_803a96fc,
                     (int)DAT_803de4b8 & 0xff,0x100);
      }
      local_40 = (double)CONCAT44(0x43300000,uVar10 * -0x14 + 0x23c ^ 0x80000000);
      dVar13 = (double)FLOAT_803e2c2c;
      uVar12 = FUN_800709e8((double)(float)(local_40 - DOUBLE_803e2af8),dVar13,DAT_803a96f8,
                            (int)DAT_803de4b8 & 0xff,0x100);
      uVar9 = FUN_8020a6a0(iVar3);
      FUN_8028fde8(uVar12,dVar13,dVar14,in_f4,in_f5,in_f6,in_f7,in_f8,(int)&local_58,&DAT_803dc7c8,
                   (uint)uVar9,in_r6,in_r7,in_r8,in_r9,in_r10);
    }
    FUN_80017484(0xff,0xff,0xff,(byte)DAT_803de4b8);
    FUN_80006c64(&local_58,0x93,0x23a,0x41);
    drawFn_80125424();
  }
  FUN_80286878();
  return;
}

extern int lbl_803A93F8[];
extern void Obj_FreeObject(int* obj);

void fn_80125D04(void) {
    int* ptr;
    int i = 0;
    ptr = lbl_803A93F8;
    for (; i < 6; i++) {
        int* obj = (int*)ptr[0];
        if (obj != NULL) {
            if ((u32)obj[19] > 0x90000000u) {
                obj[19] = 0;
            }
            Obj_FreeObject((int*)ptr[0]);
            ptr[0] = 0;
        }
        ptr++;
    }
}

extern u8 lbl_803DD85A;
extern u8 lbl_803DD85B;
extern u8 lbl_803DD7A8;
extern u8 lbl_803DD7A9;
extern u8 lbl_803DD8C8;
extern s16 lbl_803DD8CA;
extern f32 lbl_803DD8CC;
extern u16 lbl_803DD8D0;
extern u16 curGameText;
extern u8 lbl_8031AF34[];
extern u8 lbl_803A9440[];
extern u8 AudioStream_IsPreparing(void);
extern void AudioStream_StartPrepared(void);
extern void AudioStream_Play(int stream, void (*cb)(void));
extern void gameTextGetBox(int box);
extern void gameTextFreePhrase(u8 *phrase);
extern int *gGameUIInterface;

#pragma opt_common_subs off
void gameTextFn_80125ba4(int idx) {
    int a;
    int b;

    if (lbl_803DD85A == 0) {
        if (idx < 0 || idx >= 0x15) {
            idx = 0x14;
        }
        lbl_803DD85A = 1;
        lbl_803DD85B = idx;
        idx = idx * 0xc;
        if (*(int *)(lbl_8031AF34 + idx) != -1 && AudioStream_IsPreparing() == 0) {
            AudioStream_Play(*(int *)(lbl_8031AF34 + idx), AudioStream_StartPrepared);
        }
        {
            u8 *e = &lbl_8031AF34[idx];
            if (e[7] != 0) {
                (*(void (**)(int, int, int, int))(*(int *)gGameUIInterface + 0x38))(*(u16 *)(e + 4), 0, 0, 0);
            } else {
                b = *(u16 *)(e + 8);
                a = *(u16 *)(e + 4);
            if (a != -1 && curGameText == 0xffff) {
                gameTextGetBox(0x7c);
                lbl_803DD7A8 = 1;
                lbl_803DD8D0 = 0;
                curGameText = a;
                lbl_803DD8C8 = 0;
                lbl_803DD8CA = (s16)b;
                lbl_803DD8CC = (f32)(s16)b;
                gameTextFreePhrase(lbl_803A9440);
                lbl_803DD7A9 = 0;
            }
            }
        }
        lbl_803DD858 = 0x159;
        lbl_803DD856 = 0;
        lbl_803DD854 = 0;
    }
}
#pragma opt_common_subs reset

extern int lbl_8031BF90[];
extern u8 *Obj_AllocObjectSetup(int size, int def);
extern int Obj_SetupObject(u8 *def, int a, int b, int c, int d);
extern void ObjAnim_SetCurrentMove(int obj, int idx, f32 v, int p);
extern f32 lbl_803E1E3C;
extern f32 lbl_803E1E5C;
extern f32 lbl_803E205C;

void pauseMenuCreateHeads(void) {
    int i;
    int *slots;
    int *defs;
    f32 f;

    i = 0;
    slots = lbl_803A93F8;
    defs = lbl_8031BF90;
    for (; i < 6; i++) {
        if (i != 3 && i != 2 && i != 1) {
            *slots = 0;
        } else {
            if (*(void **)slots == NULL) {
                *slots = Obj_SetupObject(Obj_AllocObjectSetup(0x20, *defs), 4, -1, -1, 0);
                f = lbl_803E1E3C;
                *(f32 *)(*slots + 0xc) = f;
                *(f32 *)(*slots + 0x10) = f;
                *(f32 *)(*slots + 0x14) = lbl_803E1E5C;
                *(s16 *)*slots = 0x7447;
                *(f32 *)(*slots + 8) = lbl_803E205C;
                if (*(u32 *)(*slots + 0x4c) > 0x90000000u) {
                    *(u32 *)(*slots + 0x4c) = 0;
                }
                ObjAnim_SetCurrentMove(*slots, 1, lbl_803E1E3C, 0);
            }
        }
        slots = slots + 1;
        defs = defs + 1;
    }
}

extern int *getArwing(void);
extern int arwarwing_getShield(int *arwing);
extern int arwarwing_getMaxShield(int *arwing);
extern int arwarwing_getBombCount(int *arwing);
extern int arwarwing_getCollectedRingCount(int *arwing);
extern int arwarwing_getRequiredRingCount(int *arwing);
extern int arwarwing_getScore(int *arwing);
extern void drawTexture(int tex, f32 x, f32 y, int alpha, int scale);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShowStr(char *str, int x, int y, int z);
extern void sprintf(char *buf, char *fmt, ...);
extern u8 arwingHudVisible;
extern s16 arwingHudAlpha;
extern u8 framesThisStep;
extern int hudTextures[];
extern char lbl_803DBB60;
extern int lbl_803E1E08;
extern u8 lbl_803E1E0C;
extern f32 lbl_803E1FA0;
extern f32 lbl_803E1FAC;
extern f32 lbl_803E1F9C;
extern f32 lbl_803E2060;
extern f32 lbl_803E2064;
extern f32 lbl_803E2068;

void drawArwingHud(void) {
    char buf[8];
    int *arwing;
    int shield;
    int maxShield;
    int bombs;
    int rings;
    int req;
    int t30;
    int t23;
    int t22;
    u32 i;
    u32 v;
    int t;
    u8 b;
    int pos;

    arwing = getArwing();
    *(int *)buf = lbl_803E1E08;
    buf[4] = lbl_803E1E0C;
    if (arwing != NULL) {
        if (arwingHudVisible != 0) {
            arwingHudAlpha = (int)(lbl_803E1FA0 * (f32)(u32)framesThisStep + (f32)arwingHudAlpha);
            if (arwingHudAlpha > 0xff) {
                arwingHudAlpha = 0xff;
            }
        } else {
            arwingHudAlpha = (int)-(lbl_803E1FA0 * (f32)(u32)framesThisStep - (f32)arwingHudAlpha);
            if (arwingHudAlpha < 0) {
                arwingHudAlpha = 0;
            }
        }
        shield = arwarwing_getShield(arwing);
        maxShield = arwarwing_getMaxShield(arwing);
        bombs = arwarwing_getBombCount(arwing);
        rings = arwarwing_getCollectedRingCount(arwing);
        req = arwarwing_getRequiredRingCount(arwing);
        if (rings > req) {
            rings = req;
        }
        t30 = shield >> 2;
        t23 = (shield & 3) + 0x12;
        t22 = maxShield >> 2;
        for (i = 0; (int)(v = i & 0xff) < t22; i++) {
            if ((int)v < t30) {
                t = 0x16;
            } else if (t30 < (int)v) {
                t = 0x12;
            } else {
                t = (u8)t23;
            }
            drawTexture(hudTextures[(u8)t], (f32)(int)(v * 0x21 + 0x1e), lbl_803E1FAC,
                        arwingHudAlpha & 0xff, 0x100);
        }
        for (b = 0; b < 3; b++) {
            pos = b * 0x1c;
            drawTexture(hudTextures[56], (f32)(pos + 0x1e), lbl_803E2060, arwingHudAlpha & 0xff, 0x100);
            if ((int)b < bombs) {
                drawTexture(hudTextures[57], (f32)(pos + 0x23), lbl_803E2064, arwingHudAlpha & 0xff, 0x100);
            }
        }
        if (*(s8 *)((char *)arwing + 0xac) != 0x26) {
            drawTexture(hudTextures[61], lbl_803E2068, lbl_803E1FAC, arwingHudAlpha & 0xff, 0x100);
            for (i = 0; (int)(i & 0xff) < rings; i++) {
                drawTexture(hudTextures[60], (f32)(int)(0x244 - (i & 0xff) * 0x14), lbl_803E1F9C,
                            arwingHudAlpha & 0xff, 0x100);
            }
            for (; (int)(v = i & 0xff) < req; i++) {
                drawTexture(hudTextures[59], (f32)(int)(0x244 - v * 0x14), lbl_803E1F9C,
                            arwingHudAlpha & 0xff, 0x100);
            }
            drawTexture(hudTextures[58], (f32)(int)(0x23c - v * 0x14), lbl_803E1FAC,
                        arwingHudAlpha & 0xff, 0x100);
            sprintf(buf, &lbl_803DBB60, arwarwing_getScore(arwing));
        }
        gameTextSetColor(0xff, 0xff, 0xff, arwingHudAlpha & 0xff);
        gameTextShowStr(buf, 0x93, 0x23a, 0x41);
        drawFn_80125424();
    }
}
