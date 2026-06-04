#include "ghidra_import.h"
#include "main/tex_dolphin.h"
#include "dolphin/gx.h"
#include "dolphin/mtx.h"
#include "track/intersect.h"

typedef union {
    f64 d;
    struct {
        uint hi;
        uint lo;
    } words;
} SfaIntDouble;

extern void modelLightStruct_getColorsA8AC(void *light, u8 *a, u8 *b, u8 *c, u8 *d);
extern f32 modelLightStruct_getRadius(void *light);
extern void modelLightStruct_getPosition(void *light, void *a, void *b, void *c);
extern void modelLightStruct_selectBrightestAabbLights(undefined *dest, int count, int *out, f32 x1, f32 y1, f32 z1, f32 x2, f32 y2, f32 z2);
extern int Shader_getLayer();
extern void selectTexture();
extern void fn_8004CE0C();
extern void fn_8004D928();
extern void fn_8004D230();
extern void fn_8004DA54();
extern void fn_8004E0FC();
extern void renderHeavyFog();
extern void fn_8004EECC();
extern void fn_8004EF9C();
extern void fn_8004F080();
extern void fn_8004F2B0();
extern void fn_8004F380();
extern void fn_8004F6D8();
extern void fn_8004FA30();
extern void fn_8004FDA0();
extern void fn_80051528();
extern void fn_80051868();
extern void fn_80051B00();
extern void gxColorFn_800523d0();
extern void textureFn_800524ec();
extern int textureCrazyPointerFollowFn_80054c30();
extern void textureFn_800528bc();
extern void resetLotsOfRenderVars();
extern void fn_8005D3B4();
extern void textureFn_8006c4e0();
extern void fn_80088730();
extern void objGetColor();
extern uint AttractMovie_DrawTextureCallback();
extern u8 isHeavyFogEnabled();

extern f64 lbl_803DEBC0;
extern f32 lbl_803DEBC8;
extern f32 lbl_803DEBCC;
extern f32 displayOffsetH_803DEBFC;
extern f32 CurrTiming_803DEC20;
extern f32 lbl_803DEC24;
extern f32 FBSet_803DEC28;
extern f32 lbl_803DEC2C;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern int lbl_803DEBB0;
extern int lbl_803DCE20;
extern int lbl_803DCE28;
extern int lbl_803DCE30;
extern int *lbl_803DCE34;
extern int lbl_803DCE68;
extern int lbl_803DCE6C;

typedef struct TexOverride {
    int id;
    int ptr;
    int unk8;
    s16 count;
    u8 layerByte;
    u8 padF;
} TexOverride;
extern int lbl_802C1E40;
extern u8 lbl_8037E0C0[];
extern byte lbl_803DB638;
extern int lbl_803DB63C;
extern int lbl_803DB640;
extern byte lbl_803DB644;
extern int lbl_80382008[5];
extern int gViewFrustumPlanes[25];
extern int lbl_803E8444;
extern int lbl_803E8448;
extern undefined4 jumptable_8030E844;

/*
 * --INFO--
 *
 * Function: mapBlockBounds_HasCornerPastDepthThreshold
 * EN v1.0 Address: 0x8005DF5C
 * EN v1.0 Size: 1004b
 * EN v1.1 Address: 0x8005E0D8
 * EN v1.1 Size: 1004b
 */
#pragma scheduling off
#pragma peephole off
u8 mapBlockBounds_HasCornerPastDepthThreshold(int param_1,float *param_2)
{
  float v[3];
  uint i;
  f32 fbset;
  f32 timing;

  i = 0;
  timing = CurrTiming_803DEC20;
  fbset = FBSet_803DEC28;
  while (1) {
    {
      switch (i) {
      case 0:
        v[0] = (f32)*(s16 *)(param_1 + 0x6);
        v[1] = (f32)*(s16 *)(param_1 + 0x8);
        v[2] = (f32)*(s16 *)(param_1 + 0xa);
        break;
      case 1:
        v[0] = (f32)*(s16 *)(param_1 + 0xc);
        v[1] = (f32)*(s16 *)(param_1 + 0x8);
        v[2] = (f32)*(s16 *)(param_1 + 0xa);
        break;
      case 2:
        v[0] = (f32)*(s16 *)(param_1 + 0x6);
        v[1] = (f32)*(s16 *)(param_1 + 0xe);
        v[2] = (f32)*(s16 *)(param_1 + 0xa);
        break;
      case 3:
        v[0] = (f32)*(s16 *)(param_1 + 0xc);
        v[1] = (f32)*(s16 *)(param_1 + 0xe);
        v[2] = (f32)*(s16 *)(param_1 + 0xa);
        break;
      case 4:
        v[0] = (f32)*(s16 *)(param_1 + 0x6);
        v[1] = (f32)*(s16 *)(param_1 + 0x8);
        v[2] = (f32)*(s16 *)(param_1 + 0x10);
        break;
      case 5:
        v[0] = (f32)*(s16 *)(param_1 + 0xc);
        v[1] = (f32)*(s16 *)(param_1 + 0x8);
        v[2] = (f32)*(s16 *)(param_1 + 0x10);
        break;
      case 6:
        v[0] = (f32)*(s16 *)(param_1 + 0x6);
        v[1] = (f32)*(s16 *)(param_1 + 0xe);
        v[2] = (f32)*(s16 *)(param_1 + 0x10);
        break;
      case 7:
        v[0] = (f32)*(s16 *)(param_1 + 0xc);
        v[1] = (f32)*(s16 *)(param_1 + 0xe);
        v[2] = (f32)*(s16 *)(param_1 + 0x10);
        break;
      }
    }
    v[0] = v[0] * timing;
    v[1] = v[1] * timing;
    v[2] = v[2] * timing;
    PSMTXMultVec((const float (*)[4])param_2,(Vec *)v,(Vec *)v);
    if (v[2] >= fbset) {
      return 1;
    }
    i = i + 1;
    if (7 < (int)i) {
      return 0;
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: mapBlockRender_drawLightmapIndirectPasses
 * EN v1.0 Address: 0x8005E348
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x8005E4C4
 * EN v1.1 Size: 536b
 */
#pragma scheduling off
#pragma peephole off
typedef struct IndMtxCopy {
    int w[6];
} IndMtxCopy;

void mapBlockRender_drawLightmapIndirectPasses(int param_1,u8 *param_2,int *param_3,Mtx param_4)
{
  Mtx m2;
  float m[2][3];
  int lb;
  int la;
  int ptr;
  int bptr;
  int pos;
  uint word;
  uint flags;
  u8 count;
  int i;
  f32 k;
  f32 k24;
  f32 kH;
  u8 *tbl;

  pos = param_3[4];
  word = *(u8 *)(*param_3 + (pos >> 3));
  bptr = *param_3 + (pos >> 3);
  word = word | (u32)(*(u8 *)(bptr + 1) << 8);
  word = word | (u32)(*(u8 *)(bptr + 2) << 16);
  param_3[4] = pos + 8;
  ptr = *(int *)(param_1 + 0x68) + ((word >> (pos & 7)) & 0xff) * 0x1c;
  flags = *(uint *)(param_2 + 0x3c);
  if ((flags & 0x4000) != 0) {
    count = 4;
  }
  else if ((flags & 0x8000) != 0) {
    count = 8;
  }
  else if ((flags & 0x10000) != 0) {
    count = 0x10;
  }
  else {
    return;
  }
  i = 0;
  k = lbl_803DEC2C;
  tbl = (u8 *)&lbl_802C1E40;
  k24 = lbl_803DEC24;
  kH = displayOffsetH_803DEBFC;
  for (; i < count; i = i + 1) {
    PSMTXTrans(m2,lbl_803DEBCC,k * (f32)(i + 1),lbl_803DEBCC);
    PSMTXConcat(param_4,m2,m2);
    GXLoadPosMtxImm(m2,0);
    *(IndMtxCopy *)m = *(IndMtxCopy *)tbl;
    textureFn_8006c4e0(&la,&lb);
    selectTexture(*(int *)(la + (u8)i * 4),1);
    m[0][0] = (f32)((u8)i + 1) * k24 * kH;
    m[1][1] = m[0][0];
    GXSetIndTexMtx(1,(const float (*)[3])m,lbl_803DB644);
    GXCallDisplayList(*(void **)ptr,(uint)*(u16 *)(ptr + 4));
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: mapBlockRender_setLightmapShader
 * EN v1.0 Address: 0x8005E560
 * EN v1.0 Size: 464b
 * EN v1.1 Address: 0x8005E6DC
 * EN v1.1 Size: 464b
 */
#pragma scheduling off
#pragma peephole off
int mapBlockRender_setLightmapShader(int param_1,int *param_3,int *param_2)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined uVar4;
  undefined uVar5;
  undefined uVar6;
  volatile int local_18;
  byte local_14;
  byte local_15;
  byte local_16;
  int local_10;
  int local_C;
  int local_8;

  local_18 = lbl_803E8448;
  uVar2 = param_3[4];
  iVar1 = *param_3;
  uVar6 = *(undefined *)(iVar1 + ((int)uVar2 >> 3));
  iVar1 = iVar1 + ((int)uVar2 >> 3);
  uVar4 = *(undefined *)(iVar1 + 1);
  uVar5 = *(undefined *)(iVar1 + 2);
  param_3[4] = uVar2 + 6;
  iVar1 = *(int *)((int)param_1 + 0x64);
  uVar3 = ((uint3)(uVar6 | (uVar4 << 8) | (uVar5 << 16)) >> (uVar2 & 7)) & 0x3f;
  iVar1 = iVar1 + uVar3 * 0x44;
  GXSetTevAlphaIn(0,7,4,5,7);
  selectTexture(*(int *)Shader_getLayer(iVar1,0),0);
  if ((*(uint *)(iVar1 + 0x3c) & 4) != 0) {
    _gxSetFogParams();
    goto LAB_8005E630;
  }
  local_10 = local_18;
  GXSetFog(0,lbl_803DEBCC,lbl_803DEBCC,lbl_803DEBCC,lbl_803DEBCC,*(GXColor*)&local_10);
LAB_8005E630:
  if ((*(uint *)(iVar1 + 0x3c) & 1) == 0) {
    if ((*(uint *)(iVar1 + 0x3c) & 0x40000) == 0) {
      if ((*(uint *)(iVar1 + 0x3c) & 0x800) == 0) {
        if ((*(uint *)(iVar1 + 0x3c) & 0x1000) == 0) goto LAB_8005E6D0;
      }
    }
  }
  local_C = lbl_803DB640;
  GXSetChanAmbColor(0,*(GXColor *)&local_C);
  if ((*(uint *)(iVar1 + 0x3c) & 0x40000) != 0) {
    GXSetChanCtrl(0,0,0,1,0,0,2);
    goto LAB_8005E718;
  }
  GXSetChanCtrl(0,1,0,1,0,0,2);
  goto LAB_8005E718;
LAB_8005E6D0:
  objGetColor(0,&local_16,&local_15,&local_14);
  GXSetChanCtrl(0,1,0,1,0,0,2);
  local_8 = *(int*)&local_16;
  GXSetChanAmbColor(0,*(GXColor *)&local_8);
LAB_8005E718:
  return iVar1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: mapBlockRender_drawDimmedAabbLights
 * EN v1.0 Address: 0x8005E730
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x8005E8AC
 * EN v1.1 Size: 588b
 */
#pragma scheduling off
#pragma peephole off
void mapBlockRender_drawDimmedAabbLights(undefined4 param_1,undefined4 param_2,int param_3)
{
  int *piVar3;
  SfaIntDouble iD1;
  f32 fStack_18;
  f32 fStack_14;
  f32 fStack_10;
  int local_C;
  byte local_B;
  byte local_A;
  byte local_9;
  byte local_8;

  modelLightStruct_selectBrightestAabbLights((undefined*)&lbl_803DCE20,2,&local_C,
              (f32)(*(short *)((int)param_1 + 6) >> 3) + *(float *)((int)param_2 + 0x18) + playerMapOffsetX,
              (f32)(*(short *)((int)param_1 + 8) >> 3) + *(float *)((int)param_2 + 0x28),
              (f32)(*(short *)((int)param_1 + 10) >> 3) + *(float *)((int)param_2 + 0x38) + playerMapOffsetZ,
              (f32)(*(short *)((int)param_1 + 0xc) >> 3) + *(float *)((int)param_2 + 0x18) + playerMapOffsetX,
              (f32)(*(short *)((int)param_1 + 0xe) >> 3) + *(float *)((int)param_2 + 0x28),
              (f32)(*(short *)((int)param_1 + 0x10) >> 3) + *(float *)((int)param_2 + 0x38) + playerMapOffsetZ);
  resetLotsOfRenderVars();
  fn_8004CE0C(param_3);
  param_3 = 0;
  piVar3 = (int *)&lbl_803DCE20;
  {
    byte *pB = &local_B;
    byte *pA = &local_A;
    byte *p9 = &local_9;
    f32 *p18 = &fStack_18;
    f32 *p14 = &fStack_14;
    for (; param_3 < local_C; piVar3 = piVar3 + 1, param_3 = param_3 + 1) {
      modelLightStruct_getColorsA8AC((void *)*piVar3,&local_8,p9,pA,pB);
      local_8 = ((int)local_8 >> 1) + ((int)local_8 >> 2);
      local_9 = ((int)local_9 >> 1) + ((int)local_9 >> 2);
      local_A = ((int)local_A >> 1) + ((int)local_A >> 2);
      modelLightStruct_getPosition((void *)*piVar3,&fStack_10,p14,p18);
      modelLightStruct_getRadius((void *)*piVar3);
      fn_8004FA30(&local_8,&fStack_10);
    }
  }
  textureFn_800528bc();
  GXSetNumChans(1);
  GXSetCullMode(2);
  gxSetZMode_(1,3,0);
  gxSetPeControl_ZCompLoc_(1);
  GXSetBlendMode(1,4,5,5);
  GXSetAlphaCompare(7,0,0,7,0);
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: frustumTestAabbWithPlaneOffsets
 * EN v1.0 Address: 0x8005E97C
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x8005EAF8
 * EN v1.1 Size: 296b
 */
#pragma scheduling off
#pragma peephole off
undefined4
frustumTestAabbWithPlaneOffsets(float param_1,float param_2,float param_3,float param_4,float param_5,
            float param_6,float *param_7)
{
  byte bVar1;
  float *pfVar2;
  int i;
  float dVar4;
  float dVar5;
  float dVar6;
  float dVar7;
  float dVar8;
  float dVar9;

  pfVar2 = (float *)&gViewFrustumPlanes;
  for (i = 5; i != 0; i--, pfVar2 = pfVar2 + 5, param_7 = param_7 + 1) {
    bVar1 = *(byte *)(pfVar2 + 4);
    if ((bVar1 & 1) != 0) {
      dVar5 = param_2;
      dVar8 = param_1;
    } else {
      dVar5 = param_1;
      dVar8 = param_2;
    }
    if ((bVar1 & 2) != 0) {
      dVar4 = param_4;
      dVar7 = param_3;
    } else {
      dVar4 = param_3;
      dVar7 = param_4;
    }
    if ((bVar1 & 4) != 0) {
      dVar9 = param_6;
      dVar6 = param_5;
    } else {
      dVar9 = param_5;
      dVar6 = param_6;
    }
    if ((dVar4 * pfVar2[1] + dVar5 * *pfVar2 + dVar9 * pfVar2[2] + pfVar2[3] + *param_7 < lbl_803DEBCC) &&
        (dVar7 * pfVar2[1] + dVar8 * *pfVar2 + dVar6 * pfVar2[2] + pfVar2[3] + *param_7 < lbl_803DEBCC))
      return 0;
  }
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: mapBlockBounds_ComputeAndTestPlanes
 * EN v1.0 Address: 0x8005EAA4
 * EN v1.0 Size: 476b
 * EN v1.1 Address: 0x8005EC20
 * EN v1.1 Size: 476b
 */
#pragma scheduling off
#pragma peephole off
u8
mapBlockBounds_ComputeAndTestPlanes(int param_1,int param_2,float *param_3,int param_4,float *param_5,float *param_6,
            float *param_7,float *param_8,float *param_9,float *param_10)
{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  int i;

  *param_8 = (f32)(*(short *)(param_1 + 0xc) >> 3) + *(float *)(param_2 + 0x18);
  *param_5 = (f32)(*(short *)(param_1 + 6) >> 3) + *(float *)(param_2 + 0x18);
  *param_9 = (f32)(*(short *)(param_1 + 0xe) >> 3) + *(float *)(param_2 + 0x28);
  *param_6 = (f32)(*(short *)(param_1 + 8) >> 3) + *(float *)(param_2 + 0x28);
  *param_10 = (f32)(*(short *)(param_1 + 0x10) >> 3) + *(float *)(param_2 + 0x38);
  *param_7 = (f32)(*(short *)(param_1 + 10) >> 3) + *(float *)(param_2 + 0x38);
  for (i = 0; i < param_4; i = i + 1) {
    bVar1 = *(byte *)(param_3 + 4);
    if ((bVar1 & 1) != 0) {
      fVar2 = *param_8;
      fVar3 = *param_5;
    }
    else {
      fVar2 = *param_5;
      fVar3 = *param_8;
    }
    if ((bVar1 & 2) != 0) {
      fVar4 = *param_9;
      fVar5 = *param_6;
    }
    else {
      fVar4 = *param_6;
      fVar5 = *param_9;
    }
    if ((bVar1 & 4) != 0) {
      fVar6 = *param_10;
      fVar7 = *param_7;
    }
    else {
      fVar6 = *param_7;
      fVar7 = *param_10;
    }
    if ((param_3[3] + (fVar4 * param_3[1] + fVar2 * *param_3 + fVar6 * param_3[2]) < lbl_803DEBCC)
       && (param_3[3] + (fVar5 * param_3[1] + fVar3 * *param_3 + fVar7 * param_3[2]) <
           lbl_803DEBCC)) {
      return 0;
    }
    param_3 = param_3 + 5;
  }
  return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: mapBlockRender_callList
 * EN v1.0 Address: 0x8005EC80
 * EN v1.0 Size: 1376b
 * EN v1.1 Address: 0x8005EDFC
 * EN v1.1 Size: 1376b
 */
#pragma scheduling off
#pragma peephole off
void mapBlockRender_callList(uint hi,uint lo,int block,u8 *obj,int *stream,float *mtx)
{
  u8 dBig[16];
  int dOut1;
  int dOut0;
  int count;
  float x1;
  float y1;
  float z1;
  float x2;
  float y2;
  float z2;
  u8 c3;
  u8 c2;
  u8 c1;
  u8 c0;
  u8 g3;
  u8 g2;
  u8 g1;
  u8 g0;
  u8 *base;
  u8 *pc1;
  u8 *pc2;
  u8 *pc3;
  int *pd1;
  u8 *pdb;
  int ptr;
  int *p;
  int i;
  uint vis;
  uint flags;
  int pos;
  uint word;
  int bptr;

  base = lbl_8037E0C0;
  pc1 = &c1;
  pc2 = &c2;
  pc3 = &c3;
  pd1 = &dOut1;
  pdb = dBig;
  pos = stream[4];
  word = ((u8 *)*stream)[pos >> 3];
  bptr = *stream + (pos >> 3);
  word = word | (u32)(*(u8 *)(bptr + 1) << 8);
  word = word | (u32)(*(u8 *)(bptr + 2) << 16);
  stream[4] = pos + 8;
  ptr = *(int *)(block + 0x68) + ((word >> (pos & 7)) & 0xff) * 0x1c;
  if ((obj != NULL) && ((*(uint *)(obj + 0x3c) & 2) != 0)) {
    goto end;
  }
  if (mapBlockBounds_ComputeAndTestPlanes(ptr,block,(float *)(base + 0x987c),5,&x1,&y1,&z1,&x2,&y2,&z2) == 0) {
    goto end;
  }
  if ((u8)hi == 0) {
    flags = *(uint *)(obj + 0x3c);
    if ((flags & 0x80000000) != 0) {
      fn_8005D3B4(ptr,block,*(u8 *)(ptr + 0x18));
      *(int *)(base + lbl_803DCE30 * 16 + 0xc) = 5;
      lbl_803DCE30 = lbl_803DCE30 + 1;
    }
    else if (((flags & 0x40000000) != 0) || ((flags & 0x2000) != 0)) {
      fn_8005D3B4(ptr,block,*(u8 *)(ptr + 0x18));
      *(int *)(base + lbl_803DCE30 * 16 + 0xc) = 4;
      lbl_803DCE30 = lbl_803DCE30 + 1;
    }
  }
  else {
    if (obj != NULL) {
      flags = *(uint *)(obj + 0x3c);
      if (((flags & 0x80000000) == 0) && ((flags & 0x20000) == 0)) {
        if ((obj != NULL) && ((flags & 0x80000) != 0)) {
          count = 0;
        }
        else {
          modelLightStruct_selectBrightestAabbLights((undefined *)&lbl_803DCE28,2,&count,x1 + playerMapOffsetX,y1,
                      z1 + playerMapOffsetZ,x2 + playerMapOffsetX,y2,z2 + playerMapOffsetZ);
        }
        if ((obj == NULL) ||
            (((*(uint *)(obj + 0x3c) & 0x800) == 0 && ((*(uint *)(obj + 0x3c) & 0x1000) == 0)))) {
          p = &lbl_803DCE28;
          for (i = 0; i < count; i = i + 1) {
            modelLightStruct_getColorsA8AC((void *)*p,&c0,pc1,pc2,pc3);
            modelLightStruct_getPosition((void *)*p,&dOut0,pd1,pdb);
            modelLightStruct_getRadius((void *)*p);
            fn_8004FA30(&c0,&dOut0);
            p = p + 1;
          }
        }
        else {
          fn_80088730(&g0);
          g3 = 0;
          g2 = 0;
          g1 = 0;
          g0 = 0;
          if (count == 0) {
            if ((obj != NULL) && ((*(uint *)(obj + 0x3c) & 0x800) != 0)) {
              fn_8004EF9C(&g0);
            }
            else {
              fn_8004EECC(&g0);
            }
          }
          else {
            modelLightStruct_getColorsA8AC((void *)lbl_803DCE28,&c0,pc1,pc2,pc3);
            modelLightStruct_getPosition((void *)lbl_803DCE28,&dOut0,pd1,pdb);
            modelLightStruct_getRadius((void *)lbl_803DCE28);
            fn_8004F6D8(&c0,&dOut0,&g0);
            p = &lbl_803DCE28 + 1;
            for (i = 1; i < count; i = i + 1) {
              modelLightStruct_getColorsA8AC((void *)*p,&c0,pc1,pc2,pc3);
              modelLightStruct_getPosition((void *)*p,&dOut0,pd1,pdb);
              modelLightStruct_getRadius((void *)*p);
              fn_8004F380(&c0,&dOut0);
              p = p + 1;
            }
            if ((obj != NULL) && ((*(uint *)(obj + 0x3c) & 0x800) != 0)) {
              fn_8004F2B0();
            }
            else {
              fn_8004F080();
            }
          }
        }
        if ((obj != NULL) && ((*(uint *)(obj + 0x3c) & 0x2000) != 0)) {
          if ((obj != NULL) && ((*(uint *)(obj + 0x3c) & 0x40000000) != 0)) {
            vis = lo;
          }
          else {
            u8 res2 = mapBlockBounds_ComputeAndTestPlanes(ptr,block,(float *)(base + 0x9818),5,&x1,&y1,&z1,&x2,&y2,&z2);
            if (((res2 == 0) || ((u8)lo == 0)) && ((res2 != 0) || ((u8)lo != 0))) {
              vis = 0;
            }
            else {
              vis = 1;
            }
            if ((u8)lo != 0) {
              GXSetBlendMode(1,4,5,5);
              gxSetZMode_(1,3,0);
              gxSetPeControl_ZCompLoc_(1);
              GXSetAlphaCompare(7,0,0,7,0);
            }
          }
          if ((u8)vis == 0) {
            goto end;
          }
          fn_8004D230();
        }
        textureFn_800528bc();
      }
    }
    GXCallDisplayList(*(void **)ptr,*(u16 *)(ptr + 4));
    flags = *(uint *)(obj + 0x3c);
    if ((((flags & 0x4000) != 0) || ((flags & 0x8000) != 0) || ((flags & 0x10000) != 0)) &&
        (mapBlockBounds_HasCornerPastDepthThreshold(ptr,mtx) != 0)) {
      fn_8005D3B4(ptr,block,0x17);
      *(int *)(base + lbl_803DCE30 * 16 + 0xc) = 6;
      lbl_803DCE30 = lbl_803DCE30 + 1;
    }
  }
end:
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: mapBlockRender_setupShaderTextures
 * EN v1.0 Address: 0x8005F1E0
 * EN v1.0 Size: 888b
 * EN v1.1 Address: 0x8005F35C
 * EN v1.1 Size: 888b
 */
#pragma scheduling off
#pragma peephole off
void mapBlockRender_setupShaderTextures(int param_1, int param_2)
{
  int iVar1;
  int *piVar2;
  int iVar3;
  float *pfVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  byte bVar1;
  TexOverride *pE;
  undefined4 local_48;
  Mtx afStack_44;

  local_48 = lbl_803DEBB0;
  if ((*(byte *)(param_1 + 0x41) == 2) &&
     (iVar1 = Shader_getLayer(param_1,1), (int)(*(byte *)(iVar1 + 4) & 0x7f) == 9)) {
    piVar2 = (int *)Shader_getLayer(param_1,0);
    bVar1 = *(byte *)((int)piVar2 + 5);
    if (bVar1 == '\0') {
      iVar1 = *piVar2;
    }
    else {
      iVar1 = *piVar2;
      iVar6 = 0;
      pE = (TexOverride *)lbl_803DCE6C;
      for (iVar7 = 0x50; iVar7 != 0; iVar7--) {
        if (((0 < pE->count) && (pE->id == iVar1)) &&
           ((int)bVar1 == pE->layerByte)) {
          iVar1 = textureCrazyPointerFollowFn_80054c30(iVar1,((TexOverride *)lbl_803DCE6C)[iVar6].ptr);
          break;
        }
        pE = pE + 1;
        iVar6 = iVar6 + 1;
      }
    }
    if (*(byte *)((int)piVar2 + 6) == 0xff) {
      pfVar4 = (float *)0x0;
    }
    else {
      iVar3 = (uint)*(byte *)((int)piVar2 + 6) * 0x10;
      PSMTXTrans(afStack_44,
                 *(float *)(lbl_803DCE68 + iVar3) / lbl_803DEBC8,
                 *(float *)(lbl_803DCE68 + iVar3 + 4) / lbl_803DEBC8,
                 lbl_803DEBCC);
      pfVar4 = (float*)afStack_44;
    }
    fn_80051B00(iVar1,pfVar4,0,(char *)&local_48);
    if ((*(uint *)(param_1 + 0x3c) & 0x100) != 0) {
      fn_8004D928();
    }
    piVar2 = (int *)Shader_getLayer(param_1,1);
    bVar1 = *(byte *)((int)piVar2 + 5);
    if (bVar1 == '\0') {
      iVar1 = *piVar2;
    }
    else {
      iVar1 = *piVar2;
      iVar6 = 0;
      pE = (TexOverride *)lbl_803DCE6C;
      for (iVar7 = 0x50; iVar7 != 0; iVar7--) {
        if (((0 < pE->count) && (pE->id == iVar1)) &&
           ((int)bVar1 == pE->layerByte)) {
          iVar1 = textureCrazyPointerFollowFn_80054c30(iVar1,((TexOverride *)lbl_803DCE6C)[iVar6].ptr);
          break;
        }
        pE = pE + 1;
        iVar6 = iVar6 + 1;
      }
    }
    if (*(byte *)((int)piVar2 + 6) == 0xff) {
      pfVar4 = (float *)0x0;
    }
    else {
      iVar3 = (uint)*(byte *)((int)piVar2 + 6) * 0x10;
      PSMTXTrans(afStack_44,
                 *(float *)(lbl_803DCE68 + iVar3) / lbl_803DEBC8,
                 *(float *)(lbl_803DCE68 + iVar3 + 4) / lbl_803DEBC8,
                 lbl_803DEBCC);
      pfVar4 = (float*)afStack_44;
    }
    fn_80051868(iVar1,pfVar4,9);
    textureFn_800524ec((char *)&local_48);
  }
  else {
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_1 + 0x41); iVar3 = iVar3 + 1) {
      piVar2 = (int *)Shader_getLayer(param_1,iVar3);
      iVar1 = *piVar2;
      if (iVar1 == 0) {
        gxColorFn_800523d0();
      }
      else {
        bVar1 = *(byte *)((int)piVar2 + 5);
        if (bVar1 != '\0') {
          iVar6 = 0;
          piVar5 = (int *)lbl_803DCE6C;
          for (iVar7 = 0x50; iVar7 != 0; iVar7--) {
            if (((0 < *(short *)(piVar5 + 3)) && (*piVar5 == iVar1)) &&
               (bVar1 == *(byte *)((int)piVar5 + 0xe))) {
              iVar1 = textureCrazyPointerFollowFn_80054c30(iVar1,((int *)lbl_803DCE6C)[iVar6 * 4 + 1]);
              break;
            }
            piVar5 = piVar5 + 4;
            iVar6 = iVar6 + 1;
          }
        }
        if (*(byte *)((int)piVar2 + 6) == 0xff) {
          pfVar4 = (float *)0x0;
        }
        else {
          pfVar4 = (float *)(lbl_803DCE68 + (uint)*(byte *)((int)piVar2 + 6) * 0x10);
          PSMTXTrans(afStack_44,*pfVar4 / lbl_803DEBC8,pfVar4[1] / lbl_803DEBC8,lbl_803DEBCC);
          pfVar4 = (float*)afStack_44;
        }
        if ((*(uint *)(param_1 + 0x3c) & 0x40000) == 0) {
          fn_80051868(iVar1,pfVar4,*(byte *)(piVar2 + 1) & 0x7f);
        }
        else {
          fn_80051528(iVar1,pfVar4);
        }
      }
    }
    if ((*(uint *)(param_1 + 0x3c) & 0x100) != 0) {
      fn_8004D928();
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: mapBlockRender_setShader
 * EN v1.0 Address: 0x8005F558
 * EN v1.0 Size: 968b
 * EN v1.1 Address: 0x8005F6D4
 * EN v1.1 Size: 968b
 */
#pragma scheduling off
#pragma peephole off
int mapBlockRender_setShader(byte param_1,int param_2,int *param_3)
{
  uint iVar1;
  uint uVar2;
  uint uPos;
  int local_8;
  int local_c;
  byte local_14[4];
  byte local_18;
  byte local_19;
  byte local_1a;
  int local_1c;

  local_1c = lbl_803E8444;
  uPos = param_3[4];
  {
    int _off = (int)uPos >> 3;
    int _base = *param_3;
    uint3 _bits = *(undefined *)(_base + _off);
    _base += _off;
    _bits |= (uint3)*(undefined *)(_base + 1) << 8;
    _bits |= (uint3)*(undefined *)(_base + 2) << 16;
    param_3[4] = uPos + 6;
    iVar1 = *(int *)((int)param_2 + 0x64);
    uVar2 = (_bits >> (uPos & 7)) & 0x3f;
    iVar1 = iVar1 + uVar2 * 0x44;
  }

  if (param_1 == 0) {
    return iVar1;
  }

  if ((*(uint *)(iVar1 + 0x3c) & 4) != 0) {
    _gxSetFogParams();
    goto LAB_8005F608;
  }
  local_c = local_1c;
  GXSetFog(0,lbl_803DEBCC,lbl_803DEBCC,lbl_803DEBCC,lbl_803DEBCC,*(GXColor*)&local_c);
LAB_8005F608:
  if ((iVar1 != 0) && ((*(uint *)(iVar1 + 0x3c) & 0x80000000) != 0)) {
    return iVar1;
  }
  if ((iVar1 != 0) && ((*(uint *)(iVar1 + 0x3c) & 0x20000) != 0)) {
    uint res;
    res = AttractMovie_DrawTextureCallback(0,0,0);
    if ((res & 0xff) != 0) {
      return iVar1;
    }
  }
  resetLotsOfRenderVars();
  if ((*(uint *)(iVar1 + 0x3c) & 0x80) != 0) {
    fn_8004DA54(iVar1);
    goto LAB_8005F690;
  }
  mapBlockRender_setupShaderTextures(iVar1,(int)0x80);
LAB_8005F690:
  if ((*(uint *)(iVar1 + 0x3c) & 0x20) != 0) {
    int *lPtr = lbl_803DCE34;
    if (lPtr != 0) {
      fn_8004FDA0(lPtr,(int*)&lbl_80382008,&lbl_803DB638);
      goto LAB_8005F6F4;
    }
  }
  if ((*(uint *)(iVar1 + 0x3c) & 0x40) != 0) {
    fn_8004E0FC();
    goto LAB_8005F6F4;
  }
  if (isHeavyFogEnabled()) {
    getColor803dd01c(local_14);
    renderHeavyFog(local_14);
  }
LAB_8005F6F4:
  if (((*(uint *)(iVar1 + 0x3c) & 0x40000000) != 0) || ((*(uint *)(iVar1 + 0x3c) & 0x20000000) != 0)) {
    GXSetBlendMode(1,4,5,5);
    gxSetZMode_(1,3,0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7,0,0,7,0);
    goto LAB_8005F7FC;
  }
  if ((*(uint *)(iVar1 + 0x3c) & 0x400) != 0) {
    if ((*(uint *)(iVar1 + 0x3c) & 0x80) == 0) {
      GXSetBlendMode(0,1,0,5);
      gxSetZMode_(1,3,1);
      gxSetPeControl_ZCompLoc_(0);
      GXSetAlphaCompare(4,0,0,4,0);
      goto LAB_8005F7FC;
    }
  }
  GXSetBlendMode(0,1,0,5);
  gxSetZMode_(1,3,1);
  gxSetPeControl_ZCompLoc_(1);
  GXSetAlphaCompare(7,0,0,7,0);
LAB_8005F7FC:
  if ((*(uint *)(iVar1 + 0x3c) & 1) == 0) {
    if ((*(uint *)(iVar1 + 0x3c) & 0x40000) == 0) {
      if ((*(uint *)(iVar1 + 0x3c) & 0x800) == 0) {
        if ((*(uint *)(iVar1 + 0x3c) & 0x1000) == 0) goto LAB_8005F89C;
      }
    }
  }
  local_c = lbl_803DB63C;
  GXSetChanAmbColor(0,*(GXColor *)&local_c);
  if ((*(uint *)(iVar1 + 0x3c) & 0x40000) != 0) {
    GXSetChanCtrl(0,0,0,1,0,0,2);
    goto LAB_8005F8E4;
  }
  GXSetChanCtrl(0,1,0,1,0,0,2);
  goto LAB_8005F8E4;
LAB_8005F89C:
  objGetColor(0,&local_18,&local_19,&local_1a);
  GXSetChanCtrl(0,1,0,1,0,0,2);
  local_8 = *(int*)&local_18;
  GXSetChanAmbColor(0,*(GXColor *)&local_8);
LAB_8005F8E4:
  if ((*(uint *)(iVar1 + 0x3c) & 0x8) != 0) {
    GXSetCullMode(2);
    goto LAB_8005F908;
  }
  GXSetCullMode(0);
LAB_8005F908:
  return iVar1;
}
#pragma peephole reset
#pragma scheduling reset
