#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/waterfallControl.h"


extern int hitDetectFn_80065e50(f32 x, f32 y, f32 z, int obj, int *hitsOut, int pointCount,
                                int mask);
extern u32 randomGetRange(int min, int max);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void ObjHits_EnableObject(int obj);
extern void ObjHits_DisableObject(int *obj);
extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
extern void ObjGroup_RemoveObject(int *obj, int group);
extern void objRenderFn_8003b8f4(f32);

extern f32 timeDelta;
extern f32 lbl_803E2F5C;
extern f32 lbl_803E2F60;
extern f32 lbl_803E2F64;
extern f32 lbl_803E2F68;
extern f64 lbl_803E2F70;
extern f32 lbl_803E2F78;
extern f32 lbl_803E2F7C;
extern f32 lbl_803E2F80;
extern f32 lbl_803E2F84;
extern f32 lbl_803E2F88;
extern f64 lbl_803E2F90;
extern f32 lbl_803E2F98;
extern f32 lbl_803E2F9C;

#pragma peephole off
#pragma scheduling off

#pragma peephole on
/*
 * --INFO--
 *
 * Function: tumbleweed_updateRollingMotion
 * EN v1.0 Address: 0x80163BBC
 * EN v1.0 Size: 976b
 */
void tumbleweed_updateRollingMotion(short *param_1, int param_2)
{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  f32 dVar6;
  f32 dVar7;
  undefined4 *local_68[2];

  local_68[0] = (undefined4 *)0x0;
  dVar7 = lbl_803E2F78;
  iVar1 = hitDetectFn_80065e50(*(float *)(param_1 + 6), *(float *)(param_1 + 8),
                               *(float *)(param_1 + 10), (int)param_1, (int *)local_68, 0, 0);
  iVar5 = 0;
  puVar3 = local_68[0];
  for (iVar4 = 0; iVar4 < iVar1; iVar4++) {
    dVar6 = *(float *)(param_1 + 8) - *(float *)*puVar3;
    if (dVar6 < lbl_803E2F68) {
      dVar6 = lbl_803E2F7C * dVar6 + lbl_803E2F5C;
    }
    if (dVar6 < dVar7) {
      iVar5 = iVar4;
      dVar7 = dVar6;
    }
    puVar3 = puVar3 + 1;
  }
  if (*(float *)(param_1 + 0x12) > lbl_803E2F80) {
    *(float *)(param_1 + 0x12) = lbl_803E2F80;
  }
  else if (*(float *)(param_1 + 0x12) < lbl_803E2F7C) {
    *(float *)(param_1 + 0x12) = lbl_803E2F7C;
  }
  if (*(float *)(param_1 + 0x14) > lbl_803E2F80) {
    *(float *)(param_1 + 0x14) = lbl_803E2F80;
  }
  else if (*(float *)(param_1 + 0x14) < lbl_803E2F7C) {
    *(float *)(param_1 + 0x14) = lbl_803E2F7C;
  }
  if (*(float *)(param_1 + 0x16) > lbl_803E2F80) {
    *(float *)(param_1 + 0x16) = lbl_803E2F80;
  }
  else if (*(float *)(param_1 + 0x16) < lbl_803E2F7C) {
    *(float *)(param_1 + 0x16) = lbl_803E2F7C;
  }
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * timeDelta + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * timeDelta + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * timeDelta + *(float *)(param_1 + 10);
  iVar1 = (int)((f32)(int)*(s16 *)(param_2 + 0x27c) * timeDelta + (f32)(int)param_1[2]);
  param_1[2] = (short)iVar1;
  iVar1 = (int)((f32)(int)*(s16 *)(param_2 + 0x27e) * timeDelta + (f32)(int)param_1[1]);
  param_1[1] = (short)iVar1;
  iVar1 = (int)((f32)(int)*(s16 *)(param_2 + 0x280) * timeDelta + (f32)(int)*param_1);
  *param_1 = (short)iVar1;
  if (local_68[0] != (undefined4 *)0x0) {
    if (lbl_803E2F60 + *(float *)local_68[0][iVar5] < *(float *)(param_1 + 8)) {
      *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + lbl_803E2F64;
    }
    else {
      *(float *)(param_1 + 8) = lbl_803E2F60 + *(float *)local_68[0][iVar5];
      if (param_1[0x23] == 0x3fb) {
        uVar2 = randomGetRange(0x8c, 0xb4);
        *(f32 *)(param_1 + 0x14) =
            -(lbl_803E2F84 * *(f32 *)(param_1 + 0x14) *
              ((f32)*(ushort *)(param_2 + 0x268) / (f32)(int)uVar2));
      }
      else {
        uVar2 = randomGetRange(0x14, 0x28);
        *(f32 *)(param_1 + 0x14) =
            -(lbl_803E2F84 * *(f32 *)(param_1 + 0x14) *
              ((f32)*(ushort *)(param_2 + 0x268) / (f32)(int)uVar2));
      }
      iVar5 = (int)(lbl_803E2F88 * *(f32 *)(param_1 + 0x14));
      if (0x7f < iVar5) {
        iVar5 = 0x7f;
      }
      if (0x10 < iVar5) {
        Sfx_PlayFromObject((int)param_1, SFXsc_gethit02);
        uVar2 = randomGetRange(0, 5);
        if ((uVar2 == 0) && ((*(byte *)(param_2 + 0x27a) & 8) != 0)) {
          Sfx_PlayFromObject((int)param_1, SFXsc_gethit03);
        }
      }
    }
  }
  return;
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: tumbleweed_func0F
 * EN v1.0 Address: 0x80163F8C
 * EN v1.0 Size: 12b
 */
void tumbleweed_func0F(int obj, int value)
{
  *(int *)(*(int *)(obj + 0xb8) + 0x284) = value;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_func0E
 * EN v1.0 Address: 0x80163F98
 * EN v1.0 Size: 24b
 */
int tumbleweed_func0E(int obj)
{
  return *(byte *)(*(int *)(obj + 0xb8) + 0x278) == 6;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_render2
 * EN v1.0 Address: 0x80163FB0
 * EN v1.0 Size: 64b
 */
void tumbleweed_render2(int *obj, int p2) {
    int *state = *(int**)((char*)obj + 0xb8);
    *(u8*)((char*)state + 0x278) = 6;
    *(int*)((char*)state + 0x290) = p2;
    *(f32*)((char*)state + 0x294) = timeDelta * lbl_803E2F98;
    ObjHits_DisableObject(obj);
}

/*
 * --INFO--
 *
 * Function: tumbleweed_modelMtxFn
 * EN v1.0 Address: 0x80163FF0
 * EN v1.0 Size: 112b
 */
void tumbleweed_modelMtxFn(int obj)
{
  int state = *(int *)(obj + 0xb8);
  if (*(u8 *)(state + 0x278) == 1) {
    ObjHits_EnableObject(obj);
    *(u8 *)(state + 0x278) = 2;
    *(u8 *)(state + 0x27a) |= 3;
    if (*(s16 *)(obj + 0x46) == 0x4c1) {
      *(f32 *)(state + 0x2a0) = lbl_803E2F9C;
    }
  }
}

/*
 * --INFO--
 *
 * Function: tumbleweed_func0B
 * EN v1.0 Address: 0x80164060
 * EN v1.0 Size: 16b
 */
void tumbleweed_func0B(int obj, float x, float y)
{
  int extra = *(int *)(obj + 0xb8);

  *(float *)(extra + 0x288) = x;
  *(float *)(extra + 0x28c) = y;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_setScale
 * EN v1.0 Address: 0x80164070
 * EN v1.0 Size: 12b
 */
int tumbleweed_setScale(int obj)
{
  return *(byte *)(*(int *)(obj + 0xb8) + 0x278);
}

/*
 * --INFO--
 *
 * Function: tumbleweed_getExtraSize
 * EN v1.0 Address: 0x8016407C
 * EN v1.0 Size: 8b
 */
int tumbleweed_getExtraSize(void)
{
  return 0x2a4;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_free
 * EN v1.0 Address: 0x80164084
 * EN v1.0 Size: 252b
 */
void tumbleweed_free(int *obj)
{
  int *items;
  int counter;
  int limit;
  int target_id;

  switch (*(s16 *)((int)obj + 0x46)) {
  case 0x39d:
    target_id = 0x28d;
    break;
  case 0x3fb:
    target_id = 0x3fd;
    break;
  case 0x4ba:
    target_id = 0x4b9;
    break;
  case 0x4c1:
    target_id = 0x4be;
    break;
  }

  items = ObjList_GetObjects(&counter, &limit);
  while (counter < limit) {
    int *o = (int *)items[counter];
    if (target_id == *(s16 *)((int)o + 0x46)) {
      (*(code *)(**(int **)((int)o + 0x68) + 0x20))(o, obj);
    }
    counter = counter + 1;
  }
  ObjGroup_RemoveObject(obj, 3);
  ObjGroup_RemoveObject(obj, 0x31);
}

/*
 * --INFO--
 *
 * Function: tumbleweed_render
 * EN v1.0 Address: 0x80164180
 * EN v1.0 Size: 48b
 */
void tumbleweed_render(int p1, int p2, int p3, int p4, int p5, s8 visible) {
    if ((s32)visible >= 1) objRenderFn_8003b8f4(lbl_803E2F80);
}
