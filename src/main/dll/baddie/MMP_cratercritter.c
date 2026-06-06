#include "main/dll/baddie/MMP_cratercritter.h"

extern f32 lbl_803E23DC;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E2418;
extern f32 lbl_803E243C;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E247C;
extern f32 lbl_803E24C4;

extern const char sInWaterMessage[];
extern const char lbl_8031D478[];

extern int trickyFoodFn_8013db3c(u8 *arg1, u8 *arg2);
extern u8 **ObjGroup_GetObjects(int kind, int *count);
extern f32 getXZDistance(f32 *a, f32 *b);
extern int trickyFn_8013b368(u8 *arg1, u8 *arg2, f32 dist);
extern void objAnimFn_8013a3f0(u8 *self, int a, int b, f32 f1);
extern int trickyDebugPrint(const char *fmt, ...);

/*
 * --INFO--
 *
 * Function: trickyFn_8013d8f0
 * EN v1.0 Address: 0x8013D8F0
 * EN v1.0 Size: 588b
 */
#pragma scheduling off
#pragma peephole off
void trickyFn_8013d8f0(u8 *self, u8 *state)
{
  u8 *nearest;
  f32 rejectDist;
  f32 minDist;
  f32 dist;
  f32 zero;
  u8 **objs;
  int count;
  int i;
  int waterFlag;

  nearest = NULL;
  minDist = lbl_803E2418;

  if (trickyFoodFn_8013db3c(self, state) == 0) {
    state[0x8] = 1;
    state[0xA] = 0;
    zero = lbl_803E23DC;
    *(f32 *)(state + 0x71C) = zero;
    *(f32 *)(state + 0x720) = zero;
    *(u32 *)(state + 0x54) = *(u32 *)(state + 0x54) & 0xFFFFFFEF;
    *(u32 *)(state + 0x54) = *(u32 *)(state + 0x54) & 0xFFFEFFFF;
    *(u32 *)(state + 0x54) = *(u32 *)(state + 0x54) & 0xFFFDFFFF;
    *(u32 *)(state + 0x54) = *(u32 *)(state + 0x54) & 0xFFFBFFFF;
    *(s8 *)(state + 0xD) = -1;
    return;
  }

  objs = ObjGroup_GetObjects(0x4B, &count);
  rejectDist = lbl_803E24C4;
  for (i = 0; i < count; i++) {
    dist = getXZDistance((f32 *)((u8 *)*(int *)(state + 4) + 0x18),
                       (f32 *)(*objs + 0x18));
    if (dist > rejectDist) {
      dist = getXZDistance((f32 *)(self + 0x18), (f32 *)(*objs + 0x18));
      if (dist < minDist) {
        nearest = *objs;
        minDist = dist;
      }
    }
    objs++;
  }

  if (nearest != NULL) {
    *(u8 **)(state + 0x24) = nearest;
    if (*(u32 *)(state + 0x28) != (u32)(nearest + 0x18)) {
      *(u32 *)(state + 0x28) = (u32)(nearest + 0x18);
      *(u32 *)(state + 0x54) = *(u32 *)(state + 0x54) & 0xFFFFFBFF;
      *(s16 *)(state + 0xD2) = 0;
    }
    if (trickyFn_8013b368(self, state, lbl_803E247C) == 1) return;
  }

  if (lbl_803E23DC == *(f32 *)(state + 0x2AC)) {
    waterFlag = 0;
  } else if (lbl_803E2410 == *(f32 *)(state + 0x2B0)) {
    waterFlag = 1;
  } else if (*(f32 *)(state + 0x2B4) - *(f32 *)(state + 0x2B0) > lbl_803E2414) {
    waterFlag = 1;
  } else {
    waterFlag = 0;
  }

  if (waterFlag != 0) {
    objAnimFn_8013a3f0(self, 8, 0, lbl_803E243C);
    *(f32 *)(state + 0x79C) = lbl_803E2440;
    *(f32 *)(state + 0x838) = lbl_803E23DC;
    trickyDebugPrint(sInWaterMessage);
  } else {
    objAnimFn_8013a3f0(self, 0, 0, lbl_803E2444);
    trickyDebugPrint(lbl_8031D478);
  }
}
#pragma peephole reset
#pragma scheduling reset
