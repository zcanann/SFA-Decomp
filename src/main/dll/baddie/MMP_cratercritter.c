#include "ghidra_import.h"
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

extern char sInWaterMessage[];
extern char lbl_8031D478[];

extern int fn_8013DB3C(u8 *arg1, u8 *arg2);
extern u8 **ObjGroup_GetObjects(int kind, int *count);
extern f32 fn_8002166C(f32 *a, f32 *b);
extern int fn_8013B368(u8 *arg1, u8 *arg2, f32 dist);
extern void fn_8013A3F0(u8 *self, int a, int b, f32 f1);
extern void fn_80148BC8(char *msg);

/*
 * --INFO--
 *
 * Function: fn_8013D8F0
 * EN v1.0 Address: 0x8013D8F0
 * EN v1.0 Size: 588b
 */
void fn_8013D8F0(u8 *arg1, u8 *arg2)
{
  f32 minDist;
  f32 dist;
  u8 *nearest;
  u8 **objs;
  int count;
  int i;
  int waterFlag;

  nearest = NULL;
  minDist = lbl_803E2418;

  if (fn_8013DB3C(arg1, arg2) == 0) {
    arg2[0x8] = 1;
    arg2[0xA] = 0;
    *(f32 *)(arg2 + 0x71C) = lbl_803E23DC;
    *(f32 *)(arg2 + 0x720) = lbl_803E23DC;
    *(u32 *)(arg2 + 0x54) = *(u32 *)(arg2 + 0x54) & 0xFFFFFFEF;
    *(u32 *)(arg2 + 0x54) = *(u32 *)(arg2 + 0x54) & 0xFFFEFFFF;
    *(u32 *)(arg2 + 0x54) = *(u32 *)(arg2 + 0x54) & 0xFFFDFFFF;
    *(u32 *)(arg2 + 0x54) = *(u32 *)(arg2 + 0x54) & 0xFFFBFFFF;
    arg2[0xD] = 0xFF;
    return;
  }

  objs = ObjGroup_GetObjects(0x4B, &count);
  for (i = 0; i < count; i++) {
    dist = fn_8002166C((f32 *)((u8 *)*(int *)(arg2 + 4) + 0x18),
                       (f32 *)(*objs + 0x18));
    if (dist > lbl_803E24C4) {
      dist = fn_8002166C((f32 *)(arg1 + 0x18), (f32 *)(*objs + 0x18));
      if (dist < minDist) {
        nearest = *objs;
        minDist = dist;
      }
    }
    objs++;
  }

  if (nearest != NULL) {
    *(u8 **)(arg2 + 0x24) = nearest;
    if (*(u32 *)(arg2 + 0x28) != (u32)(nearest + 0x18)) {
      *(u32 *)(arg2 + 0x28) = (u32)(nearest + 0x18);
      *(u32 *)(arg2 + 0x54) = *(u32 *)(arg2 + 0x54) & 0xFFFFFBFF;
      *(s16 *)(arg2 + 0xD2) = 0;
    }
    if (fn_8013B368(arg1, arg2, lbl_803E247C) == 1) return;
  }

  if (lbl_803E23DC == *(f32 *)(arg2 + 0x2AC)) {
    waterFlag = 0;
  } else if (lbl_803E2410 == *(f32 *)(arg2 + 0x2B0)) {
    waterFlag = 1;
  } else if (*(f32 *)(arg2 + 0x2B4) - *(f32 *)(arg2 + 0x2B0) > lbl_803E2414) {
    waterFlag = 1;
  } else {
    waterFlag = 0;
  }

  if (waterFlag != 0) {
    fn_8013A3F0(arg1, 8, 0, lbl_803E243C);
    *(f32 *)(arg2 + 0x79C) = lbl_803E2440;
    *(f32 *)(arg2 + 0x838) = lbl_803E23DC;
    fn_80148BC8(sInWaterMessage);
  } else {
    fn_8013A3F0(arg1, 0, 0, lbl_803E2444);
    fn_80148BC8(lbl_8031D478);
  }
}
