#include "ghidra_import.h"
#include "main/dll/baddie/MMP_critterspit.h"

extern f32 lbl_803E242C;
extern f32 lbl_803E24C4;

extern u8 *ObjGroup_FindNearestObject(int kind, u8 *self, f32 *outDist);
extern int GameBit_Get(int bit);
extern int fn_8005AFAC(u8 *p, f32 a, f32 b);
extern f32 vec3f_distanceSquared(f32 *a, f32 *b);

#pragma peephole off

/*
 * --INFO--
 *
 * Function: trickyFoodFn_8013db3c
 * EN v1.0 Address: 0x8013DB3C
 * EN v1.0 Size: 332b
 */
int trickyFoodFn_8013db3c(u8 *arg1, u8 *arg2)
{
  int result = 0;
  f32 dist = lbl_803E242C;
  struct CritterByte {
    u8 pad_high : 3;
    u8 mode : 4;
    u8 pad_low : 1;
  } *bf = (struct CritterByte *)&arg2[0x58];

  if (bf->mode != 0) {
    bf->mode = bf->mode - 1;
    result = 1;
  }

  if (ObjGroup_FindNearestObject(0x53, arg1, &dist) != NULL) {
    return 0;
  }

  if ((s8)arg2[0xD] != 3) {
    if ((*(u16 *)((u8 *)*(u32 *)(arg2 + 4) + 0xB0) & 0x1000) != 0) {
      if (fn_8005AFAC((u8 *)*(u32 *)(arg2 + 4), *(f32 *)(arg1 + 0xC),
                      *(f32 *)(arg1 + 0x14)) == 0x38) {
        if ((GameBit_Get(0x385) == 0) && (GameBit_Get(0x384) != 0)) {
          if ((GameBit_Get(0xC1) != 0) || (GameBit_Get(0x12E) != 0)) {
            result = 1;
          }
        }
      } else {
        bf->mode = 0x1F;
        result = 1;
      }
    }
  }

  if (result == 1) {
    if (vec3f_distanceSquared((f32 *)((u8 *)*(u32 *)(arg2 + 4) + 0x18),
                    (f32 *)(arg1 + 0x18)) < lbl_803E24C4) {
      return 2;
    }
  }
  return result;
}
