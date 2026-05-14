#include "ghidra_import.h"
#include "main/dll/DF/DFbarrel.h"
#include "dolphin/mtx.h"

extern f32 lbl_803E4DF8;
extern f32 lbl_803E4DFC;

extern void fn_801C0E60(u8 *self);

#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: fn_801C0FD8
 * EN v1.0 Address: 0x801C0FD8
 * EN v1.0 Size: 480b
 */
void fn_801C0FD8(u8 *self)
{
  int j;
  u8 *link;
  int k;
  u8 *parts;
  int i;
  u8 *partIter;
  Vec tmp;
  f32 zero;
  u8 *partsInit;

  partsInit = (u8 *)*(int *)(self + 0x0);
  parts = partsInit;

  if ((s8)self[0x34] < -0x32) {
    self[0x35] = 1;
  }
  if ((s8)self[0x34] > 0x32) {
    self[0x35] = 2;
  }
  if ((s8)self[0x35] == 2) {
    self[0x34]--;
  } else {
    self[0x34]++;
  }

  i = 1;
  partIter = partsInit + 0x34;
  {
    f32 rate = lbl_803E4DF8;
    for (; i < (int)self[0x8] - 1; i++) {
      *(f32 *)(partIter + 0x18) =
          *(f32 *)(partIter + 0x18) + rate * (f32)(int)(s8)self[0x34];
      partIter += 0x34;
    }
  }

  k = 0;
  zero = lbl_803E4DFC;
  for (; k < *(int *)(self + 0x28); k++) {
    link = (u8 *)*(int *)(self + 0x4);
    for (j = 0; j < (int)self[0x8] - 1; j++, link += 0x24) {
      PSVECSubtract((Vec *)*(int *)(link + 0x4), (Vec *)*(int *)(link + 0x8), &tmp);
      *(f32 *)(link + 0x0) = PSVECMag(&tmp);
      if (*(f32 *)(link + 0x0) > *(f32 *)(link + 0x14)) {
        *(f32 *)(link + 0xC) = lbl_803E4DFC;
      }
      if (zero == *(f32 *)(link + 0xC)) {
        *(f32 *)(link + 0x20) = zero;
        *(f32 *)(link + 0x1C) = zero;
        *(f32 *)(link + 0x18) = zero;
      } else {
        PSVECScale(&tmp, (Vec *)(link + 0x18),
                   -*(f32 *)(link + 0x10) * (*(f32 *)(link + 0x0) - *(f32 *)(link + 0xC)));
      }
    }
    fn_801C0E60(self);
  }

  i = 0;
  {
    f32 cleanZero = lbl_803E4DFC;
    for (; i < (int)self[0x8]; i++, parts += 0x34) {
      *(f32 *)(parts + 0x18) = cleanZero;
      *(f32 *)(parts + 0x1C) = cleanZero;
      *(f32 *)(parts + 0x20) = cleanZero;
    }
  }
}

/*
 * --INFO--
 *
 * Function: fn_801C11B8
 * EN v1.0 Address: 0x801C11B8
 * EN v1.0 Size: 128b
 */
void fn_801C11B8(u8 *self, u8 *a, u8 *b)
{
  u8 *p;
  int i;
  int j;

  i = 0;
  j = 0;
  p = a;
  while (*(u32 *)(p + 0x28) != 0) {
    p += 4;
    i++;
  }
  p = b;
  while (*(u32 *)(p + 0x28) != 0) {
    p += 4;
    j++;
  }
  if (i > (int)a[0x24]) return;
  if (j > (int)b[0x24]) return;
  ((u32 *)(a + 0x28))[i] = (u32)self;
  ((u32 *)(b + 0x28))[j] = (u32)self;
  *(u32 *)(self + 0x4) = (u32)a;
  *(u32 *)(self + 0x8) = (u32)b;
}
