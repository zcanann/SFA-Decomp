#include "ghidra_import.h"
#include "main/dll/DF/DFbarrel.h"
#include "dolphin/mtx.h"

extern f32 lbl_803E4DF8;
extern f32 lbl_803E4DFC;

extern void fn_801C0E60(u8 *self);

#define DFBARREL_ROPE_PART_SIZE 0x34
#define DFBARREL_ROPE_LINK_SIZE 0x24

#define DFBARREL_SWAY_LIMIT 0x32
#define DFBARREL_SWAY_DIR_INCREASING 1
#define DFBARREL_SWAY_DIR_DECREASING 2

#define DFBARREL_NODE_LINK_LIMIT_OFFSET 0x24
#define DFBARREL_NODE_LINKS_OFFSET 0x28
#define DFBARREL_LINK_FIRST_NODE_OFFSET 0x4
#define DFBARREL_LINK_SECOND_NODE_OFFSET 0x8

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

  if ((s8)self[0x34] < -DFBARREL_SWAY_LIMIT) {
    self[0x35] = DFBARREL_SWAY_DIR_INCREASING;
  }
  if ((s8)self[0x34] > DFBARREL_SWAY_LIMIT) {
    self[0x35] = DFBARREL_SWAY_DIR_DECREASING;
  }
  if ((s8)self[0x35] == DFBARREL_SWAY_DIR_DECREASING) {
    self[0x34]--;
  } else {
    self[0x34]++;
  }

  i = 1;
  partIter = partsInit + DFBARREL_ROPE_PART_SIZE;
  {
    f32 rate = lbl_803E4DF8;
    for (; i < (int)self[0x8] - 1; i++) {
      *(f32 *)(partIter + 0x18) =
          *(f32 *)(partIter + 0x18) + rate * (f32)(int)(s8)self[0x34];
      partIter += DFBARREL_ROPE_PART_SIZE;
    }
  }

  k = 0;
  zero = lbl_803E4DFC;
  for (; k < *(int *)(self + 0x28); k++) {
    link = (u8 *)*(int *)(self + 0x4);
    for (j = 0; j < (int)self[0x8] - 1; j++, link += DFBARREL_ROPE_LINK_SIZE) {
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
    for (; i < (int)self[0x8]; i++, parts += DFBARREL_ROPE_PART_SIZE) {
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
void fn_801C11B8(u8 *linkSelf, u8 *firstNode, u8 *secondNode)
{
  u8 *nodeLinkIter;
  int firstLinkIndex;
  int secondLinkIndex;

  firstLinkIndex = 0;
  secondLinkIndex = 0;
  nodeLinkIter = firstNode;
  while (*(u32 *)(nodeLinkIter + DFBARREL_NODE_LINKS_OFFSET) != 0) {
    nodeLinkIter += 4;
    firstLinkIndex++;
  }
  nodeLinkIter = secondNode;
  while (*(u32 *)(nodeLinkIter + DFBARREL_NODE_LINKS_OFFSET) != 0) {
    nodeLinkIter += 4;
    secondLinkIndex++;
  }
  if (firstLinkIndex > (int)firstNode[DFBARREL_NODE_LINK_LIMIT_OFFSET]) return;
  if (secondLinkIndex > (int)secondNode[DFBARREL_NODE_LINK_LIMIT_OFFSET]) return;
  ((u32 *)(firstNode + DFBARREL_NODE_LINKS_OFFSET))[firstLinkIndex] = (u32)linkSelf;
  ((u32 *)(secondNode + DFBARREL_NODE_LINKS_OFFSET))[secondLinkIndex] = (u32)linkSelf;
  *(u32 *)(linkSelf + DFBARREL_LINK_FIRST_NODE_OFFSET) = (u32)firstNode;
  *(u32 *)(linkSelf + DFBARREL_LINK_SECOND_NODE_OFFSET) = (u32)secondNode;
}
