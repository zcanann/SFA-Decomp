#include "ghidra_import.h"
#include "main/dll/DF/DFbarrelanim.h"

typedef struct DFRopeNode {
  f32 pos[3];
  f32 velocity[3];
  f32 force[3];
  u8 linkCount;
  u8 pad25[3];
  struct DFRopeLink *links[2];
  u8 locked;
  u8 pad31[3];
} DFRopeNode;

typedef struct DFRopeLink {
  f32 length;
  DFRopeNode *a;
  DFRopeNode *b;
  f32 restLength;
  f32 stiffness;
  f32 maxLength;
  f32 force[3];
} DFRopeLink;

typedef struct DFRope {
  DFRopeNode *nodes;
  DFRopeLink *links;
  u8 count;
  u8 pad09[3];
  f32 start[3];
  f32 end[3];
  f32 totalLength;
  s32 enabled;
  f32 maxSlack;
  f32 step;
  u8 sway;
  u8 direction;
  u8 pad36[2];
  f32 damping;
  f32 inverseTicks;
  f32 stepPerTick;
} DFRope;

extern f32 sqrtf(f32 x);
extern void *mmAlloc(int size, int heap, int flags);
extern void fn_801C11B8(void *link, void *a, void *b);

extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern double FUN_80247f54();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();

extern f64 DOUBLE_803e4df0;
extern f32 lbl_803E4DF8;
extern f32 lbl_803E4DFC;
extern f32 lbl_803E4E00;
extern f32 lbl_803E4E04;
extern f32 lbl_803E4E08;
extern f32 lbl_803E4E0C;
extern f32 lbl_803E4E10;
extern f32 lbl_803E4E14;
extern f32 lbl_803E4E18;
extern f64 DOUBLE_803e5a88;
extern f32 lbl_803E5A90;
extern f32 lbl_803E5A94;

/*
 * --INFO--
 *
 * Function: FUN_801c1238
 * EN v1.0 Address: 0x801C1238
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x801C1414
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void *fn_801C1238(s32 count, f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY, f32 endZ,
                    f32 unused, f32 tickScale)
{
  DFRope *rope;
  DFRopeNode *node;
  DFRopeLink *link;
  DFRopeNode *nextNode;
  s32 linkCount;
  s32 i;
  f32 dx;
  f32 dy;
  f32 dz;
  f32 length;
  f32 invSegments;
  f32 zero;

  dx = endX - startX;
  dy = endY - startY;
  dz = endZ - startZ;
  length = sqrtf(dz * dz + (dx * dx + dy * dy));

  invSegments = (f32)(count - 1);
  dx = dx / invSegments;
  dy = dy / invSegments;
  dz = dz / invSegments;

  rope = (DFRope *)mmAlloc(count * sizeof(DFRopeNode) + (count - 1) * sizeof(DFRopeLink) + sizeof(DFRope),
                           0xFF, 0);
  rope->nodes = (DFRopeNode *)((u8 *)rope + sizeof(DFRope));
  rope->links = (DFRopeLink *)((u8 *)rope + count * sizeof(DFRopeNode) + sizeof(DFRope));
  rope->count = (u8)count;
  rope->totalLength = length;
  rope->start[0] = startX;
  rope->start[1] = startY;
  rope->start[2] = startZ;
  rope->end[0] = endX;
  rope->end[1] = endY;
  rope->end[2] = endZ;
  rope->sway = 0;
  rope->direction = 1;
  rope->damping = lbl_803E4E00;
  rope->enabled = 1;
  rope->step = lbl_803E4DF8;
  if (lbl_803E4E04 < rope->step * length) {
    rope->step = lbl_803E4E04 / length;
  }
  rope->maxSlack = lbl_803E4E08;
  rope->stepPerTick = rope->step / tickScale;
  rope->inverseTicks = lbl_803E4E0C / tickScale;

  zero = lbl_803E4DFC;
  node = rope->nodes;
  for (i = 0; i < count; i++, node++) {
    node->pos[0] = (f32)i * dx + rope->start[0];
    node->pos[1] = (f32)i * dy + rope->start[1];
    node->pos[2] = (f32)i * dz + rope->start[2];
    node->velocity[2] = zero;
    node->velocity[1] = zero;
    node->velocity[0] = zero;
    node->force[2] = zero;
    node->force[1] = zero;
    node->force[0] = zero;
    node->links[1] = NULL;
    node->links[0] = NULL;
    node->locked = 0;
    if ((i == 0) || (i == count - 1)) {
      node->linkCount = 1;
    } else if ((i == 1) || (i == count - 2)) {
      node->linkCount = 2;
    } else {
      node->linkCount = 2;
    }
    {
      s32 j;
      for (j = 0; j < node->linkCount; j++) {
        node->links[j] = NULL;
      }
    }
  }

  rope->nodes[count - 1].locked = 1;
  rope->nodes[0].locked = 1;

  link = rope->links;
  node = rope->nodes;
  linkCount = count - 1;
  for (i = 0; i < linkCount; i++) {
    link->restLength = rope->totalLength / (f32)linkCount;
    link->stiffness = lbl_803E4E10;
    link->force[2] = zero;
    link->force[1] = zero;
    link->force[0] = zero;
    link->maxLength = lbl_803E4E14 * link->restLength;
    nextNode = (DFRopeNode *)((u8 *)rope->nodes + (i + 1) * sizeof(DFRopeNode));
    fn_801C11B8(link, node, nextNode);
    link++;
    node++;
  }
  return rope;
}

/*
 * --INFO--
 *
 * Function: dfropenode_func12
 * EN v1.0 Address: 0x801C1618
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfropenode_func12(int obj, float value)
{
  *(float *)(*(int *)(obj + 0xb8) + 0x14) = value;
}

int dfropenode_func11(int obj)
{
  u32 bit = (*(u8 *)(*(int *)(obj + 0xb8) + 0x30) >> 7);

  return (s16)(bit == 0);
}

void dfropenode_func10(int obj, int value)
{
  u8 bit;
  u8 *extra;
  int nextObj;

  extra = (u8 *)*(int *)(obj + 0xb8);
  bit = (value == 0);
  extra[0x30] = (extra[0x30] & 0x7F) | (bit << 7);
  nextObj = *(int *)extra;
  if (nextObj != 0) {
    extra = (u8 *)*(int *)(nextObj + 0xb8);
    extra[0x30] = (extra[0x30] & 0x7F) | (bit << 7);
  }
}

/*
 * --INFO--
 *
 * Function: dfropenode_func13
 * EN v1.0 Address: 0x801C1688
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void dfropenode_func13(int obj)
{
  int value = 0;
  int extra = *(int *)(obj + 0xb8);

  *(int *)extra = value;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfropenode_func0F
 * EN v1.0 Address: 0x801C167C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfropenode_func0F(int obj)
{
  return *(short *)(*(int *)(obj + 0xb8) + 0x18);
}

f32 fn_801C1698(f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY, f32 endZ, f32 *x, f32 *y,
                f32 *z)
{
  f32 dx;
  f32 dy;
  f32 dz;
  f32 t;

  dx = endX - startX;
  dy = endY - startY;
  dz = endZ - startZ;
  if ((lbl_803E4DFC == dx) && (lbl_803E4DFC == dz)) {
    t = lbl_803E4DFC;
  } else {
    t = (dx * (*x - startX) + dz * (*z - startZ)) / (dx * dx + dz * dz);
  }
  if (t < lbl_803E4DFC) {
    *x = startX;
    *y = startY;
    *z = startZ;
  } else if (t >= lbl_803E4E18) {
    *x = endX;
    *y = endY;
    *z = endZ;
  } else {
    *x = t * dx + startX;
    *y = t * dy + startY;
    *z = t * dz + startZ;
  }
  return t;
}
