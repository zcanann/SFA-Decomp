#ifndef MAIN_DLL_DF_DFBARREL_H_
#define MAIN_DLL_DF_DFBARREL_H_

#include "ghidra_import.h"

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

void fn_801C0FD8(u8 *self);
void fn_801C11B8(DFRopeLink *linkSelf, DFRopeNode *firstNode, DFRopeNode *secondNode);

#endif /* MAIN_DLL_DF_DFBARREL_H_ */
