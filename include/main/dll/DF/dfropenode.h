#ifndef MAIN_DLL_DF_DFROPENODE_H_
#define MAIN_DLL_DF_DFROPENODE_H_

#include "ghidra_import.h"
#include "main/dll/DF/DFbarrel.h"

typedef struct DFropenodeObject DFropenodeObject;

typedef struct DFropenodeExtra {
  DFropenodeObject *linkedObj;
  f32 minX;
  f32 maxX;
  f32 minZ;
  f32 maxZ;
  f32 minY;
  s16 angle;
  u8 pad1A[2];
  f32 planeNormalX;
  f32 planeNormalY;
  f32 planeNormalZ;
  f32 planeDistance;
  DFRope *rope;
  u8 hidden : 1;
  u8 pad30 : 7;
  u8 pad31[3];
} DFropenodeExtra;

struct DFropenodeObject {
  u8 pad000[0xc];
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 pad018[0x44 - 0x18];
  s16 objType;
  u8 pad046[0x4c - 0x46];
  u8 *definition;
  u8 pad050[0xb8 - 0x50];
  DFropenodeExtra *extra;
};

#endif /* MAIN_DLL_DF_DFROPENODE_H_ */
