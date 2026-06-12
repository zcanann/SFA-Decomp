#ifndef MAIN_DLL_EFFECTSPAWNPARAMS_STRUCT_H_
#define MAIN_DLL_EFFECTSPAWNPARAMS_STRUCT_H_

#include "types.h"

typedef struct EffectSpawnParams
{
  s16* model;
  int unk04;
  uint count;
  s16 rot0;
  s16 rot1;
  s16 rot2;
  f32 srcW;
  f32 srcX;
  f32 srcY;
  f32 srcZ;
  f32 velX;
  f32 velY;
  f32 velZ;
  f32 posX;
  f32 posY;
  f32 posZ;
  f32 scale;
  s16 unk40;
  s16 kind;
  uint flagsA;
  uint flagsB;
  u32 colA;
  u32 colB;
  u32 colC;
  u16 colD;
  u16 colE;
  u16 colF;
  u8 idByte;
  u8 pad5F;
  u8 alpha;
  u8 unk61;
  u8 srcFlag;
} EffectSpawnParams;

#endif
