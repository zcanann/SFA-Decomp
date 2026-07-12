#ifndef MAIN_DLL_EFFECTSRCPARAMS_STRUCT_H_
#define MAIN_DLL_EFFECTSRCPARAMS_STRUCT_H_

#include "types.h"
#include "main/vec_types.h"

typedef struct EffectSrcParams
{
  union
  {
    struct
    {
      s16 rot0;
      s16 rot1;
      s16 rot2;
      s16 pad06;
    };
    struct
    {
      s16 rotX;
      s16 rotY;
      s16 rotZ;
      s16 padRot;
    };
    struct
    {
      s16 arg0;
      s16 arg1;
      s16 arg2;
      s16 arg3;
    };
    Vec3s rotation;
  };
  union
  {
    f32 w;
    f32 scale;
  };
  union
  {
    f32 x;
    f32 posX;
  };
  union
  {
    f32 y;
    f32 posY;
  };
  union
  {
    f32 z;
    f32 posZ;
  };
} EffectSrcParams;

#endif
