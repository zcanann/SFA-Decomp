#include "main/mapEvent.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/DF/DFlantern.h"
#include "main/dll/DF/dll_198.h"
#include "main/objanim.h"

extern uint GameBit_Get(int eventId);
extern int *objFindTexture(int obj, int textureIndex, int materialIndex);
extern void objRenderFn_8003b8f4(f32);
extern void ModelLightStruct_free(void *light);
extern void gameTimerStop(void);
extern int mapGetDirIdx(int mapId);
extern void unlockLevel(int mapDir,int mode,int flags);
extern void Music_Trigger(int trackId,int mode);
extern void GameBit_Set(int bit,int value);
extern u8 *Obj_GetPlayerObject(void);
extern void fn_80296518(void *obj,int arg,int enable);
extern s16 getAngle(f32 deltaX,f32 deltaZ);
extern f32 Vec_xzDistance(void *a,void *b);
extern f32 mathSinf(f32 angle);
extern MapEventInterface **gMapEventInterface;
extern void modelLightStruct_setEnabled(int light,int mode,f32 value);

extern f32 lbl_803E4E38;
extern f32 timeDelta;
extern f32 lbl_803E4E50;
extern f32 lbl_803E4E54;
extern f32 lbl_803E4E58;
extern f32 lbl_803E4E5C;
extern f32 lbl_803E4E60;
extern f32 lbl_803E4E64;
extern f32 lbl_803E4E68;
extern f32 lbl_803E4E6C;
extern f32 lbl_803E4E70;
extern f32 lbl_803E4E74;
extern f32 lbl_803E4E78;
extern f32 lbl_803E4E88;

typedef struct DFlanternShrineState {
  void *light;
  u8 pad04[0x14 - 0x04];
  s16 orbitA;
  s16 orbitB;
  s16 orbitC;
  u8 pad1a[0x1c - 0x1a];
  u8 flags;
} DFlanternShrineState;

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_free
 * EN v1.0 Address: 0x801C282C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_door2speci_free(void)
{
}

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_render
 * EN v1.0 Address: 0x801C2830
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void dfsh_door2speci_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
  s32 v;

  v = visible;
  if (v != 0) {
    objRenderFn_8003b8f4(lbl_803E4E38);
  }
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_hitDetect
 * EN v1.0 Address: 0x801C2860
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_door2speci_hitDetect(void)
{
}

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_update
 * EN v1.0 Address: 0x801C2864
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_door2speci_update(void)
{
}

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_init
 * EN v1.0 Address: 0x801C2868
 * EN v1.0 Size: 164b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dfsh_door2speci_init(int obj,int def)
{
  int state;
  int *texture;

  state = *(int *)&((GameObject *)obj)->extra;
  ((GameObject *)obj)->animEventCallback = (void *)DFSH_Door2Speci_SeqFn;
  if (GameBit_Get((int)*(short *)(def + 0x22)) != 0) {
    *(unsigned char *)(state + 3) = 2;
  }
  else {
    *(unsigned char *)(state + 3) = 0;
  }
  texture = objFindTexture(obj,0,0);
  if (texture != (int *)0x0) {
    if (*(unsigned char *)(state + 3) == 2) {
      *texture = 1;
    }
    else {
      *texture = 0;
    }
  }
  *(short *)state = 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_release
 * EN v1.0 Address: 0x801C290C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_door2speci_release(void)
{
}

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_initialise
 * EN v1.0 Address: 0x801C2910
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_door2speci_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: fn_801C2914
 * EN v1.0 Address: 0x801C2914
 * EN v1.0 Size: 852b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_801C2914(int obj)
{
  int def;
  DFlanternShrineState *state;
  u8 *player;
  f32 trigA;
  f32 trigB;
  f32 distance;
  int angleDelta;
  int turnStep;
  undefined animEvents[32];

  def = *(int *)&((GameObject *)obj)->anim.placementData;
  state = ((GameObject *)obj)->extra;
  player = Obj_GetPlayerObject();
  if ((((GameObject *)obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) {
    *(s16 *)obj = 0;
    ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)def)->posY;
    return;
  }

  state->orbitA += (s32)(lbl_803E4E50 * timeDelta);
  state->orbitB += (s32)(lbl_803E4E54 * timeDelta);
  state->orbitC += (s32)(lbl_803E4E58 * timeDelta);

  ((GameObject *)obj)->anim.localPosY =
      lbl_803E4E5C +
      (((ObjPlacement *)def)->posY +
       mathSinf((lbl_803E4E60 * (f32)state->orbitA) / lbl_803E4E64));

  trigA = mathSinf((lbl_803E4E60 * (f32)state->orbitB) / lbl_803E4E64);
  trigB = mathSinf((lbl_803E4E60 * (f32)state->orbitA) / lbl_803E4E64);
  trigB = trigB + trigA;
  ((GameObject *)obj)->anim.rotZ = lbl_803E4E68 * trigB;

  trigA = mathSinf((lbl_803E4E60 * (f32)state->orbitC) / lbl_803E4E64);
  trigB = mathSinf((lbl_803E4E60 * (f32)state->orbitA) / lbl_803E4E64);
  trigB = trigB + trigA;
  ((GameObject *)obj)->anim.rotY = lbl_803E4E68 * trigB;

  ObjAnim_AdvanceCurrentMove(lbl_803E4E6C,timeDelta,obj,(ObjAnimEventList *)animEvents);
  if (player != NULL) {
    angleDelta =
        ((u16)getAngle(((GameObject *)obj)->anim.worldPosX - *(f32 *)(player + 0x18),
                       ((GameObject *)obj)->anim.worldPosZ - *(f32 *)(player + 0x20)) -
         ((u16)*(s16 *)obj));
    if (angleDelta > 0x8000) {
      angleDelta -= 0xffff;
    }
    if (angleDelta < -0x8000) {
      angleDelta += 0xffff;
    }
    turnStep = (s32)(((f32)angleDelta * timeDelta) / lbl_803E4E70);
    *(s16 *)obj += (s16)turnStep;

    distance = Vec_xzDistance((void *)(obj + 0x18),player + 0x18);
    if (distance <= lbl_803E4E74) {
      ((GameObject *)obj)->anim.alpha = (u8)(s32)(lbl_803E4E78 * (distance / lbl_803E4E74));
    }
    else {
      ((GameObject *)obj)->anim.alpha = 0xff;
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfsh_shrine_SeqFn
 * EN v1.0 Address: 0x801C2C68
 * EN v1.0 Size: 348b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct LanternFlagBits {
    u8 on : 1;
    u8 rest : 7;
} LanternFlagBits;

#pragma scheduling off
#pragma peephole off
int dfsh_shrine_SeqFn(int obj,int unused,void *seq)
{
  int objLocal;
  u8 *seqBytes;
  DFlanternShrineState *state;
  u8 *player;
  int i;
  int cmdOffset;
  u8 cmd;

  objLocal = obj;
  seqBytes = seq;
  state = *(DFlanternShrineState **)(objLocal + 0xb8);
  player = Obj_GetPlayerObject();
  seqBytes[0x56] = 0;
  for (i = 0; i < seqBytes[0x8b]; i++) {
    cmdOffset = i + 0x81;
    cmd = seqBytes[cmdOffset];
    if (cmd != 0) {
      switch (cmd) {
      case 3:
        ((LanternFlagBits *)&state->flags)->on = 1;
        break;
      case 7:
        fn_80296518(player,1,1);
        GameBit_Set(0xbfd,1);
        GameBit_Set(0x956,1);
        (*gMapEventInterface)->setMode(0xb,2);
        break;
      case 0xe:
        *(s16 *)(objLocal + 6) = (s16)(*(s16 *)(objLocal + 6) | 0x4000);
        if (state->light != NULL) {
          modelLightStruct_setEnabled((int)state->light,0,lbl_803E4E88);
        }
        break;
      case 0xf:
        *(s16 *)(objLocal + 6) = (s16)(*(s16 *)(objLocal + 6) & ~0x4000);
        if (state->light != NULL) {
          modelLightStruct_setEnabled((int)state->light,0,lbl_803E4E88);
        }
        break;
      }
    }
    seqBytes[cmdOffset] = 0;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfsh_shrine_getExtraSize
 * EN v1.0 Address: 0x801C2DC4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfsh_shrine_getExtraSize(void)
{
  return 0x20;
}

/*
 * --INFO--
 *
 * Function: dfsh_shrine_getObjectTypeId
 * EN v1.0 Address: 0x801C2DCC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfsh_shrine_getObjectTypeId(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: dfsh_shrine_free
 * EN v1.0 Address: 0x801C2DD4
 * EN v1.0 Size: 148b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dfsh_shrine_free(int obj)
{
  void **state;

  state = ((GameObject *)obj)->extra;
  if (*state != NULL) {
    ModelLightStruct_free(*state);
    *state = NULL;
  }
  gameTimerStop();
  unlockLevel(mapGetDirIdx(0x1f),1,0);
  Music_Trigger(0xd8,0);
  Music_Trigger(0xd9,0);
  Music_Trigger(8,0);
  GameBit_Set(0xefa,0);
  GameBit_Set(0xcbb,1);
}
#pragma peephole reset
#pragma scheduling reset
