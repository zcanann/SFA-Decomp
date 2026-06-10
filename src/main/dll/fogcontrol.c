#include "main/dll/fogcontrol.h"
#include "main/game_object.h"
#include "main/dll/path_control_interface.h"


extern void OSReport(const char *msg, ...);
extern uint FUN_80006ba0();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8003b818();
extern void objMove(int obj, f32 dx, f32 dy, f32 dz);
extern void fn_8002A5DC(int obj);
extern void PSVECSubtract(f32 *a, f32 *b, f32 *out);
extern void PSVECNormalize(f32 *src, f32 *dst);
extern void PSVECScale(f32 *src, f32 *dst, f32 scale);
extern f32 sqrtf(f32 x);
extern void Sfx_PlayFromObject(int obj,u16 sfxId);
extern void fn_80137948(const char *fmt, ...);
extern undefined4 sidekickball_update();
extern undefined4 sidekickball_init();
extern uint countLeadingZeros();

extern f32 timeDelta;
extern f32 lbl_803DC074;
extern f32 lbl_803E369C;
extern f32 lbl_803E36A0;
extern f32 lbl_803E36B0;
extern f32 lbl_803E36B4;
extern f32 lbl_803E36B8;
extern f32 lbl_803E36BC;
extern f32 lbl_803E36C0;
extern f32 lbl_803E36C4;
extern f32 lbl_803E36C8;
extern f32 lbl_803E36CC;
extern f32 lbl_803E36D0;
extern f32 lbl_803E36D4;
extern f32 lbl_803E4334;
extern f32 lbl_803E433C;
extern f32 lbl_803E4340;
extern f32 lbl_803E4344;
extern char sSidekickBallYVelDepthFormat[];
extern char sSidekickBallDotFormat[];

typedef struct TrickyBallState {
  u8 pad00[0x68];
  f32 collisionNormal[3];
  u8 pad74[0x1B4 - 0x74];
  f32 floorHeight;
  u8 pad1B8[0x1BC - 0x1B8];
  f32 floorBaseY;
  u8 pad1C0[0x261 - 0x1C0];
  s8 hasCollisionNormal;
  u8 pad262[0x2B0 - 0x262];
  f32 prevPos[3];
  u8 pad2BC[0x2C0 - 0x2BC];
  f32 floorY;
  f32 floorDepth;
} TrickyBallState;

/*
 * --INFO--
 *
 * Function: trickyBallMove
 * EN v1.0 Address: 0x80179A2C
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x80179B84
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u8 trickyBallMove(u8 *obj)
{
  TrickyBallState *state;
  f32 collisionNormal[3];
  f32 dx;
  f32 dy;
  f32 dz;
  f32 speed;
  f32 invSpeed;
  f32 reflectedX;
  f32 reflectedY;
  f32 reflectedZ;
  f32 dot;
  int hasCollisionNormal;
  int movedFromCache;
  int hasFloorDepth;

  state = ((GameObject *)obj)->extra;
  hasCollisionNormal = 0;
  movedFromCache = 0;
  speed = lbl_803E36B0;

  ObjHits_EnableObject(obj);

  dy = state->prevPos[1] - ((GameObject *)obj)->anim.localPosY;
  if (dy < lbl_803E369C) {
    dy = -dy;
  }
  dx = state->prevPos[0] - ((GameObject *)obj)->anim.localPosX;
  if (dx < lbl_803E369C) {
    dx = -dx;
  }
  dz = state->prevPos[2] - ((GameObject *)obj)->anim.localPosZ;
  if (dz < lbl_803E369C) {
    dz = -dz;
  }

  if ((dx + dy + dz) >= lbl_803E36B4) {
    PSVECSubtract((f32 *)(obj + 0x0c), state->prevPos, collisionNormal);
    speed = lbl_803E36B0;
    hasCollisionNormal = 1;
    movedFromCache = 1;
  }

  if (state->floorHeight > lbl_803E369C) {
    state->floorY = state->floorBaseY;
    state->floorDepth = state->floorHeight;
    hasFloorDepth = 1;
  } else if (state->floorY != lbl_803E369C) {
    if (((GameObject *)obj)->anim.localPosY > state->floorY) {
      state->floorY = lbl_803E369C;
      hasFloorDepth = 0;
    } else {
      state->floorDepth = state->floorY - ((GameObject *)obj)->anim.localPosY;
      hasFloorDepth = 1;
    }
  } else {
    hasFloorDepth = 0;
  }

  if (hasFloorDepth != 0) {
    ((GameObject *)obj)->anim.velocityX *= lbl_803E36B8;
    ((GameObject *)obj)->anim.velocityY *= lbl_803E36B8;
    ((GameObject *)obj)->anim.velocityZ *= lbl_803E36B8;
    ((GameObject *)obj)->anim.velocityY += lbl_803E36BC * timeDelta;
    OSReport(sSidekickBallYVelDepthFormat, ((GameObject *)obj)->anim.velocityY, state->floorDepth);
    if ((((GameObject *)obj)->anim.velocityY < lbl_803E36C0) &&
        (((GameObject *)obj)->anim.velocityY > lbl_803E36C4) &&
        (state->floorDepth < lbl_803E36A0)) {
      return 1;
    }
  } else if (hasCollisionNormal == 0) {
    ((GameObject *)obj)->anim.velocityY -= lbl_803E36C8 * timeDelta;
  }

  objMove((int)obj, ((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityY * timeDelta,
          ((GameObject *)obj)->anim.velocityZ * timeDelta);
  (*gPathControlInterface)->update(obj, state, timeDelta);
  (*gPathControlInterface)->apply(obj, state);
  (*gPathControlInterface)->advance(obj, state, timeDelta);

  if (state->hasCollisionNormal != 0) {
    hasCollisionNormal = 1;
    collisionNormal[0] = state->collisionNormal[0];
    collisionNormal[1] = state->collisionNormal[1];
    collisionNormal[2] = state->collisionNormal[2];
  }

  if (hasCollisionNormal != 0) {
    PSVECNormalize(collisionNormal, collisionNormal);
    reflectedX = -((GameObject *)obj)->anim.velocityX;
    reflectedY = -((GameObject *)obj)->anim.velocityY;
    reflectedZ = -((GameObject *)obj)->anim.velocityZ;
    speed = sqrtf(reflectedX * reflectedX + reflectedY * reflectedY + reflectedZ * reflectedZ);
    if (speed > lbl_803E36CC) {
      Sfx_PlayFromObject((int)obj, 0x16c);
    }
    if (speed != lbl_803E369C) {
      invSpeed = lbl_803E36A0 / speed;
      reflectedX *= invSpeed;
      reflectedY *= invSpeed;
      reflectedZ *= invSpeed;
    }
    dot = lbl_803E36D0 *
          ((reflectedX * collisionNormal[0]) + (reflectedY * collisionNormal[1]) +
           (reflectedZ * collisionNormal[2]));
    fn_80137948(sSidekickBallDotFormat, dot);
    if (dot > lbl_803E369C) {
      ((GameObject *)obj)->anim.velocityX = (collisionNormal[0] * dot) - reflectedX;
      ((GameObject *)obj)->anim.velocityY = (collisionNormal[1] * dot) - reflectedY;
      ((GameObject *)obj)->anim.velocityZ = (collisionNormal[2] * dot) - reflectedZ;
      if ((state->floorY == lbl_803E369C) && (speed < lbl_803E36D4) &&
          (state->hasCollisionNormal != 0)) {
        return 2;
      }
      PSVECScale((f32 *)(obj + 0x24), (f32 *)(obj + 0x24), speed * lbl_803E36B0);
    }
  }

  if (movedFromCache != 0) {
    ((GameObject *)obj)->anim.velocityY -= lbl_803E36C8 * timeDelta;
  }

  fn_8002A5DC((int)obj);
  state->prevPos[0] = ((GameObject *)obj)->anim.localPosX;
  state->prevPos[1] = ((GameObject *)obj)->anim.localPosY;
  state->prevPos[2] = ((GameObject *)obj)->anim.localPosZ;
  return 3;
}

