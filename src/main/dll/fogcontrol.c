#include "ghidra_import.h"
#include "main/dll/fogcontrol.h"


#pragma peephole off
#pragma scheduling off
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

extern undefined4* DAT_803dd728;
extern void *gPathControlInterface;
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

  state = *(TrickyBallState **)(obj + 0xb8);
  hasCollisionNormal = 0;
  movedFromCache = 0;
  speed = lbl_803E36B0;

  ObjHits_EnableObject(obj);

  dy = state->prevPos[1] - *(f32 *)(obj + 0x10);
  if (dy < lbl_803E369C) {
    dy = -dy;
  }
  dx = state->prevPos[0] - *(f32 *)(obj + 0x0c);
  if (dx < lbl_803E369C) {
    dx = -dx;
  }
  dz = state->prevPos[2] - *(f32 *)(obj + 0x14);
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
    if (*(f32 *)(obj + 0x10) > state->floorY) {
      state->floorY = lbl_803E369C;
      hasFloorDepth = 0;
    } else {
      state->floorDepth = state->floorY - *(f32 *)(obj + 0x10);
      hasFloorDepth = 1;
    }
  } else {
    hasFloorDepth = 0;
  }

  if (hasFloorDepth != 0) {
    *(f32 *)(obj + 0x24) *= lbl_803E36B8;
    *(f32 *)(obj + 0x28) *= lbl_803E36B8;
    *(f32 *)(obj + 0x2c) *= lbl_803E36B8;
    *(f32 *)(obj + 0x28) += lbl_803E36BC * timeDelta;
    OSReport(sSidekickBallYVelDepthFormat, *(f32 *)(obj + 0x28), state->floorDepth);
    if ((*(f32 *)(obj + 0x28) < lbl_803E36C0) &&
        (*(f32 *)(obj + 0x28) > lbl_803E36C4) &&
        (state->floorDepth < lbl_803E36A0)) {
      return 1;
    }
  } else if (hasCollisionNormal == 0) {
    *(f32 *)(obj + 0x28) -= lbl_803E36C8 * timeDelta;
  }

  objMove((int)obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
          *(f32 *)(obj + 0x2c) * timeDelta);
  (*(void (**)(u8 *,TrickyBallState *,f32))(*(int *)gPathControlInterface + 0x10))(obj, state,
                                                                                  timeDelta);
  (*(void (**)(u8 *,TrickyBallState *))(*(int *)gPathControlInterface + 0x14))(obj, state);
  (*(void (**)(u8 *,TrickyBallState *,f32))(*(int *)gPathControlInterface + 0x18))(obj, state,
                                                                                  timeDelta);

  if (state->hasCollisionNormal != 0) {
    hasCollisionNormal = 1;
    collisionNormal[0] = state->collisionNormal[0];
    collisionNormal[1] = state->collisionNormal[1];
    collisionNormal[2] = state->collisionNormal[2];
  }

  if (hasCollisionNormal != 0) {
    PSVECNormalize(collisionNormal, collisionNormal);
    reflectedX = -*(f32 *)(obj + 0x24);
    reflectedY = -*(f32 *)(obj + 0x28);
    reflectedZ = -*(f32 *)(obj + 0x2c);
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
      *(f32 *)(obj + 0x24) = (collisionNormal[0] * dot) - reflectedX;
      *(f32 *)(obj + 0x28) = (collisionNormal[1] * dot) - reflectedY;
      *(f32 *)(obj + 0x2c) = (collisionNormal[2] * dot) - reflectedZ;
      if ((state->floorY == lbl_803E369C) && (speed < lbl_803E36D4) &&
          (state->hasCollisionNormal != 0)) {
        return 2;
      }
      PSVECScale((f32 *)(obj + 0x24), (f32 *)(obj + 0x24), speed * lbl_803E36B0);
    }
  }

  if (movedFromCache != 0) {
    *(f32 *)(obj + 0x28) -= lbl_803E36C8 * timeDelta;
  }

  fn_8002A5DC((int)obj);
  state->prevPos[0] = *(f32 *)(obj + 0x0c);
  state->prevPos[1] = *(f32 *)(obj + 0x10);
  state->prevPos[2] = *(f32 *)(obj + 0x14);
  return 3;
}

/*
 * --INFO--
 *
 * Function: FUN_80179ad4
 * EN v1.0 Address: 0x80179AD4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80179C24
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80179ad4(void)
{
  GameBit_Set(0x3f8,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80179afc
 * EN v1.0 Address: 0x80179AFC
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80179C4C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80179afc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 renderState)
{
  if ((*(int *)(param_1 + 0xf8) == 0) || (renderState == -1)) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80179b34
 * EN v1.0 Address: 0x80179B34
 * EN v1.0 Size: 984b
 * EN v1.1 Address: 0x80179C88
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80179b34(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9,
                 undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  char cVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined uVar7;
  int iVar8;
  double dVar9;
  double dVar10;
  
  iVar8 = *(int *)(param_9 + 0x5c);
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
  *(undefined *)(iVar8 + 0x275) = 0;
  iVar4 = FUN_80017a98();
  iVar5 = FUN_80017a90();
  if ((((iVar4 == 0) || ((*(ushort *)(iVar4 + 0xb0) & 0x1000) != 0)) || (iVar5 == 0)) ||
     ((uVar3 = countLeadingZeros((uint)*(ushort *)(iVar5 + 0xb0)), (uVar3 >> 5 & 0x1000) != 0 ||
      (uVar3 = GameBit_Get(0xd00), uVar3 != 0)))) {
    FUN_80017ac8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    return;
  }
  cVar1 = *(char *)(iVar8 + 0x274);
  if (((cVar1 == '\x03') || (cVar1 == '\x02')) || (cVar1 == '\x01')) {
    *(float *)(iVar8 + 0x26c) = *(float *)(iVar8 + 0x26c) + lbl_803DC074;
    param_1 = (double)*(float *)(iVar8 + 0x26c);
    if ((double)lbl_803E4340 <= param_1) {
      *(float *)(iVar8 + 0x26c) = lbl_803E4334;
      *(undefined *)(iVar8 + 0x274) = 5;
    }
  }
  bVar2 = *(byte *)(iVar8 + 0x274);
  if (bVar2 == 3) {
    uVar6 = sidekickball_init(param_9);
    *(char *)(iVar8 + 0x274) = (char)uVar6;
    return;
  }
  if (bVar2 < 3) {
    if (bVar2 == 1) {
      sidekickball_init(param_9);
    }
    else if (bVar2 == 0) {
      sidekickball_update(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                   iVar8,param_11,param_12,param_13,param_14,param_15,param_16);
      goto LAB_80179e98;
    }
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    uVar7 = 0;
    uVar3 = FUN_80006ba0(0);
    if ((((uVar3 & 0x100) == 0) && (*(int *)(param_9 + 0x7c) == 0)) &&
       (iVar4 = ObjTrigger_IsSet((int)param_9), iVar4 != 0)) {
      ObjHits_DisableObject((int)param_9);
      uVar7 = 1;
    }
    *(undefined *)(iVar8 + 0x2c9) = uVar7;
    if (*(char *)(iVar8 + 0x2c9) != '\0') {
      *(undefined *)(iVar8 + 0x2c8) = 0;
      *(undefined *)(iVar8 + 0x2c9) = 0;
      *(undefined *)(iVar8 + 0x274) = 0;
    }
  }
  else if (bVar2 == 5) {
    *(float *)(iVar8 + 0x26c) = *(float *)(iVar8 + 0x26c) + lbl_803DC074;
    dVar10 = (double)*(float *)(iVar8 + 0x26c);
    dVar9 = (double)lbl_803E433C;
    if (dVar9 <= dVar10) {
      FUN_80017ac8(dVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      return;
    }
    *(char *)(param_9 + 0x1b) =
         -1 - (char)(int)((double)(float)((double)lbl_803E4344 * dVar10) / dVar9);
  }
LAB_80179e98:
  if (*(char *)(*(int *)(param_9 + 0x5c) + 0x25b) == '\x01') {
    (**(code **)(*DAT_803dd728 + 0x10))((double)lbl_803DC074,param_9,iVar8);
    (**(code **)(*DAT_803dd728 + 0x14))(param_9,iVar8);
    (**(code **)(*DAT_803dd728 + 0x18))((double)lbl_803DC074,param_9,iVar8);
  }
  else {
    (**(code **)(*DAT_803dd728 + 0x20))(param_9);
  }
  return;
}
