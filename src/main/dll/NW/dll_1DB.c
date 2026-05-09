#include "ghidra_import.h"
#include "main/dll/NW/dll_1DB.h"

extern f32 lbl_803E52A8;

extern u8 *Obj_GetPlayerObject(void);
extern u8 *fn_8002B9AC(void);
extern int fn_8002B044(u8 *self);
extern void ObjHits_DisableObject(u8 *obj);
extern void gameBitIncrement(s16 bit);
extern void GameBit_Set(int bit, int value);
extern void itemPickupDoParticleFx(u8 *obj, int a, int b, f32 f1);
extern void Sfx_PlayFromObject(u8 *obj, int sfxId);
extern int ObjMsg_Pop(u8 *obj, int *outMsg, int a, int b);
extern f32 fn_800216D0(f32 *a, f32 *b);
extern void Obj_StartModelFadeIn(u8 *obj, int frames);
extern void Obj_SetModelColorFadeRecursive(u8 *obj, int a, int b, int c, int d, int e);
extern int ObjHits_GetPriorityHit(u8 *obj, int *outOther, int a, int b);
extern void fn_801D083C(u8 *self, u8 *state, u8 *other);
extern f32 sqrtf(f32 x);

#pragma peephole off
#pragma scheduling off

/*
 * --INFO--
 *
 * Function: ediblemushroom_update
 * EN v1.0 Address: 0x801D16EC
 * EN v1.0 Size: 652b
 */
void ediblemushroom_update(u8 *self)
{
  u8 *state;
  u8 *other;
  u8 *player;
  u8 *enemy;
  int hitObj;
  int msg;
  int hitKind;
  f32 distState;
  f32 distEnemy;

  state = (u8 *)*(int *)(self + 0xB8);
  other = (u8 *)*(int *)(self + 0x4C);
  player = Obj_GetPlayerObject();
  enemy = fn_8002B9AC();

  if (fn_8002B044(self) != 0) goto end;

  if (state[0x136] == 8) {
    while (ObjMsg_Pop(self, &msg, 0, 0) != 0) {
      if (((u32)msg - 0x70000) != 0xB) continue;
      *(s16 *)(self + 6) = (s16)(*(s16 *)(self + 6) | 0x4000);
      ObjHits_DisableObject(self);
      gameBitIncrement(*(s16 *)(state + 0x134));
      GameBit_Set(0x12E, 0);
      if (*(s16 *)(self + 0x46) == 0x658) {
        itemPickupDoParticleFx(self, 0xFF, 0x28, lbl_803E52A8);
      } else {
        itemPickupDoParticleFx(self, 6, 0x28, lbl_803E52A8);
      }
      Sfx_PlayFromObject(self, 0x58);
    }
    goto end;
  }

  if (state[0x139] != 0) {
    *(f32 *)(self + 0xC) = *(f32 *)(other + 0x8);
    *(f32 *)(self + 0x10) = *(f32 *)(other + 0xC);
    *(f32 *)(self + 0x14) = *(f32 *)(other + 0x10);
    self[0x36] = 0xFF;
    state[0x139] = 0;
  }

  *(f32 *)(state + 0x10C) = *(f32 *)(state + 0x108);
  distState = fn_800216D0((f32 *)(player + 0x18), (f32 *)(self + 0x18));
  if (enemy == NULL) {
    *(f32 *)(state + 0x108) = sqrtf(distState);
  } else {
    distEnemy = fn_800216D0((f32 *)(enemy + 0x18), (f32 *)(self + 0x18));
    if (distState < distEnemy) {
      *(f32 *)(state + 0x108) = sqrtf(distState);
    } else {
      *(f32 *)(state + 0x108) = sqrtf(distEnemy);
    }
    if (*(f32 *)(state + 0x108) < (f32)(u32)other[0x1F]) {
      (*(void (**)(u8 *, u8 *, int, int))(*(int *)*(int *)(enemy + 0x68) + 0x28))
          (enemy, self, 0, 1);
    }
  }

  hitKind = ObjHits_GetPriorityHit(self, &hitObj, 0, 0);
  if (hitKind != 0) {
    if (hitKind == 0x10) {
      Obj_StartModelFadeIn(self, 0x12C);
    } else {
      Obj_SetModelColorFadeRecursive(self, 0xF, 0xC8, 0, 0, 1);
      if (*(s16 *)((u8 *)hitObj + 0x46) != 0x416) {
        if ((state[0x137] & 0x10) == 0) {
          Sfx_PlayFromObject(self, 0x9D);
        }
        state[0x137] = (u8)(state[0x137] | 0x10);
      }
    }
  }
  fn_801D083C(self, state, other);

end:
  ;
}

#pragma peephole reset
#pragma scheduling reset
