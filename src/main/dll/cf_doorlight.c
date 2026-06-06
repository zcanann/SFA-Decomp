#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/dll/cf_doorlight_state.h"
#include "main/dll/cf_doorlight.h"
#include "main/dll/wallanimator.h"
#include "main/objanim.h"


extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_DisableObject();

extern void** gPlayerInterface;
extern void GameBit_Set(int bit, int value);

extern f32 timeDelta;
extern f32 lbl_803E3060;
extern int *gBaddieControlInterface;

#pragma scheduling off
#pragma peephole off
int kaldachom_stateHandlerB05(int obj, int p)
{
  int state;
  KaldaChomControl *control;
  int def;

  state = *(int *)&((GameObject *)obj)->extra;
  control = ((CfDoorlightState *)state)->control;
  if (((GroundBaddieState *)p)->baddie.controlMode == 2) {
    control->pullupSfxTimer = control->pullupSfxTimer - timeDelta;
    if (control->pullupSfxTimer <= lbl_803E3060) {
      ((GroundBaddieState *)p)->baddie.moveDone = 1;
    }
  }
  if ((s8)((GroundBaddieState *)p)->baddie.moveDone != 0 || (s8)((GroundBaddieState *)p)->baddie.moveJustStartedB != 0) {
    if (((int (*)(int, int, f32, int))((void **)*(int *)gBaddieControlInterface)[0x11])
            (obj, p, (f32)(u32)((CfDoorlightState *)state)->aggroRange, 1) != 0) {
      return 5;
    }
    def = *(int *)&((GameObject *)obj)->anim.placementData;
    if ((int)randomGetRange(0, 0x63) < (int)*(u8 *)(def + 0x2f)) {
      ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, p, 3);
    } else {
      control->pullupSfxTimer = (f32)(int)randomGetRange(0x12c, 0x258);
      ((void (*)(int, int, int))((void **)*gPlayerInterface)[5])(obj, p, 2);
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int kaldachom_stateHandlerB04(int obj, u8 *state)
{
    if ((s8)state[0x27b] != 0) {
        ((void (*)(int, u8 *, int))((void **)*gPlayerInterface)[5])(obj, state, 1);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int kaldachom_stateHandlerB03(int obj, u8 *state)
{
    if ((s8)state[0x27b] != 0) {
        u8 *extra = ((GameObject *)obj)->extra;
        extra[0x405] = 0;
        GameBit_Set(((CfDoorlightState *)extra)->gameBitB, 0);
        GameBit_Set(((CfDoorlightState *)extra)->gameBitA, 1);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int kaldachom_stateHandlerA07(int obj, int p)
{
  extern int *gBaddieControlInterface;
  extern f32 lbl_803E3060;
  extern f32 lbl_803E3078;
  extern f32 lbl_803E3084;
  extern f32 lbl_803E3088;
  extern f32 lbl_803E308C;
  int b8;
  KaldaChomControl *control;

  b8 = *(int *)&((GameObject *)obj)->extra;
  *(s8 *)(p + 0x34d) = 3;
  ((GroundBaddieState *)p)->baddie.moveSpeed = lbl_803E3084;
  {
    f32 fz = lbl_803E3060;
    ((GroundBaddieState *)p)->baddie.animSpeedA = fz;
    ((GroundBaddieState *)p)->baddie.animSpeedB = fz;
    if (*(char *)(p + 0x27a) != '\0') {
      ObjAnim_SetCurrentMove(obj, 5, fz, 0);
      *(s8 *)(p + 0x346) = 0;
    }
  }
  {
    int v = *(int *)(p + 0x314);
    if ((v & 0x1000) != 0) {
      *(int *)(p + 0x314) = v & ~0x1000;
      kaldachompme_setLinkedMouthMode((u8 *)obj, 2);
    }
  }
  control = ((CfDoorlightState *)b8)->control;
  if ((control->soundFlags & 0x1) == 0) {
    Sfx_PlayFromObject(obj, SFXkr_climb2);
    Sfx_PlayFromObject(obj, SFXsc_attack01);
    Sfx_PlayFromObject(obj, SFXdoor_unlocked);
    control->soundFlags |= 0x1;
    {
      char *r;
      if (((CfDoorlightState *)b8)->unk3F0 != 0) {
        r = ((char *(*)(int, int, int, int))((void **)*gBaddieControlInterface)[0x13])(obj, 6, -1, 0);
      } else {
        r = NULL;
      }
      if (r != NULL) {
        f32 fz = lbl_803E3060;
        (**(void (**)(char *, f32, f32, f32))(*(int *)(*(int *)(r + 0x68)) + 0x2c))(r, fz, lbl_803E3078, fz);
      }
    }
  }
  if ((control->soundFlags & 0x2) == 0) {
    if (((GameObject *)obj)->anim.currentMoveProgress > lbl_803E3088) {
      Sfx_PlayFromObject(obj, SFXdoor_creak);
      control->soundFlags |= 0x2;
    }
  }
  *(u8 *)(obj + 0x36) = (s32)((lbl_803E3078 - ((GameObject *)obj)->anim.currentMoveProgress) * lbl_803E308C);
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E3080;

#pragma scheduling off
#pragma peephole off
int kaldachom_stateHandlerB01(int* obj, u8* state) {
    KaldaChomControl *control = ((CfDoorlightState *)((GameObject *)obj)->extra)->control;
    if (*(s16*)((char*)state + 628) == 6) {
        f32 zero;
        f32 timer;
        if ((s8)state[635] != 0) {
            control->returnStateTimer = lbl_803E3080;
        }
        timer = control->returnStateTimer;
        zero = lbl_803E3060;
        if (timer != zero) {
            control->returnStateTimer = timer - timeDelta;
            if (control->returnStateTimer < zero) {
                control->returnStateTimer = zero;
            }
        } else {
            return 6;
        }
    } else {
        if ((s8)state[838] != 0) return 6;
    }
    return 0;
}

int kaldachom_stateHandlerB00(int* obj, u8* state) {
    if (*(void**)((char*)state + 0x2d0) != NULL) {
        if ((s8)state[635] != 0) {
            f32 fz = lbl_803E3060;
            *(f32*)((char*)state + 0x284) = fz;
            *(f32*)((char*)state + 0x280) = fz;
            ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, state, 0);
        } else if ((s8)state[838] != 0) {
            return 6;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int kaldachom_stateHandlerB02(int obj, int p2)
{
  extern void ObjHits_DisableObject(int);
  extern void Obj_FreeObject(int);
  extern f32 lbl_803E3078;
  extern f32 lbl_803E307C;
  int sub = *(int *)&((GameObject *)obj)->extra;

  if ((s32)(s8)*(u8 *)(p2 + 0x27b) != 0) {
    ((CfDoorlightState *)sub)->control->soundFlags = 0;
    (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, 7);
    ObjHits_DisableObject(obj);
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x8);
    ((CfDoorlightState *)sub)->flags400 = (u16)(((CfDoorlightState *)sub)->flags400 | 0x20);
    ((CfDoorlightState *)sub)->unk3E8 = lbl_803E3078;
    ((CfDoorlightState *)sub)->unk3EC = lbl_803E307C;
  } else if ((s32)(s8)*(u8 *)(p2 + 0x346) != 0) {
    if (((GameObject *)obj)->anim.placementData == NULL) {
      Obj_FreeObject(obj);
      return 0;
    }
    return 4;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset
