#include "ghidra_import.h"
#include "main/dll/sfxplayer.h"

extern void Obj_FreeObject(int obj);
extern int ObjHits_GetPriorityHit(int obj,undefined4 *outHitObject,int *outSphereIndex,uint *outHitVolume);
extern void Sfx_PlayFromObject(int obj,int sfxId);
extern void GameBit_Set(int eventId,int value);
extern void gameTimerStop(void);
extern void gameTimerInit(int timerId,int frames);
extern u32 GameBit_Get(int eventId);
extern int fn_80014670(void);
extern void fn_8001469C(void);
extern void TrickyCurve_activateEffectHandleRing(void);
extern void TrickyCurve_updateEffectHandleRing(int obj);

extern undefined4* lbl_803DCAAC;

typedef struct SfxplayerStateFlags {
  u8 bit80 : 1;
  u8 bit40 : 1;
  u8 bit20 : 1;
  u8 bit10 : 1;
  u8 lowBits : 4;
} SfxplayerStateFlags;

/*
 * --INFO--
 *
 * Function: sfxplayer_update
 * EN v1.0 Address: 0x80207CE4
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x80207F80
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sfxplayer_update(int obj)
{
  int i;
  int mode;
  int state;
  int *handles;
  SfxplayerStateFlags *flags;
  undefined4 hitObj;
  
  state = *(int *)(obj + 0xb8);
  flags = (SfxplayerStateFlags *)(state + 8);
  if ((flags->bit20 == 0) && (GameBit_Get(*(s16 *)state) == 0)) {
    if (*(u8 *)(state + 7) == 4) {
      Sfx_PlayFromObject(0,0x7e);
      flags->bit20 = 1;
      flags->bit10 = 0;
      flags->bit40 = 0;
      GameBit_Set(*(s16 *)state,1);
      GameBit_Set(0xedf,0);
      mode = (*(code *)(*lbl_803DCAAC + 0x40))((int)*(char *)(obj + 0xac));
      if ((u8)mode == 1) {
        GameBit_Set(0x9f7,1);
      }
      gameTimerStop();
    }
    else {
      if (flags->bit80 != 0) {
        flags->bit80 = 0;
        if (flags->bit10 != 0) {
          mode = (*(code *)(*lbl_803DCAAC + 0x40))((int)*(char *)(obj + 0xac));
          if ((u8)mode == 1) {
            gameTimerInit(0x1d,0x96);
          }
          else {
            gameTimerInit(0x1d,0xb4);
          }
          fn_8001469C();
        }
      }
      if (fn_80014670() != 0) {
        handles = gSfxplayerEffectHandles;
        for (i = 0; i < 4; i++) {
          if (handles[0] != 0) {
            Obj_FreeObject(handles[0]);
          }
          handles[0] = 0;
          if (handles[1] != 0) {
            Obj_FreeObject(handles[1]);
          }
          handles[1] = 0;
          Sfx_PlayFromObject(obj,0x1ce);
          handles += 2;
        }
        *(u8 *)(state + 7) = 0;
        flags->bit40 = 0;
        flags->bit10 = 0;
        GameBit_Set(0xedf,0);
      }
      TrickyCurve_updateEffectHandleRing(obj);
      handles = gSfxplayerEffectHandles;
      for (i = 0; i < 4; i++) {
        if (handles[0] != 0) {
          hitObj = 0;
          if ((ObjHits_GetPriorityHit(handles[1],&hitObj,(int *)0x0,(uint *)0x0) == 0x13) &&
             (mode = (*(code *)(*lbl_803DCAAC + 0x40))((int)*(char *)(obj + 0xac)),
              ((u8)mode == 1 || (*(int *)((int)hitObj + 0xf4) == i)))) {
            if (handles[0] != 0) {
              Obj_FreeObject(handles[0]);
            }
            handles[0] = 0;
            if (handles[1] != 0) {
              Obj_FreeObject(handles[1]);
            }
            handles[1] = 0;
            Sfx_PlayFromObject(0,0x409);
            *(u8 *)(state + 7) = *(u8 *)(state + 7) + 1;
          }
        }
        handles += 2;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: sfxplayer_init
 * EN v1.0 Address: 0x80207FBC
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x8020816C
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void sfxplayer_init(int obj,int config)
{
  int state;

  state = *(int *)(obj + 0xb8);
  *(s16 *)obj = (s16)((s8)*(u8 *)(config + 0x18) << 8);
  *(void (**)(void))(obj + 0xbc) = TrickyCurve_activateEffectHandleRing;
  *(u8 *)(state + 6) = *(u8 *)(config + 0x19);
  *(s16 *)state = *(s16 *)(config + 0x1e);
  *(s16 *)(state + 2) = *(s16 *)(config + 0x20);
  *(s16 *)(state + 4) = 1;
  gSfxplayerEffectHandles[0] = 0;
  gSfxplayerEffectHandles[1] = 0;
  gSfxplayerEffectHandles[2] = 0;
  gSfxplayerEffectHandles[3] = 0;
  gSfxplayerEffectHandles[4] = 0;
  gSfxplayerEffectHandles[5] = 0;
  gSfxplayerEffectHandles[6] = 0;
  gSfxplayerEffectHandles[7] = 0;
  gameTimerStop();
  if (GameBit_Get(*(s16 *)state) != 0) {
    SfxplayerStateFlags *flags = (void *)(state + 8);
    flags->bit20 = 1;
  }
  *(u16 *)(obj + 0xb0) = *(u16 *)(obj + 0xb0) | 0x6000;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: sfxplayer_release
 * EN v1.0 Address: 0x80208090
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80208240
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sfxplayer_release(void)
{
}

/*
 * --INFO--
 *
 * Function: sfxplayer_initialise
 * EN v1.0 Address: 0x80208094
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80208244
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sfxplayer_initialise(void)
{
}
