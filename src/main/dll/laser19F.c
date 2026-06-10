#include "main/dll/laser19F.h"
#include "main/game_object.h"
#include "main/dll/SC/SCtotemlogpuz.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"


extern undefined8 FUN_80006b14();
extern char FUN_80006bd0();
extern undefined4 FUN_800175cc();
extern void modelLightStruct_setEnabled(int p1, int p2, f32 f);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017710();
extern uint FUN_80017730();
extern int FUN_80017a98();
extern void fn_8011F6D4(int p);
extern int fn_801C49B8(int obj);
extern int Obj_GetPlayerObject(void);
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjMsg_AllocQueue();
extern int FUN_8005398c();
extern undefined4 FUN_8011eb10();
extern undefined4 FUN_8011eb1c();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294ccc();
extern void fn_80296518(int obj, int arg, int enable);

extern void* DAT_803de838;
extern MapEventInterface **gMapEventInterface;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern f64 DOUBLE_803e5bd0;
extern f64 lbl_803E4F38;
extern f32 lbl_803DC074;
extern f32 timeDelta;
extern f32 lbl_803E4F40;
extern f32 lbl_803E4F50;
extern f32 lbl_803E4F54;
extern f32 lbl_803E4F58;
extern f32 lbl_803E4F5C;
extern f32 lbl_803E4F60;
extern f32 lbl_803E5B58;
extern f32 lbl_803E5BA0;
extern f32 lbl_803E5BA4;
extern f32 lbl_803E5BA8;
extern f32 lbl_803E5BAC;
extern f32 lbl_803E5BB8;
extern f32 lbl_803E5BBC;
extern f32 lbl_803E5BC0;
extern f32 lbl_803E5BC4;
extern f32 lbl_803E5BC8;
extern f32 lbl_803E5BD8;
extern f32 lbl_803E5BDC;
extern f32 lbl_803E5BE0;
extern f32 lbl_803E5BE4;
extern f32 lbl_803E5BE8;
extern f32 lbl_803E5BEC;
extern f32 lbl_803E5BF0;
extern f32 lbl_803E5BF4;
extern f32 lbl_803E5BF8;

#define MMSH_SHRINE_FLAG_LIT 0x4000
#define MMSH_SHRINE_LOAD_MAP_DIR 0x20
#define MMSH_SHRINE_LOAD_TRIGGER_TIMER 0xf4
#define MMSH_SHRINE_LATCH_FLAG_OPEN_READY 0x1
#define MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE 0x2
#define MMSH_SHRINE_LATCH_FLAG_CHECK_COMPLETE 0x4
#define MMSH_SHRINE_LATCH_FLAG_AMBIENT_LOCK 0x8
#define MMSH_SHRINE_LATCH_FLAG_MUSIC_LOCK 0x10
#define MMSH_SHRINE_LATCH_FLAG_SWAY_RESET 0x20
#define MMSH_SHRINE_SEQ_RESULT_COMPLETE 4
#define MMSH_SHRINE_SEQ_MAP_DIR 0xb
#define MMSH_SHRINE_SEQ_MAP_EVENT 3
#define MMSH_SHRINE_SEQ_GB_KRYSTAL 0x12a
#define MMSH_SHRINE_SEQ_GB_UNKNOWN_FF 0xff
#define MMSH_SHRINE_SEQ_GB_RESET0 0xe82
#define MMSH_SHRINE_SEQ_GB_RESET1 0xe83
#define MMSH_SHRINE_SEQ_GB_RESET2 0xe84
#define MMSH_SHRINE_SEQ_GB_RESET3 0xe85
#define MMSH_SHRINE_GB_OPEN 0xae6
#define MMSH_SHRINE_GB_COMPLETE 0xae4
#define MMSH_SHRINE_GB_RESET_A 0x12b
#define MMSH_SHRINE_GB_RESET_B 0xae5
#define MMSH_SHRINE_GB_MUSIC_LOCK 0xcbb
#define MMSH_SHRINE_SFX_IDLE 0x343
#define MMSH_SHRINE_MUSIC_RUMBLE 0xd8

typedef struct MMSHShrineRuntime {
  void *light;
  f32 swayBase;
  f32 swayAccel;
  f32 swayVelocity;
  f32 swayTarget;
  f32 idleSfxTimer;
  SCGameBitLatchState latch;
  u8 pad1C[0x24 - 0x1C];
  u8 phase;
  u8 pad25[3];
} MMSHShrineRuntime;

typedef struct MMSHShrineObject {
  s16 yaw;
  u8 pad02[0x06 - 0x02];
  s16 flags06;
  u8 pad08[0x0C - 0x08];
  f32 posX;
  f32 posY;
  f32 posZ;
  f32 prevPosX;
  f32 prevPosY;
  f32 prevPosZ;
  u8 pad24[0xAF - 0x24];
  u8 objectFlags;
  u8 padB0[0xB4 - 0xB0];
  s16 triggerHandle;
  u8 padB6[0xB8 - 0xB6];
  MMSHShrineRuntime *runtime;
  u8 padBC[MMSH_SHRINE_LOAD_TRIGGER_TIMER - 0xBC];
  s32 loadTriggerTimer;
} MMSHShrineObject;

/*
 * --INFO--
 *
 * Function: MMSH_Shrine_SeqFn
 * EN v1.0 Address: 0x801C4B10
 * EN v1.0 Size: 616b
 * EN v1.1 Address: 0x801C4B54
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int MMSH_Shrine_SeqFn(int objArg, undefined4 unused, MMSHShrineSequenceState *seq)
{
  u8 command;
  int i;
  int playerObj;
  MMSHShrineRuntime *runtime;
  MMSHShrineObject *obj;

  obj = (MMSHShrineObject *)objArg;
  runtime = obj->runtime;
  playerObj = Obj_GetPlayerObject();
  seq->targetObject = -1;
  seq->activeCommand = 0;

  for (i = 0; i < (int)(u32)seq->commandCount; i++) {
    command = seq->commands[i];
    if (command != 0) {
      switch (command) {
      case 7:
        fn_80296518(playerObj,4,1);
        GameBit_Set(MMSH_SHRINE_SEQ_GB_KRYSTAL,1);
        GameBit_Set(MMSH_SHRINE_SEQ_GB_UNKNOWN_FF,1);
        (*gMapEventInterface)->setMode(MMSH_SHRINE_SEQ_MAP_DIR,MMSH_SHRINE_SEQ_MAP_EVENT);
        break;
      case 0xe:
        obj->flags06 |= MMSH_SHRINE_FLAG_LIT;
        if (runtime->light != NULL) {
          modelLightStruct_setEnabled((int)runtime->light,0,lbl_803E4F50);
        }
        break;
      case 0xf:
        obj->flags06 &= ~MMSH_SHRINE_FLAG_LIT;
        if (runtime->light != NULL) {
          modelLightStruct_setEnabled((int)runtime->light,0,lbl_803E4F50);
        }
        break;
      case 1:
        runtime->latch.activeMask |= MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE;
        break;
      case 2:
        runtime->latch.activeMask &= ~MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE;
        if ((runtime->latch.activeMask & MMSH_SHRINE_LATCH_FLAG_SWAY_RESET) != 0) {
          fn_8011F6D4(0);
          runtime->latch.activeMask &= ~MMSH_SHRINE_LATCH_FLAG_SWAY_RESET;
        }
        break;
      case 3:
        runtime->swayTarget = lbl_803E4F54;
        break;
      case 4:
        runtime->swayTarget = lbl_803E4F58;
        break;
      case 5:
        runtime->swayTarget = -runtime->swayTarget;
        runtime->swayVelocity = -runtime->swayTarget;
        break;
      case 6:
        runtime->swayTarget *= lbl_803E4F5C;
        break;
      case 8:
        runtime->swayTarget *= lbl_803E4F60;
        break;
      }
    }
    seq->commands[i] = 0;
  }

  if (((runtime->latch.activeMask & MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE) != 0) &&
      ((u8)fn_801C49B8((int)obj) != 0)) {
    fn_8011F6D4(0);
    runtime->latch.activeMask &= ~(MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE |
                                   MMSH_SHRINE_LATCH_FLAG_SWAY_RESET);
    runtime->phase = 3;
    GameBit_Set(MMSH_SHRINE_SEQ_GB_RESET0,0);
    GameBit_Set(MMSH_SHRINE_SEQ_GB_RESET1,0);
    GameBit_Set(MMSH_SHRINE_SEQ_GB_RESET2,0);
    GameBit_Set(MMSH_SHRINE_SEQ_GB_RESET3,0);
    return MMSH_SHRINE_SEQ_RESULT_COMPLETE;
  }
  runtime->latch.activeMask |= MMSH_SHRINE_LATCH_FLAG_OPEN_READY;
  return 0;
}

/*
 * --INFO--
 *
 * Function: mmsh_shrine_getExtraSize
 * EN v1.0 Address: 0x801C4D78
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int mmsh_shrine_getExtraSize(void)
{
  return 0x28;
}

/*
 * --INFO--
 *
 * Function: mmsh_shrine_getObjectTypeId
 * EN v1.0 Address: 0x801C4D80
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int mmsh_shrine_getObjectTypeId(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: mmsh_shrine_hitDetect
 * EN v1.0 Address: 0x801C4F1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void mmsh_shrine_hitDetect(void)
{
}

extern void ModelLightStruct_free(void *p);
extern void Music_Trigger(int id, int p2);
extern void objRenderFn_8003b8f4(int p1, undefined4 p2, undefined4 p3, undefined4 p4,
                                  undefined4 p5, f32 f);
extern void objParticleFn_80099d84(int p1, f32 f1, int p2, f32 f2, int p3);
extern void skyFn_80088c94(int skyId, int enable);
extern void getEnvfxAct(int obj, int target, int effectId, int flags);
extern int mapGetDirIdx(int mapDir);
extern void unlockLevel(int mapDir, int mode, int flags);
extern void fn_801C4664(int obj);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern int randomGetRange(int min, int max);
extern int objGetAnimStateFlags(int obj, u32 mask);
extern void audioStopByMask(int mask);

/*
 * --INFO--
 *
 * Function: mmsh_shrine_free
 * EN v1.0 Address: 0x801C4D88
 * EN v1.0 Size: 220b
 */
void mmsh_shrine_free(int obj)
{
    int t = *(int *)&((GameObject *)obj)->extra;
    if ((*(int *)(t + 0x18) & 0x20) != 0) {
        fn_8011F6D4(0);
        *(int *)(t + 0x18) = *(int *)(t + 0x18) & 0xffffffdf;
    }
    if (*(void **)t != NULL) {
        ModelLightStruct_free(*(void **)t);
        *(int *)t = 0;
    }
    Music_Trigger(0xd8, 0);
    Music_Trigger(0xd9, 0);
    Music_Trigger(0x8, 0);
    Music_Trigger(0xa, 0);
    GameBit_Set(0xefa, 0);
    GameBit_Set(0xcbb, 1);
    GameBit_Set(0xe82, 0);
    GameBit_Set(0xe83, 0);
    GameBit_Set(0xe84, 0);
    GameBit_Set(0xe85, 0);
}

/*
 * --INFO--
 *
 * Function: mmsh_shrine_render
 * EN v1.0 Address: 0x801C4E64
 * EN v1.0 Size: 184b
 */
void mmsh_shrine_render(int obj, undefined4 a2, undefined4 a3, undefined4 a4, undefined4 a5,
                        char visible)
{
    MMSHShrineObject *shrine = (MMSHShrineObject *)obj;
    MMSHShrineRuntime *runtime = shrine->runtime;

    if (visible == 0) {
        if (runtime->light != NULL) {
            modelLightStruct_setEnabled((int)runtime->light, 0, lbl_803E4F50);
        }
    } else {
        if (runtime->light != NULL) {
            modelLightStruct_setEnabled((int)runtime->light, 1, lbl_803E4F50);
        }
        objRenderFn_8003b8f4(obj, a2, a3, a4, a5, lbl_803E4F50);
        objParticleFn_80099d84(obj, lbl_803E4F50, 7, *(f32 *)&lbl_803E4F50, (int)runtime->light);
    }
}

/*
 * --INFO--
 *
 * Function: mmsh_shrine_update
 * EN v1.0 Address: 0x801C4F20
 * EN v1.0 Size: 952b
 *
 * Shrine state machine: load-completion effects, gamebit latches, object-trigger phases.
 */
void mmsh_shrine_update(int objArg)
{
  MMSHShrineRuntime *runtime;
  MMSHShrineObject *obj;
  int playerObj;

  obj = (MMSHShrineObject *)objArg;
  runtime = obj->runtime;
  playerObj = Obj_GetPlayerObject();

  if (obj->loadTriggerTimer != 0) {
    obj->loadTriggerTimer--;
    if (obj->loadTriggerTimer == 0) {
      skyFn_80088c94(7,1);
      getEnvfxAct((int)obj,playerObj,0x20d,0);
      getEnvfxAct((int)obj,playerObj,0x20e,0);
      getEnvfxAct((int)obj,playerObj,0x222,0);
      obj->prevPosX = obj->posX;
      obj->prevPosY = obj->posY;
      obj->prevPosZ = obj->posZ;
    }
  }
  unlockLevel(mapGetDirIdx(MMSH_SHRINE_LOAD_MAP_DIR),1,0);
  fn_801C4664((int)obj);
  SCGameBitLatch_Update(&runtime->latch,MMSH_SHRINE_LATCH_FLAG_AMBIENT_LOCK,-1,-1,
                        MMSH_SHRINE_GB_OPEN,0xa);
  SCGameBitLatch_UpdateInverted(&runtime->latch,MMSH_SHRINE_LATCH_FLAG_CHECK_COMPLETE,-1,-1,
                                MMSH_SHRINE_GB_MUSIC_LOCK,8);
  SCGameBitLatch_Update(&runtime->latch,MMSH_SHRINE_LATCH_FLAG_MUSIC_LOCK,-1,-1,
                        MMSH_SHRINE_GB_MUSIC_LOCK,0xc4);

  switch (runtime->phase) {
  case 0:
    {
      f32 idleSfxTimer = runtime->idleSfxTimer - timeDelta;
      runtime->idleSfxTimer = idleSfxTimer;
      if (idleSfxTimer <= lbl_803E4F40) {
        Sfx_PlayFromObject((int)obj,MMSH_SHRINE_SFX_IDLE);
        runtime->idleSfxTimer = (f32)(s32)randomGetRange(500,1000);
      }
    }
    if ((obj->objectFlags & 1) == 0) {
      break;
    }
    runtime->phase = 1;
    (*gObjectTriggerInterface)->setCamVars(0x4c,0,0,0);
    (*gObjectTriggerInterface)->runSequence(0,obj,-1);
    Music_Trigger(MMSH_SHRINE_MUSIC_RUMBLE,1);
    break;
  case 1:
    if ((runtime->latch.activeMask & MMSH_SHRINE_LATCH_FLAG_OPEN_READY) == 0) {
      break;
    }
    obj->flags06 |= MMSH_SHRINE_FLAG_LIT;
    obj->yaw = 0;
    runtime->phase = 2;
    runtime->latch.activeMask &= ~MMSH_SHRINE_LATCH_FLAG_OPEN_READY;
    GameBit_Set(MMSH_SHRINE_GB_OPEN,1);
    (*gObjectTriggerInterface)->runSequence(2,obj,-1);
    break;
  case 3:
    (*gObjectTriggerInterface)->endSequence(obj->triggerHandle);
    (*gObjectTriggerInterface)->runSequence(3,obj,-1);
    runtime->phase = 4;
    GameBit_Set(MMSH_SHRINE_GB_OPEN,0);
    break;
  case 4:
    runtime->phase = 5;
    GameBit_Set(MMSH_SHRINE_GB_OPEN,0);
    GameBit_Set(MMSH_SHRINE_GB_COMPLETE,1);
    break;
  case 2:
    if (objGetAnimStateFlags(playerObj,4) == 0) {
      audioStopByMask(3);
      (*gObjectTriggerInterface)->runSequence(1,obj,-1);
    }
    runtime->phase = 5;
    GameBit_Set(MMSH_SHRINE_GB_OPEN,0);
    break;
  case 5:
    runtime->phase = 0;
    runtime->latch.activeMask &= ~MMSH_SHRINE_LATCH_FLAG_OPEN_READY;
    obj->flags06 &= ~MMSH_SHRINE_FLAG_LIT;
    GameBit_Set(MMSH_SHRINE_GB_RESET_A,0);
    GameBit_Set(MMSH_SHRINE_GB_COMPLETE,0);
    GameBit_Set(MMSH_SHRINE_GB_RESET_B,0);
    GameBit_Set(MMSH_SHRINE_GB_OPEN,0);
    break;
  }
}
