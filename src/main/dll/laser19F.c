#include "ghidra_import.h"
#include "main/dll/laser19F.h"
#include "main/dll/SC/SCtotemlogpuz.h"


#pragma peephole off
#pragma scheduling off
extern undefined8 FUN_80006b14();
extern char FUN_80006bd0();
extern undefined4 FUN_800175cc();
extern void lightFn_8001db6c(int p1, int p2, f32 f);
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

extern undefined4* DAT_803dd72c;
extern void* DAT_803de838;
extern int *gMapEventInterface;
extern int *gObjectTriggerInterface;
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

typedef struct MMSHShrineSequenceState {
  u8 pad00[0x56];
  u8 activeCommand;
  u8 pad57[0x70 - 0x57];
  s16 targetObject;
  u8 pad72[0x81 - 0x72];
  u8 commands[10];
  u8 commandCount;
} MMSHShrineSequenceState;

typedef void (*ObjectTriggerRefreshFn)(int mode, int obj, int arg);
typedef void (*ObjectTriggerReleaseFn)(s16 triggerHandle);
typedef void (*ObjectTriggerSpawnFn)(int type, int a, int b, int c);
typedef void (*MapEventTriggerFn)(int mapDir, int eventId);

#define OBJECT_TRIGGER_FN(offset, type) ((type)(*(u32 *)((u8 *)*gObjectTriggerInterface + (offset))))
#define MAP_EVENT_FN(offset, type) ((type)(*(u32 *)((u8 *)*gMapEventInterface + (offset))))

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
int MMSH_Shrine_SeqFn(int objArg, undefined4 unused, int seqArg)
{
  MMSHShrineObject *obj;
  MMSHShrineRuntime *runtime;
  MMSHShrineSequenceState *seq;
  int playerObj;
  int i;
  u8 command;

  obj = (MMSHShrineObject *)objArg;
  seq = (MMSHShrineSequenceState *)seqArg;
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
        MAP_EVENT_FN(0x44,MapEventTriggerFn)(MMSH_SHRINE_SEQ_MAP_DIR,MMSH_SHRINE_SEQ_MAP_EVENT);
        break;
      case 0xe:
        obj->flags06 |= MMSH_SHRINE_FLAG_LIT;
        if (runtime->light != NULL) {
          lightFn_8001db6c((int)runtime->light,0,lbl_803E4F50);
        }
        break;
      case 0xf:
        obj->flags06 &= ~MMSH_SHRINE_FLAG_LIT;
        if (runtime->light != NULL) {
          lightFn_8001db6c((int)runtime->light,0,lbl_803E4F50);
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
 * Function: FUN_801c4b14
 * EN v1.0 Address: 0x801C4B14
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801C4C18
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c4b14(ushort *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 local_30;
  
  iVar4 = *(int *)(param_1 + 0x26);
  iVar3 = *(int *)(param_1 + 0x5c);
  iVar1 = FUN_80017a98();
  if ((param_1[3] & 0x4000) == 0) {
    *(short *)(iVar3 + 0x1e) =
         *(short *)(iVar3 + 0x1e) + (short)(int)(lbl_803E5BA0 * lbl_803DC074);
    *(short *)(iVar3 + 0x20) =
         *(short *)(iVar3 + 0x20) + (short)(int)(lbl_803E5BA4 * lbl_803DC074);
    *(short *)(iVar3 + 0x22) =
         *(short *)(iVar3 + 0x22) + (short)(int)(lbl_803E5BA8 * lbl_803DC074);
    dVar5 = (double)FUN_80293f90();
    *(float *)(param_1 + 8) = lbl_803E5BAC + (float)((double)*(float *)(iVar4 + 0xc) + dVar5);
    dVar5 = (double)FUN_80293f90();
    dVar6 = (double)FUN_80293f90();
    param_1[2] = (ushort)(int)(lbl_803E5BB8 * (float)(dVar6 + dVar5));
    dVar5 = (double)FUN_80293f90();
    dVar6 = (double)FUN_80293f90();
    param_1[1] = (ushort)(int)(lbl_803E5BB8 * (float)(dVar6 + dVar5));
    FUN_8002fc3c((double)lbl_803E5BBC,(double)lbl_803DC074);
    if (iVar1 != 0) {
      uVar2 = FUN_80017730();
      uVar2 = (uVar2 & 0xffff) - (uint)*param_1;
      if (0x8000 < (int)uVar2) {
        uVar2 = uVar2 - 0xffff;
      }
      if ((int)uVar2 < -0x8000) {
        uVar2 = uVar2 + 0xffff;
      }
      local_30 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *param_1 = *param_1 +
                 (short)(int)(((float)(local_30 - DOUBLE_803e5bd0) * lbl_803DC074) /
                             lbl_803E5BC0);
      dVar5 = (double)FUN_80017710((float *)(param_1 + 0xc),(float *)(iVar1 + 0x18));
      if ((double)lbl_803E5BC4 < dVar5) {
        *(undefined *)(param_1 + 0x1b) = 0xff;
      }
      else {
        *(char *)(param_1 + 0x1b) =
             (char)(int)(lbl_803E5BC8 * (float)(dVar5 / (double)lbl_803E5BC4));
      }
    }
  }
  else {
    *param_1 = 0;
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar4 + 0xc);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c4de0
 * EN v1.0 Address: 0x801C4DE0
 * EN v1.0 Size: 364b
 * EN v1.1 Address: 0x801C4F6C
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801c4de0(int param_1)
{
  float fVar1;
  float fVar2;
  char cVar4;
  undefined4 uVar3;
  int iVar5;
  undefined8 local_18;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if ((*(uint *)(iVar5 + 0x18) & 0x20) == 0) {
    FUN_8011eb10(1);
    *(uint *)(iVar5 + 0x18) = *(uint *)(iVar5 + 0x18) | 0x20;
    fVar1 = lbl_803E5BD8;
    *(float *)(iVar5 + 4) = lbl_803E5BD8;
    *(float *)(iVar5 + 8) = fVar1;
    *(float *)(iVar5 + 0xc) = fVar1;
  }
  cVar4 = FUN_80006bd0(0);
  fVar2 = lbl_803E5BE0;
  local_18 = (double)CONCAT44(0x43300000,(int)cVar4 ^ 0x80000000);
  *(float *)(iVar5 + 8) =
       ((float)(local_18 - DOUBLE_803e5bd0) / lbl_803E5BDC) * lbl_803E5BE0 * lbl_803DC074 +
       *(float *)(iVar5 + 8);
  fVar1 = *(float *)(iVar5 + 0x10);
  if ((lbl_803E5BD8 <= fVar1) || (*(float *)(iVar5 + 0xc) <= fVar1)) {
    if ((lbl_803E5BD8 < fVar1) && (*(float *)(iVar5 + 0xc) < fVar1)) {
      *(float *)(iVar5 + 0xc) = lbl_803E5BE0 * lbl_803DC074 + *(float *)(iVar5 + 0xc);
    }
  }
  else {
    *(float *)(iVar5 + 0xc) = -(fVar2 * lbl_803DC074 - *(float *)(iVar5 + 0xc));
  }
  *(float *)(iVar5 + 4) =
       lbl_803DC074 * (*(float *)(iVar5 + 8) + *(float *)(iVar5 + 0xc)) + *(float *)(iVar5 + 4);
  iVar5 = (int)(lbl_803E5BE4 * *(float *)(iVar5 + 4));
  FUN_8011eb1c(0x60,0x39,(short)iVar5);
  if ((iVar5 < 0x3a) && (-0x3a < iVar5)) {
    uVar3 = 0;
  }
  else {
    uVar3 = 1;
  }
  return uVar3;
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

extern void lightFn_8001db6c(int p1, int p2, f32 f);
extern void fn_8011F6D4(int p);
extern void ModelLightStruct_free(void *p);
extern void Music_Trigger(int id, int p2);
extern void objRenderFn_8003b8f4(int p1, undefined4 p2, undefined4 p3, undefined4 p4,
                                  undefined4 p5, f32 f);
extern void objParticleFn_80099d84(int p1, int p2, int p3, f32 f1, f32 f2);
extern void skyFn_80088c94(int skyId, int enable);
extern void getEnvfxAct(int obj, int target, int effectId, int flags);
extern int mapGetDirIdx(int mapDir);
extern void unlockLevel(int mapDir, int mode, int flags);
extern void fn_801C4664(int obj);
extern void SCGameBitLatch_Update(SCGameBitLatchState *state, int mask, s16 clearIfSetBit,
                                  s16 clearIfClearBit, s16 latchBit, int musicId);
extern void SCGameBitLatch_UpdateInverted(SCGameBitLatchState *state, int mask, s16 clearIfSetBit,
                                          s16 clearIfClearBit, s16 latchBit, int musicId);
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
#pragma peephole off
#pragma scheduling off
void mmsh_shrine_free(int obj)
{
    int t = *(int *)(obj + 0xb8);
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
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: mmsh_shrine_render
 * EN v1.0 Address: 0x801C4E64
 * EN v1.0 Size: 184b
 */
#pragma peephole off
#pragma scheduling off
void mmsh_shrine_render(int obj, undefined4 a2, undefined4 a3, undefined4 a4, undefined4 a5,
                        char visible)
{
    MMSHShrineObject *shrine = (MMSHShrineObject *)obj;
    MMSHShrineRuntime *runtime = shrine->runtime;

    if (visible == 0) {
        if (runtime->light != NULL) {
            lightFn_8001db6c((int)runtime->light, 0, lbl_803E4F50);
        }
    } else {
        if (runtime->light != NULL) {
            lightFn_8001db6c((int)runtime->light, 1, lbl_803E4F50);
        }
        objRenderFn_8003b8f4(obj, a2, a3, a4, a5, lbl_803E4F50);
        objParticleFn_80099d84(obj, 7, (int)runtime->light, lbl_803E4F50, lbl_803E4F50);
    }
}
#pragma scheduling reset
#pragma peephole reset

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
    runtime->idleSfxTimer -= timeDelta;
    if (runtime->idleSfxTimer <= lbl_803E4F40) {
      Sfx_PlayFromObject((int)obj,MMSH_SHRINE_SFX_IDLE);
      runtime->idleSfxTimer = (f32)(s32)randomGetRange(500,1000);
    }
    if ((obj->objectFlags & 1) == 0) {
      break;
    }
    runtime->phase = 1;
    OBJECT_TRIGGER_FN(0x50,ObjectTriggerSpawnFn)(0x4c,0,0,0);
    OBJECT_TRIGGER_FN(0x48,ObjectTriggerRefreshFn)(0,(int)obj,-1);
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
    OBJECT_TRIGGER_FN(0x48,ObjectTriggerRefreshFn)(2,(int)obj,-1);
    break;
  case 2:
    if (objGetAnimStateFlags(playerObj,4) == 0) {
      audioStopByMask(3);
      OBJECT_TRIGGER_FN(0x48,ObjectTriggerRefreshFn)(1,(int)obj,-1);
    }
    runtime->phase = 5;
    GameBit_Set(MMSH_SHRINE_GB_OPEN,0);
    break;
  case 3:
    OBJECT_TRIGGER_FN(0x4c,ObjectTriggerReleaseFn)(obj->triggerHandle);
    OBJECT_TRIGGER_FN(0x48,ObjectTriggerRefreshFn)(3,(int)obj,-1);
    runtime->phase = 4;
    GameBit_Set(MMSH_SHRINE_GB_OPEN,0);
    break;
  case 4:
    runtime->phase = 5;
    GameBit_Set(MMSH_SHRINE_GB_OPEN,0);
    GameBit_Set(MMSH_SHRINE_GB_COMPLETE,1);
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
