#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/cup1C3.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/resource.h"

#pragma peephole off
#pragma scheduling off

#define DBSH_SYMBOL_OBJECT_MODEL_ACTIVE_FLAG OBJ_MODEL_STATE_SHADOW_VISIBLE

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern void* FUN_800069a8();
extern int FUN_80006a64();
extern undefined8 FUN_80006a68();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern uint FUN_80006bf8();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern uint FUN_80017a98();
extern int FUN_80017b00();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 FUN_8003b818();
extern uint FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(void *a, void *b);
extern void objUpdateOpacity(int obj);

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern u8 lbl_803DBF68;
extern int *gObjectTriggerInterface;
extern int *gModgfxInterface;
extern ExpgfxInterface **gExpgfxInterface;
extern EffectInterface **gPartfxInterface;
extern u8 framesThisStep;
extern int lbl_802C23C8[];
extern s8 lbl_803DDBD0;
extern f32 lbl_803E5138;
extern f32 lbl_803E513C;
extern f64 DOUBLE_803e5da8;
extern f32 lbl_803DC074;
extern f32 lbl_803E5D78;
extern f32 lbl_803E5D7C;
extern f32 lbl_803E5D80;
extern f32 lbl_803E5D84;
extern f32 lbl_803E5D88;
extern f32 lbl_803E5D8C;
extern f32 lbl_803E5D90;
extern f32 lbl_803E5D94;
extern f32 lbl_803E5D98;
extern f32 lbl_803E5D9C;
extern f32 lbl_803E5DA0;
extern f32 lbl_803E5DB8;
extern f32 lbl_803E5DBC;
extern f32 lbl_803E5DC0;
extern f32 lbl_803E5DC4;
extern f32 lbl_803E5DC8;
extern f32 lbl_803E5DCC;

typedef struct Cup197State {
    s32 gameBit;
    s16 sparkTimer;
    s16 activeTimer;
    s16 hitCooldown;
    u8 visibleToCamera;
    u8 mode;
    u8 active;
    u8 sparkArmed;
    u8 previousActive;
    u8 stage;
} Cup197State;

/*
 * --INFO--
 *
 * Function: DBSH_Symbol_SeqFn
 * EN v1.0 Address: 0x801C9660
 * EN v1.0 Size: 2276b
 * EN v1.1 Address: 0x801C9C14
 * EN v1.1 Size: 1500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Sfx_SetObjectSfxVolume(int obj, int sfx, int vol, f32 f);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfx);
extern void gameTimerInit(int a, int b);
extern void timerSetToCountUp(void);
extern void gameTimerStop(void);
extern int isGameTimerDisabled(void);
extern int getButtonsJustPressedIfNotBusy(int p);
extern f32 timeDelta;
extern f32 lbl_803E50E0;
extern f32 lbl_803E50E4;
extern f32 lbl_803E50E8;
extern f32 lbl_803E50EC;
extern f32 lbl_803E50F0;
extern f32 lbl_803E50F4;
extern f32 lbl_803E50F8;
extern f32 lbl_803E50FC;
extern f32 lbl_803E5100;
extern f32 lbl_803E5104;
extern f32 lbl_803E5108;

typedef struct DbshSymbolFlags {
    u8 finished : 1;
    u8 active : 1;
} DbshSymbolFlags;

/*
 * Per-object extra state for the DBSH spin-symbol minigame
 * (dbsh_symbol_getExtraSize == 0x24).
 */
typedef struct DbshSymbolState {
    void *partnerObj; /* nearest objType-0x20F symbol, spun in mirror */
    f32 spinSpeed;
    f32 sfxTimerB; /* object creak sfx 0x4A3 */
    f32 sfxTimerA; /* player grunt sfx 0x13A */
    int spinProgress; /* 0..0x7EF4 = fully turned */
    int prevSpinProgress;
    int triggerHandle;
    u8 pad1C[2];
    s16 phase; /* update: 0 hide, 1 scuff, 2 arm trigger, 3 resolve */
    DbshSymbolFlags flags;
    u8 pad21[3];
} DbshSymbolState;

STATIC_ASSERT(sizeof(DbshSymbolState) == 0x24);
STATIC_ASSERT(offsetof(DbshSymbolState, phase) == 0x1E);
STATIC_ASSERT(offsetof(DbshSymbolState, flags) == 0x20);

int DBSH_Symbol_SeqFn(int *obj, int *anim, u8 *seq)
{
    f32 maxSpeed;
    f32 spdThresh;
    f32 animDiv;
    int v;
    int *list;
    int count;
    int idx;
    int i;
    int player;
    DbshSymbolState *state;

    state = ((GameObject *)obj)->extra;
    player = Obj_GetPlayerObject();
    Sfx_SetObjectSfxVolume((int)obj, 0x3af, 10, lbl_803E50E0);
    Sfx_KeepAliveLoopedObjectSound((int)obj, 0x3af);
    seq[0x56] = 0;
    for (i = 0; i < seq[0x8b]; i++) {
        if (seq[i + 0x81] == 1) {
            gameTimerInit(0x1d, 0x3c);
            timerSetToCountUp();
            state->flags.active = 0;
            ((GameObject *)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
        }
    }
    if (state->flags.active == 0) {
        return 0;
    }
    if (state->partnerObj == NULL) {
        list = (int *)ObjList_GetObjects(&idx, &count);
        while (idx < count) {
            *(int *)&state->partnerObj = list[idx];
            if (*(s16 *)(*(int *)&state->partnerObj + 0x46) == 0x20f) {
                break;
            }
            idx++;
        }
    }
    if (state->partnerObj == NULL) {
        return 0;
    }
    maxSpeed = lbl_803E50E8;
    spdThresh = lbl_803E50F8;
    animDiv = lbl_803E5100;
    for (i = 0; i < framesThisStep; i++) {
        if (isGameTimerDisabled() != 0) {
            Sfx_PlayFromObject((int)obj, 0x1d4);
            state->flags.finished = 0;
            state->flags.active = 1;
            ((ObjectTriggerInterface *)*gObjectTriggerInterface)->yield((int)seq, 0xbd);
        }
        if ((getButtonsJustPressedIfNotBusy(0) & 0x100) != 0) {
            state->spinSpeed = state->spinSpeed + lbl_803E50E4;
        }
        if (state->spinSpeed > maxSpeed) {
            state->spinSpeed = maxSpeed;
        }
        state->spinProgress = (int)((f32)state->spinProgress + state->spinSpeed);
        if (state->spinProgress >= 0x7ef4) {
            gameTimerStop();
            Sfx_PlayFromObject((int)obj, 0x1d4);
            ObjAnim_SetCurrentMove(player, 0, lbl_803E50EC, 0);
            state->flags.finished = 1;
            state->flags.active = 1;
            state->spinProgress = 0x7ef4;
            ((ObjectTriggerInterface *)*gObjectTriggerInterface)->yield((int)seq, 0xbd);
            return 0;
        }
        (*(void (**)(int))(*gObjectTriggerInterface + 0x74))(state->triggerHandle);
        if (state->spinProgress < 0) {
            state->spinProgress = 0;
            if (state->spinSpeed < lbl_803E50EC) {
                state->spinSpeed = lbl_803E50EC;
            }
            state->prevSpinProgress = state->spinProgress;
            if (state->spinSpeed > lbl_803E50F0) {
                state->spinSpeed = state->spinSpeed - lbl_803E50F4;
            }
            return 0;
        }
        if (state->spinSpeed > spdThresh) {
            state->spinSpeed = state->spinSpeed - lbl_803E50FC;
        }
        if (ObjAnim_AdvanceCurrentMove(
                ((f32)state->spinProgress - (f32)state->prevSpinProgress) / animDiv,
                timeDelta, player, NULL) != 0) {
            if (*(f32 *)(player + 0x98) < lbl_803E50EC) {
                *(f32 *)(player + 0x98) = lbl_803E5104 + *(f32 *)(player + 0x98);
            }
        }
        if (state->partnerObj != NULL) {
            if (ObjAnim_AdvanceCurrentMove(
                    -((f32)state->spinProgress - (f32)state->prevSpinProgress) / lbl_803E5100,
                    timeDelta, *(int *)&state->partnerObj, NULL) != 0) {
                f32 h = *(f32 *)(*(int *)&state->partnerObj + 0x98);
                if (h < lbl_803E50EC) {
                    *(f32 *)(*(int *)&state->partnerObj + 0x98) = lbl_803E5104 + h;
                }
            }
        }
        state->prevSpinProgress = state->spinProgress;
    }
    state->sfxTimerA = state->sfxTimerA - timeDelta;
    if (state->sfxTimerA < lbl_803E50EC) {
        if (state->spinSpeed < lbl_803E50EC) {
            state->sfxTimerA = (f32)(int)randomGetRange(0x28, 0x64);
        } else {
            state->sfxTimerA = (f32)(int)randomGetRange(0x78, 0xf0);
        }
        Sfx_PlayFromObject(player, 0x13a);
    }
    state->sfxTimerB = state->sfxTimerB - timeDelta;
    if (state->sfxTimerB < lbl_803E50EC) {
        if (state->spinSpeed > lbl_803E50EC) {
            state->sfxTimerB = (f32)(int)randomGetRange(0x28, 0x64);
        } else {
            state->sfxTimerB = (f32)(int)randomGetRange(0x78, 0xf0);
        }
        Sfx_PlayFromObject((int)obj, 0x4a3);
    }
    {
        f32 vol = lbl_803E5108 * state->spinSpeed;
        if (vol >= lbl_803E50EC) {
        } else {
            vol = -vol;
        }
        v = (int)vol;
        if (v > 100) {
            v = 100;
        }
        Sfx_SetObjectSfxVolume((int)obj, 0x3af, (u8)v, lbl_803E50E0);
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801c9f44
 * EN v1.0 Address: 0x801C9F44
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801CA1F0
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c9f44(void)
{
  FUN_80006b4c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c9f64
 * EN v1.0 Address: 0x801C9F64
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801CA210
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c9f64(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: dbsh_symbol_update
 * EN v1.0 Address: 0x801C9F84
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x801CA234
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dbsh_symbol_update(int obj)
{
  s16 phase;
  uint puzzleStarted;
  DbshSymbolState *state;
  
  state = ((GameObject *)obj)->extra;
  puzzleStarted = GameBit_Get(0x16a);
  if (puzzleStarted == 0) {
    state->phase = 0;
    state->partnerObj = NULL;
    GameBit_Set(0x16c,0);
  }
  else {
    phase = state->phase;
    if (phase == 0) {
      ((GameObject *)obj)->anim.modelState->flags &= ~DBSH_SYMBOL_OBJECT_MODEL_ACTIVE_FLAG;
      state->phase = 1;
    }
    else if (phase == 2) {
      state->phase = 3;
      state->triggerHandle =
          ((ObjectTriggerInterface *)*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
    }
    else if (phase == 1) {
      if (lbl_803DBF68 != '\0') {
        lbl_803DBF68 = 0;
        Sfx_PlayFromObject(obj, SFXfoot_stone_scuff);
      }
      state->phase = 2;
      lbl_803DBF68 = '\x01';
    }
    else if (phase == 3) {
      ((GameObject *)obj)->anim.modelState->flags &= ~DBSH_SYMBOL_OBJECT_MODEL_ACTIVE_FLAG;
      if (state->flags.finished != 0) {
        GameBit_Set(0x16b,1);
      }
      else {
        GameBit_Set(0x16c,1);
      }
      Sfx_StopObjectChannel(obj, 0x7f);
      state->flags.active = 1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dbsh_symbol_getExtraSize
 * EN v1.0 Address: 0x801C9C34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dbsh_symbol_getExtraSize(void)
{
  return 0x24;
}


/*
 * --INFO--
 *
 * Function: dbsh_symbol_free
 * EN v1.0 Address: 0x801C9C3C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dbsh_symbol_free(void)
{
  gameTimerStop();
}

/*
 * --INFO--
 *
 * Function: dbsh_symbol_render
 * EN v1.0 Address: 0x801CA0E0
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801CA418
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void objRenderFn_8003b8f4(f32);
void dbsh_symbol_render(int p1, int p2, int p3, int p4, int p5, s8 visible) {
    objRenderFn_8003b8f4(lbl_803E5104);
}

/*
 * --INFO--
 *
 * Function: FUN_801ca13c
 * EN v1.0 Address: 0x801CA13C
 * EN v1.0 Size: 596b
 * EN v1.1 Address: 0x801CA46C
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ca13c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined4 auStack_68 [2];
  short asStack_60 [4];
  short asStack_58 [4];
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined auStack_2c [12];
  float local_20;
  float local_1c;
  float local_18;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if (visible == 0) {
    *(undefined2 *)(iVar5 + 4) = 0;
    *(undefined *)(iVar5 + 10) = 0;
  }
  else if (*(char *)(iVar5 + 0xc) != '\0') {
    *(undefined *)(iVar5 + 10) = 1;
    puVar2 = FUN_800069a8();
    local_38 = *(float *)(puVar2 + 6) - *(float *)(param_1 + 0xc);
    local_34 = *(float *)(puVar2 + 8) - *(float *)(param_1 + 0x10);
    local_30 = *(float *)(puVar2 + 10) - *(float *)(param_1 + 0x14);
    dVar6 = FUN_80293900((double)(local_30 * local_30 + local_38 * local_38 + local_34 * local_34));
    if ((double)lbl_803E5DB8 < dVar6) {
      fVar1 = (float)((double)lbl_803E5DBC / dVar6);
      local_38 = local_38 * fVar1;
      dVar12 = (double)local_38;
      local_34 = local_34 * fVar1;
      dVar11 = (double)local_34;
      local_30 = local_30 * fVar1;
      dVar10 = (double)local_30;
      dVar6 = (double)lbl_803E5DC0;
      local_44 = (float)(dVar6 * dVar12) + *(float *)(param_1 + 0xc);
      local_40 = (float)(dVar6 * dVar11) + *(float *)(param_1 + 0x10);
      local_3c = (float)(dVar6 * dVar10) + *(float *)(param_1 + 0x14);
      dVar6 = (double)lbl_803E5DC4;
      dVar9 = (double)(float)(dVar6 * dVar12);
      dVar8 = (double)(float)(dVar6 * dVar11);
      local_50 = (float)(dVar9 + (double)*(float *)(puVar2 + 6));
      local_4c = (float)(dVar8 + (double)*(float *)(puVar2 + 8));
      local_48 = (float)(dVar6 * dVar10) + *(float *)(puVar2 + 10);
      FUN_80006a68(&local_44,asStack_58);
      uVar7 = FUN_80006a68(&local_50,asStack_60);
      iVar3 = FUN_80006a64(uVar7,dVar8,dVar9,dVar10,dVar11,dVar12,in_f7,in_f8,asStack_58,asStack_60,
                           auStack_68,(undefined *)0x0,0);
      if (iVar3 == 0) {
        *(undefined *)(iVar5 + 10) = 0;
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
      }
    }
    if (*(short *)(iVar5 + 4) < 1) {
      if (*(char *)(iVar5 + 10) != '\0') {
        local_20 = lbl_803E5DC8;
        local_1c = lbl_803E5DCC;
        local_18 = lbl_803E5DC8;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x1f7,auStack_2c,0x12,0xffffffff,0);
      }
      uVar4 = randomGetRange(0xfffffff6,10);
      *(short *)(iVar5 + 4) = (short)uVar4 + 0x3c;
    }
    else {
      *(ushort *)(iVar5 + 4) = *(short *)(iVar5 + 4) - (ushort)DAT_803dc070;
    }
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_197_hitDetect(void) {}

void dll_197_update(int obj)
{
    Cup197State *state = ((GameObject *)obj)->extra;
    int resourceParams[4];
    u8 callbackData[0x14];
    int player;
    f32 distance;
    void *resource;
    int effect;
    int stageEffectBase;
    int *resourceDefaults;

    resourceDefaults = lbl_802C23C8;
    resourceParams[0] = resourceDefaults[0];
    resourceParams[1] = resourceDefaults[1];
    resourceParams[2] = resourceDefaults[2];
    resourceParams[3] = resourceDefaults[3];

    player = Obj_GetPlayerObject();
    distance = Vec_distance((void *)(player + 0x18), (void *)(obj + 0x18));
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x40) != 0) {
        if (distance >= lbl_803E5138 && state->active != 0) {
            Sfx_StopObjectChannel(obj, 0x40);
        }
    } else if (distance < lbl_803E5138 && state->active != 0) {
        Sfx_PlayFromObject(obj, 0x72);
    }

    objUpdateOpacity(obj);

    if (state->hitCooldown > 0) {
        state->hitCooldown -= framesThisStep;
    }

    switch (state->mode) {
    case 1:
        break;
    default:
        return;
    }

    *(f32 *)(callbackData + 0x10) = lbl_803E513C;
    state->previousActive = state->active;
    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0 ||
        (state->hitCooldown != 0 && state->hitCooldown <= 0x14)) {
        state->active = 1 - state->active;
        if (state->active != 0) {
            state->activeTimer = 1000;
        }
        if (state->hitCooldown != 0) {
            state->hitCooldown = 0;
            lbl_803DDBD0 = 3;
            state->activeTimer = 300;
            if (state->stage == 2) {
                GameBit_Set(0x472, 1);
            }
        }
    }

    if (state->active != 0 && state->activeTimer != 0) {
        state->activeTimer -= framesThisStep;
        if (state->activeTimer <= 0) {
            state->activeTimer = 0;
            state->active = 0;
        }
    }

    if (state->active != 0 && state->sparkTimer <= 0 && state->sparkArmed != 0) {
        state->sparkArmed = 0;
        Sfx_PlayFromObject(obj, 0x80);
    }

    if (state->active == state->previousActive) {
        return;
    }

    if (state->active != 0) {
        resource = Resource_Acquire(0x69, 1);
        stageEffectBase = state->stage * 2;
        resourceParams[1] = stageEffectBase + 0x19d;
        resourceParams[2] = stageEffectBase + 0x19e;
        (*(void (*)(int, int, void *, int, int, void *))(*(int *)(*(int *)resource + 4)))(
            obj, 1, callbackData, 0x10004, -1, resourceParams);
        Resource_Release(resource);

        for (effect = 0; effect < 200; effect++) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x1a3, NULL, 0,
                                                                -1, NULL);
        }

        if (state->gameBit != -1 && GameBit_Get(state->gameBit) == 0) {
            GameBit_Set(state->gameBit, 1);
        }
        if (lbl_803DDBD0 == 0 && state->stage == 0 && GameBit_Get(state->gameBit) != 0) {
            lbl_803DDBD0 = 1;
        }
        if (lbl_803DDBD0 == 1 && state->stage == 1 && GameBit_Get(state->gameBit) != 0) {
            lbl_803DDBD0 = 2;
        }
        if (lbl_803DDBD0 == 2 && state->stage == 2 && GameBit_Get(state->gameBit) != 0) {
            GameBit_Set(0x472, 1);
            lbl_803DDBD0 = 3;
        }
        state->sparkArmed = 1;
        state->sparkTimer = 1;
    } else {
        Sfx_StopObjectChannel(obj, 0x7f);
        ((ModgfxInterface *)*gModgfxInterface)->detachSource((void *)obj);
        (*gExpgfxInterface)->freeSource(obj);
        if (state->gameBit != -1 && GameBit_Get(state->gameBit) != 0) {
            GameBit_Set(state->gameBit, 0);
        }
        if (lbl_803DDBD0 == 1 && state->stage == 0) {
            lbl_803DDBD0 = 0;
        }
        if (lbl_803DDBD0 == 2 && state->stage == 1) {
            lbl_803DDBD0 = 0;
        }
        if (lbl_803DDBD0 == 3 && state->stage == 2 && GameBit_Get(0x474) == 0) {
            GameBit_Set(0x472, 0);
            lbl_803DDBD0 = 0;
        }
    }
}

/* 8b "li r3, N; blr" returners. */
int dll_197_getExtraSize(void) { return 0x10; }
int dll_197_getObjectTypeId(void) { return 0x1; }

/* Render-side line-of-sight particle callback for the cup object. */
extern f32 lbl_803E5120;
extern f32 lbl_803E5124;
extern f32 lbl_803E5128;
extern f32 lbl_803E512C;
extern f32 lbl_803E5130;
extern f32 lbl_803E5134;
extern void *Camera_GetCurrentViewSlot(void);
extern f32 sqrtf(f32 x);
extern void voxmaps_worldToGrid(void *world, void *grid);
extern int voxmaps_traceLine(void *from, void *to, void *out, int p4, int p5);
#pragma scheduling off
#pragma peephole off
#pragma fp_contract off
void dll_197_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    struct {
        u8 pad[0xc];
        f32 pos[3];
    } particleParams;
    f32 dir[3];
    f32 objTrace[3];
    f32 cameraTrace[3];
    s16 startGrid[4];
    s16 endGrid[4];
    u8 traceOut[8];
    Cup197State *state = ((GameObject *)obj)->extra;
    u8 *camera;
    f32 dist;
    f32 scale;
    void *dirAlias = (void *)dir;

    if (visible == 0) {
        state->sparkTimer = 0;
        state->visibleToCamera = 0;
        return;
    }

    if (state->active == 0) {
        return;
    }

    state->visibleToCamera = 1;
    camera = Camera_GetCurrentViewSlot();
    dir[0] = *(f32 *)(camera + 0xc) - ((GameObject *)obj)->anim.localPosX;
    dir[1] = *(f32 *)(camera + 0x10) - ((GameObject *)obj)->anim.localPosY;
    dir[2] = *(f32 *)(camera + 0x14) - ((GameObject *)obj)->anim.localPosZ;

    dist = sqrtf(dir[2] * dir[2] + (dir[0] * dir[0] + dir[1] * dir[1]));
    if (dist > lbl_803E5120) {
        scale = lbl_803E5124 / dist;
        dir[0] = dir[0] * scale;
        dir[1] = dir[1] * scale;
        dir[2] = dir[2] * scale;

        objTrace[0] = lbl_803E5128 * dir[0];
        objTrace[1] = lbl_803E5128 * dir[1];
        objTrace[2] = lbl_803E5128 * dir[2];
        objTrace[0] = objTrace[0] + ((GameObject *)obj)->anim.localPosX;
        objTrace[1] = objTrace[1] + ((GameObject *)obj)->anim.localPosY;
        objTrace[2] = objTrace[2] + ((GameObject *)obj)->anim.localPosZ;
        cameraTrace[0] = lbl_803E512C * dir[0];
        cameraTrace[1] = lbl_803E512C * dir[1];
        cameraTrace[2] = lbl_803E512C * dir[2];
        cameraTrace[0] = cameraTrace[0] + *(f32 *)(camera + 0xc);
        cameraTrace[1] = cameraTrace[1] + *(f32 *)(camera + 0x10);
        cameraTrace[2] = cameraTrace[2] + *(f32 *)(camera + 0x14);

        voxmaps_worldToGrid((void *)objTrace, startGrid);
        voxmaps_worldToGrid((void *)cameraTrace, endGrid);
        if (voxmaps_traceLine(startGrid, endGrid, traceOut, 0, 0) == 0) {
            state->visibleToCamera = 0;
            (*gExpgfxInterface)->freeSource(obj);
        }
    }

    if (state->sparkTimer > 0) {
        state->sparkTimer -= framesThisStep;
        return;
    }

    if (state->visibleToCamera != 0) {
        particleParams.pos[0] = lbl_803E5130;
        particleParams.pos[1] = lbl_803E5134;
        particleParams.pos[2] = lbl_803E5130;
        (*gPartfxInterface)->spawnObject((void *)obj, 0x1f7, &particleParams,
                                                            0x12, -1, NULL);
    }

    state->sparkTimer = randomGetRange(-10, 10) + 0x3c;
}
#pragma fp_contract reset
#pragma peephole reset
#pragma scheduling reset

void dll_197_free(int obj)
{
    ((ModgfxInterface *)*gModgfxInterface)->detachSource((void *)obj);
    ((EffectInterface *)*gExpgfxInterface)->freeObject((void *)obj);
}

extern f32 lbl_803E5118;

#pragma scheduling off
#pragma peephole off
void dbsh_symbol_init(int* obj)
{
    DbshSymbolState* state = ((GameObject *)obj)->extra;

    state->spinSpeed = lbl_803E50EC;
    state->spinProgress = 0;
    state->prevSpinProgress = 0;
    state->phase = 0;
    *(int*)&state->partnerObj = 0;
    state->flags.finished = 0;
    state->flags.active = 1;

    ((GameObject *)obj)->anim.localPosY -= lbl_803E5118;
    ((GameObject *)obj)->animEventCallback = (void *)DBSH_Symbol_SeqFn;

    ((GameObject *)obj)->anim.modelState->flags &= ~DBSH_SYMBOL_OBJECT_MODEL_ACTIVE_FLAG;
}
#pragma peephole reset
#pragma scheduling reset
