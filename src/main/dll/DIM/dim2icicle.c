/*
 * dim2icicle - DIM2 Icicle boss per-frame update functions.
 * Handles boss sequence effects (glow light, dust/burst particle spawns),
 * Dark Ice Mines map-warp and environmental effects, player hit-response
 * (score tracking, game-bit setting, hit-effect spawning), and the main
 * combat-state driver that runs the AI and controls Tricky interaction.
 */
#include "main/dll/DIM/DIM2lift.h"
#include "main/audio/sfx.h"
#include "main/dll/baddie_state.h"
#include "main/effect_interfaces.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/objhits.h"
#include "main/player_control_interface.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_trigger_ids.h"

static inline int *DIM2Icicle_GetActiveModel(void *obj) {
  ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
  return (int *)objAnim->banks[objAnim->bankIndex];
}

extern int randomGetRange(int lo, int hi);

extern void ObjPath_GetPointWorldPosition(int obj, int pointIndex, float* outX, float* outY, float* outZ, int useInputPosition);
extern u32 gDIMbossAnimTable[];
extern u32 gDIMbossHitDetectAnimTable[];
extern void* getTrickyObject(void);
extern u32* gBaddieControlInterface;
extern u32 gDIMbossSequenceFlags;
extern f32 timeDelta;
extern f32 lbl_803E4BC8;
extern f32 lbl_803E4BD8;
extern f32 lbl_803E4BEC;
extern f32 lbl_803E4C44;
extern f32 lbl_803E4C70;
extern f32 gDim2IcicleLightDuration;
extern u8 gDim2IcicleMeltEntries[];

typedef struct IcicleEntry {
    f32 resetTime;
    u16 bit;
    u16 pad;
} IcicleEntry;

typedef struct IcicleState {
    u8 pad[0xa0];
    f32 meltTimer;
    f32 lightTimer;
    f32 fadeTimer;
    u8 pad2[9];
    u8 index;
} IcicleState;

extern void PSMTXMultVec(f32 *mtx, f32 *src, f32 *dst);
extern void memcpy(void *dst, void *src, int n);
extern const f32 lbl_803E4BCC;
extern const f32 lbl_803E4C34;
extern const f32 lbl_803E4C38;
extern f32 lbl_803E4C3C;
extern f32 lbl_803E4C40;
extern f32 lbl_803E4C48;
extern u8 gDim2IcicleDustFxSource[];
extern DIMbossAnimScratch gDIMbossAnimScratchBase;

typedef struct IcicleFxPos {
    u8 pad[0xc];
    f32 x;
    f32 y;
    f32 z;
} IcicleFxPos;

void DIM2icicle_updateBossSequenceEffects(DIMbossObject *obj, DIMbossRuntime *runtime)
{
  DIMbossTopState *topState;
  int objIndex;
  s16 brightness;
  int i;
  f32 zero;
  f32 c34v;
  f32 prod;
  f32 m[12];
  u8 colA;
  u8 colB;
  u8 colG;
  u8 colR;

  objIndex = (int)obj;
  topState = runtime->topState;
  if (topState->effect != NULL) {
    if (runtime->phase == DIMBOSS_PHASE_LAUNCH_LIFT) {
      modelLightStruct_setPosition((ModelLightStruct *)topState->effect, topState->liftGlowSource.x, topState->liftGlowSource.y, topState->liftGlowSource.z);
    }
    else {
      modelLightStruct_setPosition((ModelLightStruct *)topState->effect, topState->tonsilDustSource.x, topState->tonsilDustSource.y, topState->tonsilDustSource.z);
    }
    modelLightStruct_getSpecularColor((ModelLightStruct *)topState->effect, &colA, &colB, &colG, &colR);
    modelLightStruct_setGlowColor((ModelLightStruct *)topState->effect, colA, colB, colG, 0xc0);
    if (topState->effect->glowType != 0 && topState->effect->enabled != 0) {
      brightness = topState->effect->glowAlpha + topState->effect->glowAlphaStep;
      if (brightness < 0) {
        brightness = 0;
        topState->effect->glowAlphaStep = 0;
      }
      else if (brightness > 0xc) {
        brightness = brightness + randomGetRange(-0xc, 0xc);
        if (brightness > 0xff) {
          brightness = 0xff;
          topState->effect->glowAlphaStep = 0;
        }
      }
      topState->effect->glowAlpha = brightness;
    }
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_7) {
    ObjPath_GetPointWorldPosition(objIndex, 7, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->x, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->y, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->z, 0);
    i = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)objIndex, 0x4b7, &gDim2IcicleDustFxSource, 0x200001, -1, NULL);
      i = i + 1;
    } while (i < 0xf);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_8) {
    ObjPath_GetPointWorldPosition(objIndex, 8, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->x, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->y, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->z, 0);
    i = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)objIndex, 0x4b7, &gDim2IcicleDustFxSource, 0x200001, -1, NULL);
      i = i + 1;
    } while (i < 0xf);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_9) {
    ObjPath_GetPointWorldPosition(objIndex, 9, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->x, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->y, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->z, 0);
    i = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)objIndex, 0x4b7, &gDim2IcicleDustFxSource, 0x200001, -1, NULL);
      i = i + 1;
    } while (i < 0xf);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_10) {
    ObjPath_GetPointWorldPosition(objIndex, 10, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->x, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->y, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->z, 0);
    i = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)objIndex, 0x4b7, &gDim2IcicleDustFxSource, 0x200001, -1, NULL);
      i = i + 1;
    } while (i < 0xf);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_BREATH_BURST) {
    memcpy(m, (void *)ObjPath_GetPointModelMtx(objIndex, 0xb), 0x30);
    zero = lbl_803E4BD8;
    m[3] = zero;
    m[7] = zero;
    m[11] = zero;
    i = 0;
    do {
      ((IcicleFxPos *)&gDim2IcicleDustFxSource)->x = (f32)(int)randomGetRange(-0x19, 0x19);
      ((IcicleFxPos *)&gDim2IcicleDustFxSource)->y = (f32)(int)randomGetRange(-0x19, 0x19);
      c34v = lbl_803E4C34;
      ((IcicleFxPos *)&gDim2IcicleDustFxSource)->z = lbl_803E4C34;
      prod = c34v * lbl_803E4C38;
      gDIMbossAnimScratchBase.effectVelocity[0] =
          ((IcicleFxPos *)&gDim2IcicleDustFxSource)->x / prod;
      gDIMbossAnimScratchBase.effectVelocity[1] =
          ((IcicleFxPos *)&gDim2IcicleDustFxSource)->y / prod;
      gDIMbossAnimScratchBase.effectVelocity[2] = lbl_803E4BCC;
      PSMTXMultVec(m, gDIMbossAnimScratchBase.effectVelocity,
                   gDIMbossAnimScratchBase.effectVelocity);
      ObjPath_GetPointWorldPosition(objIndex, 0xb, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->x, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->y, &((IcicleFxPos *)&gDim2IcicleDustFxSource)->z, 1);
      (*gPartfxInterface)->spawnObject(
          (void *)objIndex, 0x4b8, &gDim2IcicleDustFxSource, 0x200001, -1,
          gDIMbossAnimScratchBase.effectVelocity);
      i = i + 1;
    } while (i < 5);
  }
  topState->breathBurstSource.x = lbl_803E4BD8;
  topState->breathBurstSource.y = lbl_803E4C3C;
  topState->breathBurstSource.z = lbl_803E4C40;
  topState->breathBurstSource.scale = lbl_803E4C44;
  topState->breathBurstSource.rotZ = 0;
  topState->breathBurstSource.rotY = 0;
  topState->breathBurstSource.rotX = 0;
  ObjPath_GetPointWorldPosition(objIndex, 0xd, &topState->breathBurstSource.x, &topState->breathBurstSource.y, &topState->breathBurstSource.z, 1);
  ObjPath_GetPointWorldPosition(objIndex, 0xd, &topState->blueWhiteEffectSource.x, &topState->blueWhiteEffectSource.y, &topState->blueWhiteEffectSource.z, 0);
  ObjPath_GetPointWorldPosition(objIndex, 0xb, &topState->tonsilDustSource.x, &topState->tonsilDustSource.y, &topState->tonsilDustSource.z, 0);
  topState->liftGlowSource.x = lbl_803E4BD8;
  topState->liftGlowSource.y = lbl_803E4C48;
  topState->liftGlowSource.z = lbl_803E4BC8;
  topState->liftGlowSource.scale = lbl_803E4C44;
  topState->liftGlowSource.rotZ = 0;
  topState->liftGlowSource.rotY = 0;
  topState->liftGlowSource.rotX = 0;
  ObjPath_GetPointWorldPosition(objIndex, 0xc, &topState->liftGlowSource.x, &topState->liftGlowSource.y, &topState->liftGlowSource.z, 1);
  memcpy(topState->breathBurstMtx, (void *)ObjPath_GetPointModelMtx(objIndex, 0), 0x30);
  zero = lbl_803E4BD8;
  topState->breathBurstMtx[3] = zero;
  topState->breathBurstMtx[7] = zero;
  topState->breathBurstMtx[11] = zero;
  gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~DIMBOSS_SEQUENCE_FLAGS_ICICLE_DUST_AND_BREATH;
}

#define GAMEBIT_DIM2_ICICLE_ACTIVE     0x25e
#define GAMEBIT_DIM2_ICICLE_DEFEATED   0x20e
#define GAMEBIT_DIM2_ICICLE_PHASE1_WIN 0x20b
#define GAMEBIT_DIM2_ICICLE_PHASE2_WIN 0x266


extern int getEnvfxAct(int a, int b, u16 idx, int d);


extern void skyFn_800895e0(int flags, u8 red, u8 green, u8 blue, u8 m1, u8 m2);




extern int gDim2IcicleSequenceSfx[];
extern f32 lbl_803E4BC4;
extern f32 lbl_803E4BF4;
extern f32 lbl_803E4BF8;
extern f32 lbl_803E4C4C;
extern f32 lbl_803E4C50;
extern f32 lbl_803E4C54;
extern const f32 lbl_803E4C58;
extern const f32 lbl_803E4C5C;
extern f32 lbl_803E4C60;
extern f32 lbl_803E4C64;
extern f32 lbl_803E4C68;
extern f32 lbl_803E4C6C;

typedef struct IcicleWarpFlags {
    u8 pending : 1;
    u8 rest : 7;
} IcicleWarpFlags;

void DIM2icicle_updateDarkIceMinesWarpAndEffects(DIMbossObject *obj, DIMbossRuntime *runtime)
{
  DIMbossTopState *topState;
  int counter;
  int i;
  u32 flags;
  f32 vec[3];

  topState = runtime->topState;
  counter = topState->defeatTimer;
  if (counter != 0) {
    topState->defeatTimer = counter - 1;
    if (topState->defeatTimer <= 0) {
      topState->defeatTimer = 0;
      setShowWorldMapHud(0);
      warpToMap(0x77, 1);
      return;
    }
  }
  if (((IcicleWarpFlags *)&topState->steamFlags)->pending) {
    getEnvfxAct(0, 0, 0xdb, 0);
    getEnvfxAct(0, 0, 0xdc, 0);
    skyFn_80089710(7, 1, 0);
    skyFn_800894a8(7, lbl_803E4C4C, lbl_803E4C50, lbl_803E4C54);
    skyFn_800895e0(7, 0xa0, 0xa0, 0xff, 0x7f, 0x28);
    ((IcicleWarpFlags *)&topState->steamFlags)->pending = 0;
  }
  if (runtime->sequenceTriggerFlags & DIMBOSS_SEQUENCE_FLAG_0004) {
    runtime->sequenceTriggerFlags &= ~DIMBOSS_SEQUENCE_FLAG_0004;
    Sfx_PlayFromObject((u32)obj, gDim2IcicleSequenceSfx[0]);
    gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0004 | DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_7;
    doRumble(lbl_803E4BF8);
  }
  if (runtime->sequenceTriggerFlags & DIMBOSS_SEQUENCE_FLAG_0002) {
    runtime->sequenceTriggerFlags &= ~DIMBOSS_SEQUENCE_FLAG_0002;
    Sfx_PlayFromObject((u32)obj, gDim2IcicleSequenceSfx[1]);
    gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0004 | DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_8;
    doRumble(lbl_803E4BF8);
  }
  if (runtime->sequenceTriggerFlags & DIMBOSS_SEQUENCE_FLAG_BREATH_BURST) {
    runtime->sequenceTriggerFlags &= ~DIMBOSS_SEQUENCE_FLAG_BREATH_BURST;
    Sfx_PlayFromObject((u32)obj, gDim2IcicleSequenceSfx[2]);
    gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0004 | DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_9;
    doRumble(lbl_803E4BF8);
  }
  if (runtime->sequenceTriggerFlags & DIMBOSS_SEQUENCE_FLAG_TONSIL_GUARD_ACTIVE) {
    runtime->sequenceTriggerFlags &= ~DIMBOSS_SEQUENCE_FLAG_TONSIL_GUARD_ACTIVE;
    Sfx_PlayFromObject((u32)obj, gDim2IcicleSequenceSfx[3]);
    gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_0004 | DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_10;
    doRumble(lbl_803E4BF8);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_2000) {
    i = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)obj, 0x4b1, &topState->liftGlowSource, 0x200001, -1, NULL);
      i = i + 1;
    } while (i < 0x32);
    (*gPartfxInterface)->spawnObject((void *)obj, 0x4b2, &topState->liftGlowSource, 0x200001, -1, NULL);
    (*gPartfxInterface)->spawnObject((void *)obj, 0x4b3, &topState->liftGlowSource, 0x200001, -1, NULL);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_80000) {
    (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x800, NULL, 1, NULL);
  }
  if ((gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAGS_TONSIL_IMPACT) || runtime->animMode < 2) {
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0020) {
      i = 0;
      do {
        (*gPartfxInterface)->spawnObject((void *)obj, 0x4b4, &topState->tonsilDustSource, 0x200001, -1, NULL);
        i = i + 1;
      } while (i < 7);
    }
    else {
      if (randomGetRange(0, runtime->animMode) == 0 && runtime->phase == DIMBOSS_PHASE_GAMEBIT_COUNT_MET) {
        (*gPartfxInterface)->spawnObject((void *)obj, 0x4b4, &topState->tonsilDustSource, 0x200001, -1, NULL);
      }
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_8000) {
      (*gPartfxInterface)->spawnObject((void *)obj, 0x4b2, &topState->tonsilDustSource, 0x200001, -1, NULL);
      (*gPartfxInterface)->spawnObject((void *)obj, 0x4b3, &topState->tonsilDustSource, 0x200001, -1, NULL);
    }
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAGS_ICICLE_HIT_EFFECTS) {
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0040) {
      i = 0;
      do {
        vec[0] = lbl_803E4C58 * (f32)(int)randomGetRange(-5, 5);
        vec[1] = lbl_803E4C58 * (f32)(int)randomGetRange(-5, 5);
        vec[2] = lbl_803E4C5C * (f32)(int)randomGetRange(2, 8);
        PSMTXMultVec(topState->breathBurstMtx, vec, vec);
        (*gPartfxInterface)->spawnObject((void *)obj, 0x4b5, &topState->breathBurstSource, 0x200001, -1, vec);
        i = i + 1;
      } while (i < 5);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0080) {
      (*gPartfxInterface)->spawnObject((void *)obj, 0x4b5, &topState->blueWhiteEffectSource, 0x200001, -1, NULL);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0100) {
      vec[0] = lbl_803E4C58;
      vec[1] = lbl_803E4C60;
      vec[2] = lbl_803E4C64 * (f32)(int)randomGetRange(4, 8);
      PSMTXMultVec(topState->breathBurstMtx, vec, vec);
      (*gPartfxInterface)->spawnObject((void *)obj, 0x4b6, &topState->blueWhiteEffectSource, 0x200001, -1, vec);
    }
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_CAPTURE_BLUE_WHITE_VELOCITY) {
      vec[0] = lbl_803E4BD8;
      vec[1] = lbl_803E4C60;
      vec[2] = lbl_803E4C68;
      PSMTXMultVec(topState->breathBurstMtx, vec, vec);
      memcpy(topState->blueWhiteVelocity, vec, 0xc);
      gDIMbossSequenceFlags |= (u64)DIMBOSS_SEQUENCE_FLAG_SPAWN_BLUE_WHITE_EFFECT;
    }
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ARENA_DUST_BURST) {
    i = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)obj, 0x4b7, NULL, 1, -1, NULL);
      i = i + 1;
    } while (i < 0x32);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0001) {
    Camera_EnableViewYOffset();
    doRumble(lbl_803E4BF8);
    CameraShake_Start(lbl_803E4BC4, lbl_803E4BC8, lbl_803E4BCC);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_40000) {
    Camera_EnableViewYOffset();
    doRumble(lbl_803E4C6C);
    CameraShake_Start(lbl_803E4BC8, lbl_803E4BF4, lbl_803E4BF8);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0002) {
    Camera_EnableViewYOffset();
    CameraShake_Start(lbl_803E4BD8, lbl_803E4BD8, lbl_803E4BD8);
    CameraShake_SetAllMagnitudes(lbl_803E4BD8);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_0004) {
    GameBit_Set(GAMEBIT_DIM2_ICICLE_ACTIVE, 1);
  }
  else {
    GameBit_Set(GAMEBIT_DIM2_ICICLE_ACTIVE, 0);
  }
  gDIMbossSequenceFlags &= DIMBOSS_SEQUENCE_FLAGS_PERSIST_AFTER_EFFECT_UPDATE;
}

extern int Obj_GetPlayerObject(void);
extern int fn_80295A04(int obj, int sel);
extern void ObjMsg_SendToObject(int to, int msg, int obj, int data);
extern int *gTitleMenuControlInterfaceCopy;
extern int *gDIMbossHitEffectResource;
extern int gDim2IcicleHitCooldown;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E4C10;
extern u8 gDim2IcicleHitDescTemplate[];
extern u8 gDim2IcicleHitFxBuffer[];

typedef struct IcicleHitDesc {
    int f0;
    int f1;
    int f2;
    int f3;
} IcicleHitDesc;

typedef struct IcicleHitEntry {
    f32 q;
    f32 px;
    f32 py;
    f32 pz;
} IcicleHitEntry;

typedef struct IcicleHitFx {
    u16 a;
    u16 b;
    u16 c;
    u16 pad;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} IcicleHitFx;

void DIM2icicle_updateHitResponse(int obj, int playerObj)
{
  int *state;
  u8 hit;
  int hitResult;
  int player;
  IcicleHitEntry *base;
  ObjHitsPriorityState *hitState;
  int hitType;
  u32 hitVolume;
  int hitId;
  IcicleHitDesc desc;

  state = ((GameObject *)obj)->extra;
  Obj_GetPlayerObject();
  hit = 0;
  desc = *(IcicleHitDesc *)gDim2IcicleHitDescTemplate;
  if (gDim2IcicleHitCooldown != 0) {
    gDim2IcicleHitCooldown = gDim2IcicleHitCooldown - 1;
  }
  hitResult = ObjHits_GetPriorityHit(obj, &hitId, &hitType, &hitVolume);
  if (hitResult != 0) {
    gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~(u64)DIMBOSS_SEQUENCE_FLAG_0040;
    if (((GroundBaddieState *)state)->targetState == 1) {
      if ((gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_TONSIL_GUARD_ACTIVE) == 0 ||
          hitType != 2) {
        hit = 1;
      }
    }
    else if (((GroundBaddieState *)state)->targetState == 2) {
      if (hitType != 4 || ((GameObject *)obj)->anim.currentMoveProgress < lbl_803E4C10 || ((GameObject *)obj)->anim.currentMove != 0x12) {
        hit = 1;
      }
    }
    if (hit) {
      if (gDim2IcicleHitCooldown == 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_sc_npu_216_4b2);
        base = (IcicleHitEntry *)DIM2Icicle_GetActiveModel((void *)obj)[0x14];
        ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->x = playerMapOffsetX + base[hitType].px;
        ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->y = base[hitType].py;
        ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->z = playerMapOffsetZ + base[hitType].pz;
        (*gPartfxInterface)->spawnObject((void *)obj, 0x328, gDim2IcicleHitFxBuffer, 0x200001, -1, NULL);
        ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->x = ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->x - ((GameObject *)obj)->anim.worldPosX;
        ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->y = ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->y - ((GameObject *)obj)->anim.worldPosY;
        ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->z = ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->z - ((GameObject *)obj)->anim.worldPosZ;
        ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->scale = lbl_803E4C44;
        ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->a = 0;
        ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->b = 0;
        ((IcicleHitFx *)gDim2IcicleHitFxBuffer)->c = 0;
        desc.f1 += randomGetRange(0, 0x9b);
        desc.f2 += randomGetRange(0, 0x9b);
        ((void (*)(int, int, u8 *, int, int, IcicleHitDesc *))*(VtableFn **)(*(int *)gDIMbossHitEffectResource + 4))(obj, 0, gDim2IcicleHitFxBuffer, 1, -1, &desc);
        gDim2IcicleHitCooldown = 0x1e;
      }
    }
    else {
      if (((BaddieState *)playerObj)->targetObj == NULL) {
        player = Obj_GetPlayerObject();
        if (fn_80295A04(player, 1) != 0) {
          ((void (*)(int, int, int, int, int, int, int, int, int))*(VtableFn **)(*gBaddieControlInterface + 0x28))
                    (obj, playerObj, (int)state + 0x35c, (int)*(s16 *)((int)state + 0x3f4), 0, 2, 10, -1, -1);
          *(int *)&((BaddieState *)playerObj)->targetObj = player;
          ((BaddieState *)playerObj)->hasTarget = 0;
        }
      }
      if (((GroundBaddieState *)state)->targetState == 1) {
        if (*(s8 *)&((BaddieState *)playerObj)->hitPoints == 3) {
          ((void (*)(int, int, int, int, int))*(VtableFn **)(*(int *)gTitleMenuControlInterfaceCopy + 4))(obj, 0x68, 0, 0, 0);
        }
        else if (*(s8 *)&((BaddieState *)playerObj)->hitPoints == 2) {
          ((void (*)(int, int, int, int, int))*(VtableFn **)(*(int *)gTitleMenuControlInterfaceCopy + 4))(obj, 0x6c, 0, 0, 0);
        }
      }
      else if (((GroundBaddieState *)state)->targetState == 2) {
        if (*(s8 *)&((BaddieState *)playerObj)->hitPoints == 3) {
          ((void (*)(int, int, int, int, int))*(VtableFn **)(*(int *)gTitleMenuControlInterfaceCopy + 4))(obj, 0x77, 0, 0, 0);
        }
        else if (*(s8 *)&((BaddieState *)playerObj)->hitPoints == 2) {
          ((void (*)(int, int, int, int, int))*(VtableFn **)(*(int *)gTitleMenuControlInterfaceCopy + 4))(obj, 0x78, 0, 0, 0);
        }
      }
      ((BaddieState *)playerObj)->moveDone = 0;
      *(s8 *)(playerObj + 0x34f) = hitResult;
      ((BaddieState *)playerObj)->hitPoints -= 1;
      Sfx_PlayFromObject(obj, SFXTRIG_wp_mpwru1);
      if (*(s8 *)&((BaddieState *)playerObj)->hitPoints <= 0) {
        ((BaddieState *)playerObj)->hitPoints = 0;
        ((BaddieState *)playerObj)->hasTarget = 0;
        (*gPlayerInterface)->setState((void*)obj, (void*)playerObj, 0);
        hitState = (ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x80;
        GameBit_Set(GAMEBIT_DIM2_ICICLE_DEFEATED, 1);
        if (((GroundBaddieState *)state)->targetState == 1) {
          GameBit_Set(GAMEBIT_DIM2_ICICLE_PHASE1_WIN, 1);
        }
        else if (((GroundBaddieState *)state)->targetState == 2) {
          GameBit_Set(GAMEBIT_DIM2_ICICLE_PHASE2_WIN, 1);
        }
      }
      else if (((GroundBaddieState *)state)->targetState == 1) {
        (*gPlayerInterface)->setState((void*)obj, (void*)playerObj, 10);
      }
      else {
        (*gPlayerInterface)->setState((void*)obj, (void*)playerObj, 0xb);
      }
      ObjMsg_SendToObject(hitId, 0xe0001, obj, 0);
    }
  }
}

void DIM2icicle_updateCombatState(DIMbossObject *obj, ObjAnimUpdateState *animUpdate,
                                  DIMbossRuntime *runtime, DIMbossRuntime *updateRuntime)
{
  IcicleState *state;
  GameObject *gameObj;
  u8 *tricky;
  f32 timer;
  f32 limit;

  gameObj = (GameObject *)obj;
  state = (IcicleState *)runtime->topState;
  tricky = (u8 *)getTrickyObject();
  ObjHits_EnableObject((u32)obj);
  updateRuntime->effectActive = 1;
  ((void (*)(DIMbossObject *, DIMbossRuntime *, f32, int))*(VtableFn **)(*gBaddieControlInterface + 0x2c))(obj, updateRuntime, lbl_803E4C70, 1);
  ((void (*)(DIMbossObject *, DIMbossRuntime *, void *, int, u8 *, int, int, int))*(VtableFn **)(*gBaddieControlInterface + 0x54))
            (obj, updateRuntime, runtime->moveScratch, runtime->activeMoveId, &runtime->hitReactMode, 0, 0, 0);
  if (updateRuntime->scale == 6) {
    state->meltTimer =
         -(timeDelta * (lbl_803E4BC8 * obj->anim.currentMoveProgress + lbl_803E4C44) - state->meltTimer);
  }
  else {
    state->meltTimer = state->meltTimer - timeDelta;
  }
  if (state->meltTimer <= lbl_803E4BD8) {
    IcicleEntry *entry = (IcicleEntry *)gDim2IcicleMeltEntries;
    GameBit_Set(entry[state->index].bit, 1);
    state->meltTimer = *(f32 *)(gDim2IcicleMeltEntries + state->index * 8);
    state->index++;
    if (state->index > 0x17) {
      state->index = 0;
    }
  }
  if (tricky != NULL) {
    timer = state->lightTimer;
    if (timer > lbl_803E4BD8) {
      limit = gDim2IcicleLightDuration;
      if (timer <= limit) {
        state->lightTimer = timer + timeDelta;
        if (state->lightTimer >= limit) {
          ((void (*)(u8 *, int, int))*(VtableFn **)(*(int *)(*(int *)(tricky + 0x68)) + 0x34))(tricky, 1, (int)obj);
        }
      }
    }
    if (state->fadeTimer > (timer = lbl_803E4BD8)) {
      state->fadeTimer = state->fadeTimer + timeDelta;
      if (state->fadeTimer >= lbl_803E4BEC) {
        runtime->stateFlags &= ~DIMBOSS_STATE_FLAG_TARGET_TRICKY;
        state->fadeTimer = timer;
        ((void (*)(u8 *, int, int))*(VtableFn **)(*(int *)(*(int *)(tricky + 0x68)) + 0x34))(tricky, 0, 0);
        state->lightTimer = lbl_803E4C44;
      }
    }
    else if (runtime->phase == DIMBOSS_PHASE_LAUNCH_LIFT) {
      runtime->stateFlags |= DIMBOSS_STATE_FLAG_TARGET_TRICKY;
      state->fadeTimer = lbl_803E4C44;
      DIM2icicle_createStateLight((int)obj, 0);
    }
  }
  if (runtime->phase == DIMBOSS_PHASE_GAMEBIT_COUNT_MET) {
    DIM2icicle_createStateLight((int)obj, 1);
  }
  {
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_SPAWN_BLUE_WHITE_EFFECT) {
      gDIMbossSequenceFlags &= ~(u64)DIMBOSS_SEQUENCE_FLAG_SPAWN_BLUE_WHITE_EFFECT;
      DIM2icicle_spawnBlueWhiteEffect(&runtime->topState->blueWhiteEffectSource, runtime->topState->blueWhiteVelocity);
    }
  }
  if (runtime->stateFlags & DIMBOSS_STATE_FLAG_TARGET_TRICKY) {
    gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_TONSIL_GUARD_ACTIVE;
  }
  if (runtime->phase == DIMBOSS_PHASE_LAUNCH_LIFT) {
    ((void (*)(u8 *, int, int, int))*(VtableFn **)(*(int *)(*(int *)(tricky + 0x68)) + 0x28))(tricky, (int)obj, 1, 2);
    gameObj->hitVolumeIndex = 1;
  }
  else {
    gameObj->hitVolumeIndex = 2;
  }
  runtime->savedPendingParentObj = *(int *)&gameObj->pendingParentObj;
  *(int *)&gameObj->pendingParentObj = 0;
  (*gPlayerInterface)->update((void*)obj, updateRuntime, timeDelta, timeDelta,
                              gDIMbossHitDetectAnimTable, gDIMbossAnimTable);
  *(int *)&gameObj->pendingParentObj = runtime->savedPendingParentObj;
}
