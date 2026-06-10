#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/CR/CRsnowbike.h"
#include "main/mapEventTypes.h"
#include "main/screen_transition.h"

#include "global.h"

typedef struct ScMusictreeSpawnAmbientEffectPlacement {
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    u8 pad8[0x20 - 0x8];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 pad23[0x28 - 0x23];
} ScMusictreeSpawnAmbientEffectPlacement;


/* sc_levelcontrol_getExtraSize == 0x24 (CloudRunner race level control). */
typedef struct ScLevelControlState {
    f32 fogNear;    /* 0x00: enableHeavyFog base */
    f32 fog04;      /* 0x04 */
    f32 fog08;      /* 0x08 */
    f32 fog0C;      /* 0x0c */
    f32 timer10;    /* 0x10 */
    f32 fadeTimer;  /* 0x14 */
    u8 pad18[4];
    u8 musicStep;   /* 0x1c: index into the lbl_803DC060 cue table */
    u8 mode;        /* 0x1d: anim-event mode latch */
    u8 areaCell;    /* 0x1e: 0xff until the player enters map 0xe */
    u8 flags1F;     /* 0x1f */
    u8 musicTrack;  /* 0x20 */
    s8 unk21;       /* 0x21 */
    u8 flags22;     /* 0x22: SnowFlags22 overlay (bit 7) */
    u8 pad23;
} ScLevelControlState;
STATIC_ASSERT(sizeof(ScLevelControlState) == 0x24);


extern undefined8 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068d0();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern undefined4 FUN_80006c88();
extern undefined4 FUN_80017680();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern int FUN_80017a5c();
extern undefined4 FUN_80017a6c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern uint FUN_80017ae8();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_PollPriorityHitEffectWithCooldown();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80048000();
extern undefined4 FUN_8004800c();
extern undefined4 FUN_80053c98();
extern int FUN_8005b024();
extern undefined8 FUN_80080f14();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_80080f3c();
extern undefined4 FUN_80081110();
extern undefined4 FUN_8012e250();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801da7f8();

extern undefined4 DAT_803dccc8;
extern ScreenTransitionInterface **gScreenTransitionInterface;
extern undefined4* DAT_803dd6d8;
extern MapEventInterface **gMapEventInterface;
extern undefined4 DAT_803de878;
extern undefined4 DAT_803de880;
extern f32 lbl_803DC074;
extern f32 lbl_803E61C0;
extern f32 lbl_803E61C8;
extern f32 lbl_803E61CC;
extern f32 lbl_803E61D0;
extern f32 lbl_803E61D8;
extern f32 lbl_803E61DC;
extern f32 lbl_803E61E0;
extern f32 lbl_803E61E8;
extern f32 lbl_803E61EC;
extern f32 lbl_803E61F0;
extern f32 lbl_803E61F4;
extern f32 lbl_803E61F8;
extern f32 lbl_803E61FC;
extern f32 lbl_803E6200;
extern f32 lbl_803E6204;
extern f32 lbl_803E6208;
extern f32 lbl_803E620C;
extern f32 lbl_803E6210;
extern f32 lbl_803E6214;

/*
 * --INFO--
 *
 * Function: sh_emptytumblew_init
 * EN v1.0 Address: 0x801DAFDC
 * EN v1.0 Size: 1440b
 * EN v1.1 Address: 0x801DB048
 * EN v1.1 Size: 1080b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803E5540;
extern f32 lbl_803E5544;
extern f32 lbl_803E5548;
void sh_emptytumblew_init(s16 *p1, int p2)
{
    f32 fv;

    *(s16 *)((char *)p1 + 4) = (*(u8 *)(p2 + 0x18) - 0x7f) * 0x80;
    *(s16 *)((char *)p1 + 2) = (*(u8 *)(p2 + 0x19) - 0x7f) * 0x80;
    *(s16 *)((char *)p1 + 0) = *(u8 *)(p2 + 0x1a) << 8;
    *(f32 *)((char *)p1 + 8) = *(f32 *)(p2 + 0x1c);
    fv = *(f32 *)((char *)p1 + 8);
    ObjHitbox_SetCapsuleBounds(p1, (int)(lbl_803E5540 * fv), (int)(lbl_803E5544 * fv), (int)(lbl_803E5548 * fv));
    *(u16 *)((char *)p1 + 0xb0) |= 0x4000;
}


/*
 * --INFO--
 *
 * Function: FUN_801db580
 * EN v1.0 Address: 0x801DB580
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801DB594
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: sc_levelcontrol_processAnimEvents
 * EN v1.0 Address: 0x801DB670
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x801DB688
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 sc_levelcontrol_processAnimEvents(int param_1,undefined4 param_2,ObjAnimUpdateState *animUpdate)
{
  byte bVar2;
  byte eventId;
  uint uVar1;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)&((GameObject *)param_1)->extra;
  animUpdate->sequenceEventActive = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)animUpdate->eventCount; iVar3 = iVar3 + 1) {
    eventId = animUpdate->eventIds[iVar3];
    if (eventId == 2) {
      sc_levelcontrol_setAnimEventState(param_1,5);
    }
    else if (eventId < 2) {
      if (eventId != 0) {
        sc_levelcontrol_setAnimEventState(param_1,7);
      }
    }
    else if (eventId < 4) {
      ((ScLevelControlState *)iVar4)->flags1F = ((ScLevelControlState *)iVar4)->flags1F | 2;
    }
  }
  ((ScLevelControlState *)iVar4)->flags1F = ((ScLevelControlState *)iVar4)->flags1F | 1;
  FUN_80017698(0x60f,0);
  iVar3 = *(int *)&((GameObject *)param_1)->extra;
  FUN_80017a98();
  if (*(char *)(iVar3 + 0x1d) == '\x05') {
    FUN_80017698(0x60f,1);
    bVar2 = FUN_80006b44();
    if (bVar2 != 0) {
      uVar1 = FUN_80017690(0x7a);
      if (uVar1 != 0) {
        FUN_80017698(0x85,1);
      }
      ((ScLevelControlState *)iVar3)->timer10 = lbl_803E61E8;
      ((ScLevelControlState *)iVar3)->mode = 0;
      FUN_80006824(0,SFXsp_skeep_mumb1);
      FUN_800067c0((int *)0xef,0);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: sc_levelcontrol_setAnimEventState
 * EN v1.0 Address: 0x801DB7B4
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801DB7E8
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sc_levelcontrol_setAnimEventState(int param_1,undefined param_2)
{
  char cVar1;
  int iVar2;
  
  iVar2 = *(int *)&((GameObject *)param_1)->extra;
  ((ScLevelControlState *)iVar2)->mode = param_2;
  cVar1 = *(char *)&((ScLevelControlState *)iVar2)->mode;
  if (cVar1 == '\x02') {
    ((ScLevelControlState *)iVar2)->mode = 0;
  }
  else if (cVar1 == '\x05') {
    FUN_80017698(0x2b8,1);
    FUN_80017698(0x4bd,0);
    FUN_80017698(0x85,0);
    FUN_80006b54(0x1d,0x96);
    FUN_800067c0((int *)0xef,1);
    FUN_80006b50();
  }
  else if (cVar1 == '\x03') {
    FUN_80006b54(0x1d,0x3c);
    ((ScLevelControlState *)iVar2)->mode = 0;
    FUN_800067c0((int *)0xc7,1);
    FUN_80006b50();
  }
  else if (cVar1 == '\x06') {
    FUN_800067c0((int *)0xef,0);
    ((ScLevelControlState *)iVar2)->mode = 0;
    ((ScLevelControlState *)iVar2)->fadeTimer = lbl_803E61E8;
    FUN_80006b4c();
  }
  else if (cVar1 == '\x04') {
    ((ScLevelControlState *)iVar2)->mode = 0;
    FUN_800067c0((int *)0xc7,0);
    FUN_80006b4c();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801db8c4
 * EN v1.0 Address: 0x801DB8C4
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x801DB904
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801db924
 * EN v1.0 Address: 0x801DB924
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DB964
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on



/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void sc_levelcontrol_hitDetect(void) {}
void sc_levelcontrol_release(void) {}
void sc_levelcontrol_initialise(void) {}
void sc_musictree_free(void) {}
void sc_musictree_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int sc_levelcontrol_getExtraSize(void) { return 0x24; }
int sc_levelcontrol_getObjectTypeId(void) { return 0x0; }
int sc_musictree_getExtraSize(void) { return 0x50; }
int sc_musictree_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */
u8 sc_levelcontrol_getAnimEventState(int *obj) { return *(u8*)((char*)((int**)obj)[0xb8/4] + 0x1d); }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5554;
extern void objRenderFn_8003b8f4(f32);
void sc_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5554); }

extern void fn_8003B608(int a, int b, int c);
extern int ObjPath_GetPointWorldPosition(int obj, int idx, f32 *x, f32 *y, f32 *z, int p6);
extern f32 lbl_803E558C;
typedef struct SCMusicTreeState {
    int ambientEffect[3];
    f32 pathPoint[3][3];
    f32 proximityBurstTimer;
    f32 animSpeed;
    f32 scale;
    f32 proximityCooldown;
    f32 hitCooldown;
    int hitCooldownState;
    u16 hearRadius;
    s16 previousDistance;
    u8 flags;
    u8 pad4D[0x50 - 0x4D];
} SCMusicTreeState;

void sc_musictree_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    int *def = *(int **)&((GameObject *)obj)->anim.placementData;
    SCMusicTreeState *state = ((GameObject *)obj)->extra;
    int i;
    if (visible == 0) return;
    fn_8003B608((int)*(u8 *)((char *)def + 0x20), (int)*(u8 *)((char *)def + 0x21), (int)*(u8 *)((char *)def + 0x22));
    ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E558C);
    if ((state->flags & 0x80) != 0) {
        for (i = 0; i < 3; i++) {
            ObjPath_GetPointWorldPosition(obj, i,
                &state->pathPoint[0][0],
                &state->pathPoint[0][1],
                &state->pathPoint[0][2],
                0);
            state = (SCMusicTreeState *)((char *)state + 12);
        }
    }
    ((GameObject *)obj)->unkF8 = 1;
}

extern void gameTimerStop(void);
extern void disableHeavyFog(void);
extern void Music_Trigger(int track, int param);
void sc_levelcontrol_free(int obj) {
    gameTimerStop();
    disableHeavyFog();
    Music_Trigger(196, 0);
    Music_Trigger(54, 0);
    Music_Trigger(239, 0);
    Music_Trigger(34, 0);
    Music_Trigger(199, 0);
}

extern void GameBit_Set(int bit, int val);
extern int GameBit_Get(int bit);
extern void gameTimerInit(int a, int b);
extern void timerSetToCountUp(void);
extern int isGameTimerDisabled(void);
extern u8 *Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(int a, int b);
extern f32 lbl_803E5550;

int sc_levelcontrol_processAnimEventsCallback(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    int i;

    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < (int)(u32)animUpdate->eventCount; i++) {
        int eventId = animUpdate->eventIds[i];
        switch (eventId) {
        case 1:
            sc_levelcontrol_applyAnimEventState(obj, 7);
            break;
        case 2:
            sc_levelcontrol_applyAnimEventState(obj, 5);
            break;
        case 3:
            ((ScLevelControlState *)state)->flags1F |= 2;
            break;
        }
    }
    ((ScLevelControlState *)state)->flags1F |= 1;
    GameBit_Set(0x60f, 0);
    state = *(int *)&((GameObject *)obj)->extra;
    Obj_GetPlayerObject();
    if (((ScLevelControlState *)state)->mode == 5) {
        GameBit_Set(0x60f, 1);
        if (isGameTimerDisabled()) {
            if ((u32)GameBit_Get(0x7a) != 0) {
                GameBit_Set(0x85, 1);
            }
            ((ScLevelControlState *)state)->timer10 = lbl_803E5550;
            ((ScLevelControlState *)state)->mode = 0;
            Sfx_PlayFromObject(0, 0x10a);
            Music_Trigger(0xef, 0);
        }
    }
    return 0;
}

void sc_levelcontrol_applyAnimEventState(int obj, u8 scale)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    u8 v;

    ((ScLevelControlState *)state)->mode = scale;
    v = ((ScLevelControlState *)state)->mode;
    if (v == 2) {
        ((ScLevelControlState *)state)->mode = 0;
    } else if (v == 5) {
        GameBit_Set(0x2b8, 1);
        GameBit_Set(0x4bd, 0);
        GameBit_Set(0x85, 0);
        gameTimerInit(0x1d, 0x96);
        Music_Trigger(0xef, 1);
        timerSetToCountUp();
    } else if (v == 3) {
        gameTimerInit(0x1d, 0x3c);
        ((ScLevelControlState *)state)->mode = 0;
        Music_Trigger(199, 1);
        timerSetToCountUp();
    } else if (v == 6) {
        Music_Trigger(0xef, 0);
        ((ScLevelControlState *)state)->mode = 0;
        ((ScLevelControlState *)state)->fadeTimer = lbl_803E5550;
        gameTimerStop();
    } else if (v == 4) {
        ((ScLevelControlState *)state)->mode = 0;
        Music_Trigger(199, 0);
        gameTimerStop();
    }
}

extern void enableHeavyFog(f32 a, f32 b, f32 c, f32 d, f32 e, int f);
extern int mapGetDirIdx(int idx);
extern void unlockLevel(int a, int b, int c);
extern int getSaveGameLoadStatus(void);
extern f32 lbl_803E5580;
extern f32 lbl_803E5564;
extern f32 lbl_803E5568;
extern f32 lbl_803E5570;
extern f32 lbl_803E5574;
extern f32 lbl_803E5578;
extern f32 lbl_803E557C;
typedef struct { u8 bit7 : 1; u8 lo : 7; } SnowFlags22;
void sc_levelcontrol_init(int obj)
{
    ScLevelControlState *st = ((GameObject *)obj)->extra;
    int state = (int)st;
    f32 v;

    ((SnowFlags22 *)&((ScLevelControlState *)state)->flags22)->bit7 = 0;
    ((ScLevelControlState *)state)->areaCell = 0xff;
    ((ScLevelControlState *)state)->mode = 0;
    ((GameObject *)obj)->animEventCallback = (void *)sc_levelcontrol_processAnimEventsCallback;
    GameBit_Set(0x60f, 1);
    GameBit_Set(0x2b8, 0);
    GameBit_Set(0x4bd, 1);
    GameBit_Set(0x81, 0);
    GameBit_Set(0x82, 0);
    GameBit_Set(0x83, 0);
    GameBit_Set(0x84, 0);
    st->fog0C = lbl_803E5580;
    v = lbl_803E5564;
    st->fogNear = lbl_803E5564;
    st->fog04 = v;
    st->fog08 = lbl_803E5568;
    enableHeavyFog(lbl_803E5570 + st->fogNear, st->fogNear, lbl_803E5574, lbl_803E5578, lbl_803E557C, 0);
    if ((u32)GameBit_Get(0x7a) != 0) {
        GameBit_Set(0x85, 1);
    }
    unlockLevel(mapGetDirIdx(0xe), 0, 0);
    if (getSaveGameLoadStatus() != 0) {
        ((GameObject *)obj)->unkF4 = 2;
    } else {
        ((GameObject *)obj)->unkF4 = 1;
    }
    ((GameObject *)obj)->unkF8 = 1;
}

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int a, int b);
extern int randomGetRange(int lo, int hi);
extern int Obj_SetupObject(int setup, int a, int b, int c, int d);
void sc_musictree_spawnAmbientEffect(int obj, int p2, int p3, s8 idx)
{
    int def = *(int *)&((GameObject *)obj)->anim.placementData;
    SCMusicTreeState *state = (SCMusicTreeState *)p2;
    int setup;

    if (Obj_IsLoadingLocked() != 0) {
        setup = Obj_AllocObjectSetup(0x28, 0x210);
        *(u8 *)(setup + 4) = ((ScMusictreeSpawnAmbientEffectPlacement *)def)->unk4;
        *(u8 *)(setup + 6) = ((ScMusictreeSpawnAmbientEffectPlacement *)def)->unk6;
        *(u8 *)(setup + 5) = ((ScMusictreeSpawnAmbientEffectPlacement *)def)->unk5;
        *(u8 *)(setup + 7) = ((ScMusictreeSpawnAmbientEffectPlacement *)def)->unk7 - 10;
        ((ObjPlacement *)setup)->posX = state->pathPoint[idx][0];
        ((ObjPlacement *)setup)->posY = state->pathPoint[idx][1];
        ((ObjPlacement *)setup)->posZ = state->pathPoint[idx][2];
        *(u16 *)(setup + 0x1c) = randomGetRange(0x708, 0x1770);
        *(u16 *)(setup + 0x1e) = 1;
        *(u8 *)(setup + 0x20) = 10;
        *(u8 *)(setup + 0x21) = 40;
        *(u8 *)(setup + 0x22) = 50;
        *(u8 *)(setup + 0x23) = 10;
        *(u8 *)(setup + 0x24) = 50;
        *(s8 *)(setup + 0x25) = -50;
        *(s16 *)(setup + 0x26) = -1;
        *(int *)(setup + 0x18) = 0;
        state->ambientEffect[idx] = Obj_SetupObject(setup, 5, -1, -1, *(int *)&((GameObject *)obj)->anim.parent);
    }
}

extern f32 lbl_803E5588;
void sc_musictree_handleHitObject(int p1, int p2, int effectType)
{
    int id = *(int *)(*(int *)(p1 + 0x4c) + 0x14);
    SCMusicTreeState *state = (SCMusicTreeState *)p2;
    (void)effectType;

    switch (id) {
    case 0x30d9c:
        Sfx_PlayFromObject(p1, 299);
        Sfx_PlayFromObject(p1, 298);
        GameBit_Set(0x7d, 1);
        break;
    case 0x30d9d:
        Sfx_PlayFromObject(p1, 300);
        Sfx_PlayFromObject(p1, 298);
        GameBit_Set(0x7e, 1);
        break;
    case 0x30d9b:
        Sfx_PlayFromObject(p1, 0x12d);
        Sfx_PlayFromObject(p1, 298);
        GameBit_Set(0x7f, 1);
        break;
    case 0x448c2:
        if ((u32)GameBit_Get(0xc44) != 0)
            GameBit_Set(0xc41, 1);
        break;
    case 0x45178:
        if ((u32)GameBit_Get(0xc44) != 0)
            GameBit_Set(0xc43, 1);
        break;
    case 0x4517c:
        if ((u32)GameBit_Get(0xc44) != 0)
            GameBit_Set(0xc45, 1);
        break;
    }
    state->animSpeed = lbl_803E5588;
}

extern void skyFn_80088c94(int a, int b);
extern void envFxActFn_800887f8(int arg);
extern void getEnvfxActImmediately(void *obj, void *target, int animId, int flags);
extern void getEnvfxAct(void *obj, void *source, int effectId, int arg);
extern int  coordsToMapCell(f32 x, f32 z);
extern void gameTextShow(int id);
extern void skyFn_80088e54(int mode, f32 brightness);
extern void warpToMap(int mapId, int flag);
extern void timeListFn_8012df14(void);
extern void SCGameBitLatch_Update(int state, int a, int b, int c, int d, int e);
extern int *gSHthorntailAnimationInterface;
extern u16  lbl_803DC060[4];
extern f32  timeDelta;
extern f32  lbl_803E5558;
extern f32  lbl_803E555C;
extern f32  lbl_803E5560;
extern f32  lbl_803E556C;

/* EN v1.0 0x801DB3A8  size: 2732b  SnowBike Race level controller per-frame
 * driver: replays the env-fx set on map (re)entry, latches the race
 * GameBits, runs the two race countdown timers, eases the heavy fog level,
 * tracks the totem combo code (bits 0x7d..0x7f), and keeps the area music
 * in sync with the Thorntail animation state. */
void sc_levelcontrol_update(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    u8 *player = Obj_GetPlayerObject();

    if (((GameObject *)obj)->unkF4 != 0) {
        skyFn_80088c94(7, 0);
        envFxActFn_800887f8(0);
        if (((GameObject *)obj)->unkF4 == 2) {
            getEnvfxActImmediately(0, 0, 0x4f, 0);
            getEnvfxActImmediately(0, 0, 0x50, 0);
            getEnvfxActImmediately(0, 0, 0x245, 0);
            if ((*gMapEventInterface)->getAnimEvent(0xe, 5) != 0) {
                getEnvfxActImmediately(0, 0, 0x246, 0);
            } else {
                getEnvfxActImmediately(0, 0, 0x51, 0);
            }
        } else {
            getEnvfxAct(0, 0, 0x4f, 0);
            getEnvfxAct(0, 0, 0x50, 0);
            getEnvfxAct(0, 0, 0x245, 0);
            if ((*gMapEventInterface)->getAnimEvent(0xe, 5) != 0) {
                getEnvfxAct(0, 0, 0x246, 0);
            } else {
                getEnvfxAct(0, 0, 0x51, 0);
            }
        }
        ((GameObject *)obj)->unkF4 = 0;
    }
    if (((SnowFlags22 *)&((ScLevelControlState *)state)->flags22)->bit7 == 0 && (u32)GameBit_Get(0xc53) != 0) {
        (*gMapEventInterface)->setAnimEvent(0xe, 0xa, 1);
        ((SnowFlags22 *)&((ScLevelControlState *)state)->flags22)->bit7 = 1;
    }
    if (((ScLevelControlState *)state)->areaCell != 0xe) {
        if (coordsToMapCell(((GameObject *)player)->anim.localPosX, ((GameObject *)player)->anim.localPosZ) == 0xe) {
            u8 c = ((int (*)(s32))(*gMapEventInterface)->getMode)(0xe);
            Obj_GetPlayerObject();
            switch (c) {
            case 1:
                if ((u32)GameBit_Get(0x5f3) != 0) {
                    (*gMapEventInterface)->setMode(0xe, 2);
                }
                break;
            case 2:
            case 3:
            case 4:
            case 5:
                if ((u32)GameBit_Get(0x2d0) != 0) {
                    (*gMapEventInterface)->setMode(0xe, 6);
                }
                break;
            }
        } else {
            return;
        }
    }
    if (((ScLevelControlState *)state)->fadeTimer != lbl_803E5558) {
        if ((((GameObject *)player)->objectFlags & 0x1000) == 0) {
            f32 lim;
            if (lbl_803E5550 == ((ScLevelControlState *)state)->fadeTimer) {
                (*gScreenTransitionInterface)->start(0x73, 1);
            }
            ((ScLevelControlState *)state)->fadeTimer -= timeDelta;
            if (((ScLevelControlState *)state)->fadeTimer <= (lim = lbl_803E5558)) {
                ((ScLevelControlState *)state)->fadeTimer = lim;
                ((ScLevelControlState *)state)->timer10 = lim;
                GameBit_Set(0x2b8, 0);
                GameBit_Set(0x4bd, 1);
                GameBit_Set(0x81, 0);
                GameBit_Set(0x82, 0);
                GameBit_Set(0x83, 0);
                GameBit_Set(0x84, 0);
                GameBit_Set(0x63e, 1);
                GameBit_Set(0x7cf, 1);
            }
        }
    } else if (((ScLevelControlState *)state)->timer10 != lbl_803E5558) {
        if ((((GameObject *)player)->objectFlags & 0x1000) == 0) {
            if (lbl_803E5550 == ((ScLevelControlState *)state)->timer10) {
                (*gScreenTransitionInterface)->start(0x73, 1);
            }
            ((ScLevelControlState *)state)->timer10 -= timeDelta;
            if (((ScLevelControlState *)state)->timer10 <= *(f32 *)&lbl_803E5558) {
                GameBit_Set(0x640, 1);
                ((ScLevelControlState *)state)->timer10 = lbl_803E5558;
                GameBit_Set(0x2b8, 0);
                GameBit_Set(0x4bd, 1);
                GameBit_Set(0x81, 0);
                GameBit_Set(0x82, 0);
                GameBit_Set(0x83, 0);
                GameBit_Set(0x84, 0);
            }
        }
    }
    ((ScLevelControlState *)state)->areaCell = coordsToMapCell(((GameObject *)player)->anim.localPosX, ((GameObject *)player)->anim.localPosZ);
    if ((u32)GameBit_Get(0xcdc) != 0) {
        if (((ScLevelControlState *)state)->fog0C > lbl_803E5558) {
            gameTextShow(0x429);
            ((ScLevelControlState *)state)->fog0C -= timeDelta;
            if (((ScLevelControlState *)state)->fog0C < *(f32 *)&lbl_803E5558) {
                ((ScLevelControlState *)state)->fog0C = lbl_803E5558;
            }
        }
        if ((*gMapEventInterface)->getAnimEvent(0xe, 1) != 0) {
            ((ScLevelControlState *)state)->fog04 = lbl_803E555C;
            ((ScLevelControlState *)state)->fog08 = lbl_803E5560;
        } else if ((*gMapEventInterface)->getAnimEvent(0xe, 5) != 0) {
            ((ScLevelControlState *)state)->fog04 = lbl_803E5564;
            ((ScLevelControlState *)state)->fog08 = lbl_803E5568;
            if (((GameObject *)obj)->unkF8 != 0) {
                skyFn_80088e54(1, lbl_803E5554);
                ((GameObject *)obj)->unkF8 = 0;
            }
        } else {
            ((ScLevelControlState *)state)->fog04 = lbl_803E555C;
            ((ScLevelControlState *)state)->fog08 = lbl_803E5560;
        }
    } else {
        ((ScLevelControlState *)state)->fog04 = lbl_803E556C;
        ((ScLevelControlState *)state)->fog08 = lbl_803E5568;
    }
    if (((ScLevelControlState *)state)->fog04 != *(f32 *)state) {
        *(f32 *)state = ((ScLevelControlState *)state)->fog08 * timeDelta + *(f32 *)state;
        if (((ScLevelControlState *)state)->fog08 < lbl_803E5558) {
            if (*(f32 *)state < ((ScLevelControlState *)state)->fog04) {
                *(f32 *)state = ((ScLevelControlState *)state)->fog04;
            }
        } else {
            if (*(f32 *)state > ((ScLevelControlState *)state)->fog04) {
                *(f32 *)state = ((ScLevelControlState *)state)->fog04;
            }
        }
        enableHeavyFog(lbl_803E5570 + *(f32 *)state, *(f32 *)state, lbl_803E5574, lbl_803E5578,
                       lbl_803E557C, 0);
    }
    if ((u32)GameBit_Get(0x7d) != 0) {
        GameBit_Set(0x7d, 0);
        if (lbl_803DC060[((ScLevelControlState *)state)->musicStep] == 0x7d) {
            ((ScLevelControlState *)state)->musicStep += 1;
        } else {
            ((ScLevelControlState *)state)->musicStep = 0;
        }
    } else if ((u32)GameBit_Get(0x7e) != 0) {
        GameBit_Set(0x7e, 0);
        if (lbl_803DC060[((ScLevelControlState *)state)->musicStep] == 0x7e) {
            ((ScLevelControlState *)state)->musicStep += 1;
        } else {
            ((ScLevelControlState *)state)->musicStep = 0;
        }
    } else if ((u32)GameBit_Get(0x7f) != 0) {
        GameBit_Set(0x7f, 0);
        if (lbl_803DC060[((ScLevelControlState *)state)->musicStep] == 0x7f) {
            ((ScLevelControlState *)state)->musicStep += 1;
        } else {
            ((ScLevelControlState *)state)->musicStep = 0;
        }
    }
    if (((ScLevelControlState *)state)->musicStep >= 3) {
        GameBit_Set(0x80, 1);
        ((ScLevelControlState *)state)->musicStep = 0;
    }
    if ((((ScLevelControlState *)state)->flags1F & 1) != 0) {
        ((ScLevelControlState *)state)->flags1F &= ~1;
        GameBit_Set(0x60f, 1);
        if ((u32)GameBit_Get(0x7a) == 0) {
            if ((u32)GameBit_Get(0x627) != 0 && (u32)GameBit_Get(0x63e) != 0) {
                GameBit_Set(0x61c, 1);
            }
        } else {
            if ((u32)GameBit_Get(0x61c) != 0) {
                GameBit_Set(0x85, 1);
            }
        }
    }
    if (((ScLevelControlState *)state)->mode == 0) {
        if ((u32)GameBit_Get(0x60e) != 0) {
            GameBit_Set(0x60e, 0);
            timeListFn_8012df14();
        }
    } else if (((ScLevelControlState *)state)->mode == 5) {
        if ((u32)GameBit_Get(0x60e) != 0) {
            GameBit_Set(0x60e, 0);
            gameTimerStop();
            if ((u32)GameBit_Get(0x7a) != 0) {
                GameBit_Set(0x85, 1);
            }
            ((ScLevelControlState *)state)->timer10 = lbl_803E5550;
            (*gScreenTransitionInterface)->start(0x73, 1);
            ((ScLevelControlState *)state)->mode = 0;
            Sfx_PlayFromObject(0, 0x10a);
        }
    }
    if ((u32)GameBit_Get(0x647) != 0) {
        GameBit_Set(0x612, 1);
        GameBit_Set(0x90b, 1);
        GameBit_Set(0x87, 1);
    }
    if ((u32)GameBit_Get(0xbde) != 0) {
        GameBit_Set(0x2c6, 1);
        GameBit_Set(0x2ce, 1);
        GameBit_Set(0xbdc, 1);
    }
    if ((u32)GameBit_Get(0xbe5) != 0) {
        GameBit_Set(0xbdf, 1);
        GameBit_Set(0xbe1, 1);
        GameBit_Set(0xbe3, 1);
    }
    {
        int state2 = *(int *)&((GameObject *)obj)->extra;
        Obj_GetPlayerObject();
        if (((ScLevelControlState *)state2)->mode == 5) {
            GameBit_Set(0x60f, 1);
            if (isGameTimerDisabled()) {
                if ((u32)GameBit_Get(0x7a) != 0) {
                    GameBit_Set(0x85, 1);
                }
                ((ScLevelControlState *)state2)->timer10 = lbl_803E5550;
                ((ScLevelControlState *)state2)->mode = 0;
                Sfx_PlayFromObject(0, 0x10a);
                Music_Trigger(0xef, 0);
            }
        }
    }
    if ((u32)GameBit_Get(0x4d0) == 0) {
        if ((u32)GameBit_Get(0x2b5) != 0) {
            GameBit_Set(0x4d0, 1);
            (*gMapEventInterface)->setAnimEvent(0xe, 2, 1);
            warpToMap(0x50, 0);
            (*gMapEventInterface)->setAnimEvent(0xe, 1, 0);
        }
    }
    if ((*(int (**)(int))((char *)*gSHthorntailAnimationInterface + 0x24))(0) != 0) {
        if (((ScLevelControlState *)state)->musicTrack != 0x2d) {
            ((ScLevelControlState *)state)->musicTrack = 0x2d;
            Music_Trigger(0x2d, 1);
        }
        if (((ScLevelControlState *)state)->unk21 != -1) {
            ((ScLevelControlState *)state)->unk21 = -1;
            Music_Trigger(0x22, 0);
        }
    } else {
        if (((ScLevelControlState *)state)->musicTrack != 0x33) {
            ((ScLevelControlState *)state)->musicTrack = 0x33;
            Music_Trigger(0x33, 1);
        }
        if (((ScLevelControlState *)state)->unk21 != 0x22) {
            ((ScLevelControlState *)state)->unk21 = 0x22;
            Music_Trigger(0x22, 1);
        }
    }
    SCGameBitLatch_Update(state + 0x18, 1, -1, -1, 0xe1e, 0x36);
    SCGameBitLatch_Update(state + 0x18, 2, -1, -1, 0xcbb, 0xc4);
    if ((((ScLevelControlState *)state)->flags1F & 2) != 0) {
        GameBit_Set(0x60e, 1);
        ((ScLevelControlState *)state)->flags1F &= ~2;
    }
}
