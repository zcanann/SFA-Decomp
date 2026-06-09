#include "main/mapEvent.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "main/dll/ped.h"
#include "main/dll/dimtruthhornice.h"

extern uint GameBit_Get(int eventId);
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern void Sfx_RemoveLoopedObjectSound(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void ObjHits_DisableObject(int obj);
extern void ObjHits_EnableObject(int obj);
extern void GameBit_Set(int eventId, int value);
extern void objAudioFn_8006ef38(int obj, void *events, int pointCount, void *points,
                                void *scratch, f32 scaleX, f32 scaleZ);

extern ObjectTriggerInterface **gObjectTriggerInterface;
extern f32 lbl_803E520C;
extern f32 lbl_803E5210;

void fn_801CDF94(int obj, int state, int flag);

typedef struct TreeBirdState {
  s16 gameBit;
  s16 triggerId;
  s16 immediateTrigger;
  u8 triggerLatched;
  u8 searchDelay;
  void *targetObj;
} TreeBirdState;

/*
 * --INFO--
 *
 * Function: treebird_init
 * EN v1.0 Address: 0x801CDBEC
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x801CDC2C
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void treebird_init(int obj,int setup)
{
  TreeBirdState *state;

  state = ((GameObject *)obj)->extra;
  ((GameObject *)obj)->animEventCallback = (void *)TreeBird_SeqFn;
  *(s16 *)obj = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
  ((GameObject *)obj)->anim.rotY = *(s16 *)(setup + 0x1a);
  ((GameObject *)obj)->anim.rotZ = *(s16 *)(setup + 0x1c);
  state->triggerId = (s16)(s8)*(u8 *)(setup + 0x19);
  state->gameBit = *(s16 *)(setup + 0x1e);
  if (GameBit_Get((int)state->gameBit) != 0) {
    state->immediateTrigger = 0x154;
  }
  state->searchDelay = 4;
}

/*
 * --INFO--
 *
 * Function: nw_geyser_init
 * EN v1.0 Address: 0x801CDE50
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void nw_geyser_init(int obj)
{
  ((GameObject *)obj)->objectFlags = (ushort)(((GameObject *)obj)->objectFlags | 0x6000);
  ((GameObject *)obj)->animEventCallback = (void *)NW_geyser_SeqFn;
}

char *fn_801CDE70(int *obj) { return *(char **)&((GameObject *)obj)->extra + 0xc; }

extern MapEventInterface **gMapEventInterface;
void nw_geyser_free(int *obj) {
    (*gMapEventInterface)->setAnimEvent(*(s8*)((char*)obj + 0xac), 0x1f, 0);
}

void nw_geyser_update(int obj)
{
    if (GameBit_Get(0xa) != 0) {
        ((GameObject *)obj)->anim.flags = OBJANIM_FLAG_HIDDEN;
        ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x8000);
        Sfx_RemoveLoopedObjectSound(obj, 0x372);
        Sfx_RemoveLoopedObjectSound(obj, 0x373);
        ObjHits_DisableObject(obj);
        GameBit_Set(0x398, 1);
    } else {
        Sfx_AddLoopedObjectSound(obj, 0x372);
        Sfx_AddLoopedObjectSound(obj, 0x373);
        (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
        ObjHits_EnableObject(obj);
    }
}

extern int objFindTexture(int *obj, int idx, int p3);
extern f32 lbl_803E5200;
extern f32 timeDelta;

int NW_geyser_SeqFn(int *obj, int p2, void *p3) {
    int *tex0;
    if (GameBit_Get(0xa) != 0) {
        *(u8 *)((char *)p3 + 0x90) = (u8)(*(u8 *)((char *)p3 + 0x90) | 4);
    }
    tex0 = (int *)objFindTexture(obj, 0, 0);
    objFindTexture(obj, 1, 0);
    *(s16 *)((char *)tex0 + 0xa) = (s16)(*(s16 *)((char *)tex0 + 0xa) + (s32)(lbl_803E5200 * timeDelta));
    if (*(s16 *)((char *)tex0 + 0xa) > 0x4e80) {
        *(s16 *)((char *)tex0 + 0xa) -= 0x4e80;
    }
    *(s16 *)((char *)p3 + 0x6e) = (s16)(*(s16 *)((char *)p3 + 0x70) & ~0x40);
    *(u8 *)((char *)p3 + 0x56) = 0;
    return 0;
}

int fn_801CDE7C(int obj, int param_2, u8 *seqData)
{
    u8 *state;
    void *audioEvents;
    void *audioPoints;
    void *audioScratch;
    f32 audioScale;

    (void)param_2;

    state = ((GameObject *)obj)->extra;
    if ((state[0x43c] & 0x20) == 0) {
        Sfx_StopObjectChannel(obj, 0x7f);
        *(f32 *)(state + 0x54) = lbl_803E520C;
        state[0x43c] = (u8)(state[0x43c] & ~0x10);
        state[0x43c] = (u8)(state[0x43c] | 0x20);
    }
    if ((state[0x43c] & 4) != 0) {
        *(f32 *)(state + 0x18) = lbl_803E520C;
        *(s16 *)(seqData + 0x6e) = (s16)(*(s16 *)(seqData + 0x6e) & ~8);
        *(s16 *)(seqData + 0x6e) = (s16)(*(s16 *)(seqData + 0x6e) & ~0x40);
        fn_801CDF94(obj, (int)state, 1);
    }
    audioEvents = state + 0x440;
    audioPoints = state + 0x45c;
    audioScratch = state + 0x16c;
    audioScale = lbl_803E5210;
    objAudioFn_8006ef38(obj, audioEvents, 8, audioPoints, audioScratch,
                        audioScale, audioScale);
    if (seqData[0x8b] != 0) {
        ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags & ~0x400);
        ((GameObject *)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
    }
    return 0;
}

extern void fn_8003A168(int obj, void* p);
extern void fn_8003B228(int obj, void* p);
extern void fn_8003A230(int obj, void* p, f32 f);
extern void characterDoEyeAnims(int obj, void* p);
extern u8 lbl_803268B4[];
extern f32 lbl_803E5214;

void fn_801CDF94(int obj, int state, int flag)
{
    if (flag != 0 && *(void**)(state + 0x28) != NULL && *(f32*)(state + 0x18) < lbl_803E5214) {
        *(u8*)(state + 0x40c) = 1;
        *(f32*)(state + 0x410) = *(f32*)(*(int*)(state + 0x28) + 0xc);
        *(f32*)(state + 0x414) = *(f32*)(*(int*)(state + 0x28) + 0x10);
        *(f32*)(state + 0x418) = *(f32*)(*(int*)(state + 0x28) + 0x14);
    } else {
        *(u8*)(state + 0x40c) = 0;
    }
    if ((lbl_803268B4[*(u8*)(state + 0x408)] & 0x2) != 0) {
        fn_8003A168(obj, (void*)(state + 0x40c));
        fn_8003B228(obj, (void*)(state + 0x40c));
    } else {
        fn_8003A230(obj, (void*)(state + 0x40c), lbl_803E520C);
        characterDoEyeAnims(obj, (void*)(state + 0x40c));
    }
}
