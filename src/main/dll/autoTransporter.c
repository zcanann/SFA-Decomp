#include "main/dll/autoTransporter.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "global.h"

/*
 * Per-object extra state for the doorf4 auto door
 * (doorf4_getExtraSize == 0x24).
 */
typedef struct DoorF4State {
    f32 cosYaw; /* cos/sin of spawn yaw; door plane normal */
    f32 sinYaw;
    f32 planeD; /* -(cos*x + sin*z) plane offset */
    f32 openRange; /* per-type approach distance */
    int gameBitA; /* params+0x1E; open latch */
    int gameBitB; /* per-type (68/152/-1) secondary gate */
    int unk18; /* params+0x20 */
    u16 sfxOpen; /* 830 for types 318/890 */
    u16 sfxClose; /* 831 */
    u8 active; /* gamebit-derived open state */
    u8 triggerLatch;
    u8 toggled;
    u8 pad23;
} DoorF4State;

STATIC_ASSERT(sizeof(DoorF4State) == 0x24);

/*
 * Per-object extra state for the sidekick (Tricky) ball
 * (sidekickball_getExtraSize == 0x2CC). Only locally-evidenced
 * fields are named.
 */
#include "main/dll/sidekickball_state.h"

typedef struct Doorf4State {
    u8 pad0[0x1C - 0x0];
    u16 unk1C;
    u8 pad1E[0x24 - 0x1E];
} Doorf4State;



extern undefined4 FUN_80006728();
extern bool FUN_800067f8();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern void* FUN_800069a8();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern int FUN_80017a98();
extern int FUN_80017b00();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Peek();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToNearbyObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80081110();
extern int FUN_801778e0();
extern uint FUN_80286830();
extern undefined4 FUN_8028687c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint countLeadingZeros();

extern ObjectTriggerInterface **gObjectTriggerInterface;
extern f64 DOUBLE_803e42d8;
extern f32 lbl_803DC074;
extern f32 lbl_803E42B0;
extern f32 lbl_803E42B8;
extern f32 lbl_803E42C8;
extern f32 lbl_803E42CC;
extern f32 lbl_803E42D0;
extern f32 lbl_803E42E0;
extern f32 lbl_803E42EC;
extern f32 lbl_803E42F0;
extern f32 lbl_803E42F4;
extern f32 lbl_803E42F8;
extern f32 lbl_803E42FC;
extern f32 lbl_803E4300;
extern f32 lbl_803E4304;
extern f32 lbl_803E4308;
extern f32 lbl_803E430C;
extern f32 lbl_803E431C;

/*
 * --INFO--
 *
 * Function: FUN_80178338
 * EN v1.0 Address: 0x80178338
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80178648
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_80178338(undefined4 param_1)
{
  float local_18;
  float local_14;
  float local_10;
  
  local_18 = lbl_803E42B0;
  local_14 = lbl_803E42B8;
  local_10 = lbl_803E42B0;
  FUN_80081110(param_1,2,0,0,&local_18);
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_801799bc
 * EN v1.0 Address: 0x801799BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017967C
 * EN v1.1 Size: 468b
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
 * Function: FUN_801799c0
 * EN v1.0 Address: 0x801799C0
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80179850
 * EN v1.1 Size: 20b
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
void doorf4_hitDetect(void) {}
void doorf4_release(void) {}
void doorf4_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int doorf4_getExtraSize(void) { return 0x24; }
int doorf4_getObjectTypeId(void) { return 0x1; }
int sidekickball_getExtraSize(void) { return 0x2cc; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3680;
extern void objRenderFn_8003b8f4(f32);
void doorf4_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3680); }

int fn_801793A4(int *obj) { return *((u8*)((int**)obj)[0xb8/4] + 0x274) == 0; }

void sidekickball_free(int obj) { GameBit_Set(0x3F8, 1); }

extern int Sfx_IsPlayingFromObject(int obj, int sfxId);
extern void Sfx_StopFromObject(int obj, int sfxId);
void doorf4_free(int obj) {
    int *state = ((GameObject *)obj)->extra;
    if (((Doorf4State *)state)->unk1C != 0) {
        if (Sfx_IsPlayingFromObject(obj, ((Doorf4State *)state)->unk1C) != 0) {
            Sfx_StopFromObject(obj, ((Doorf4State *)state)->unk1C);
        }
    }
    ObjGroup_RemoveObject(obj, 14);
}

extern f32 lbl_803E36A0;
void sidekickball_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    if (((GameObject *)obj)->moveF8 == 0 || visible == -1) {
        objRenderFn_8003b8f4(lbl_803E36A0);
    }
}

extern f32 lbl_803E369C;
extern void ObjHits_DisableObject(int* obj);
extern void ObjHits_EnableObject(int* obj);
extern void ObjHits_SyncObjectPositionIfDirty(int* obj);

void fn_8017962C(int* obj)
{
    SidekickBallState* state = ((GameObject *)obj)->extra;
    u8 b = state->ballMode;
    if (b != 3 && b != 2) return;
    state->fadeTimer = lbl_803E369C;
}

int fn_80179650(int* obj)
{
    int r = 0;
    u8 b = (*(SidekickBallState**)&((GameObject *)obj)->extra)->ballMode;
    if (b == 2 || b == 1) r = 1;
    return r;
}

void fn_80179678(int* obj)
{
    SidekickBallState* state = ((GameObject *)obj)->extra;
    state->fadeTimer = lbl_803E369C;
    state->ballMode = 0;
    ObjHits_DisableObject(obj);
    state->unk25B = 0;
}

void fn_801796BC(int* obj, f32 a, f32 b, f32 c)
{
    SidekickBallState* state = ((GameObject *)obj)->extra;
    state->ballMode = 3;
    state->fadeTimer = lbl_803E369C;
    *(f32*)((char*)obj + 36) = a;
    ((GameObject *)obj)->anim.velocityY = b;
    ((GameObject *)obj)->anim.velocityZ = c;
    ObjHits_EnableObject(obj);
    ObjHits_SyncObjectPositionIfDirty(obj);
    state->unk25B = 1;
    state->launchX = ((GameObject *)obj)->anim.localPosX;
    state->launchY = ((GameObject *)obj)->anim.localPosY;
    state->launchZ = ((GameObject *)obj)->anim.localPosZ;
}

extern int *Obj_GetPlayerObject(void);
extern void getYButtonItem(s16 *out);
extern u32 getButtonsJustPressed(int controller);
extern int fn_80295BF0(int *player);
extern int fn_8029669C(int *player);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void vecRotateZXY(void *inParams, f32 *outVec);
/* extern void ObjMsg_SendToObject(int *target, int msg, int *src, int p4); -- already declared */
extern f32 lbl_803E3688;
extern f32 lbl_803E368C;
extern f32 lbl_803E3690;
extern f32 lbl_803E3694;
extern f32 lbl_803E3698;
extern f32 lbl_803E36A4;

void trickyBallFn_801793b8(int *obj, u8 *params)
{
    int *player;
    int *playerState;
    s16 yItem;
    u32 btns;
    f32 lcl[6];

    player = Obj_GetPlayerObject();
    playerState = ((GameObject *)player)->extra;

    if (params[0x2c8] == 1) goto end;

    if (params[0x2c9] == 0) {
        params[0x2c9] = 1;
        if (params[0x2c9] == 0) goto end;
        params[0x2ca] = 1;
        goto end;
    }

    ObjHits_DisableObject(obj);
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;

    getYButtonItem(&yItem);
    btns = getButtonsJustPressed(0);
    if ((btns & 0x100) != 0 || (yItem == 5 && (getButtonsJustPressed(0) & 0x800) != 0)) {
        if (fn_80295BF0(player) != 0) {
            params[0x2ca] = 0;
        } else {
            Sfx_PlayFromObject(0, 0x10a);
        }
    }

    if (((GameObject *)obj)->moveF8 == 1) {
        params[0x2c9] = 2;
    }
    if (params[0x2c9] != 2) goto end;
    if (((GameObject *)obj)->moveF8 != 0) goto end;

    if (fn_8029669C(player) == 0) {
        params[0x2c9] = 0;
        params[0x2ca] = 0;
        *(f32 *)((char *)params + 0x26c) = lbl_803E36A4;
        params[0x274] = 5;
        goto end;
    }

    params[0x2c9] = 0;
    params[0x2c8] = 1;

    {
        f32 k = lbl_803E3688;
        ((GameObject *)obj)->anim.velocityY =
            k * (lbl_803E3690 * *(f32 *)((char *)playerState + 0x298) + lbl_803E368C);
        ((GameObject *)obj)->anim.velocityZ =
            k * (lbl_803E3698 * *(f32 *)((char *)playerState + 0x298) + lbl_803E3694);
    }

    ((GameObject *)lcl)->anim.localPosX = lbl_803E369C;
    ((GameObject *)lcl)->anim.localPosY = lbl_803E369C;
    ((GameObject *)lcl)->anim.localPosZ = lbl_803E369C;
    ((GameObject *)lcl)->anim.rootMotionScale = lbl_803E36A0;
    ((GameObject *)lcl)->anim.rotZ = 0;
    ((GameObject *)lcl)->anim.rotY = 0;
    if (((GameObject *)player)->anim.parent != NULL) {
        *(s16 *)lcl = (s16)(*(s16 *)*(int **)&((GameObject *)player)->anim.parent + *(s16 *)player);
    } else {
        *(s16 *)lcl = *(s16 *)player;
    }
    vecRotateZXY(lcl, &((GameObject *)obj)->anim.velocityX);

    fn_801796BC(obj,
                ((GameObject *)obj)->anim.velocityX,
                ((GameObject *)obj)->anim.velocityY,
                ((GameObject *)obj)->anim.velocityZ);

end:
    if (params[0x2ca] != 0) {
        ObjMsg_SendToObject(player, 0x100010, obj, 0);
    }
}

extern u32 GameBit_Get(int eventId);
void doorf4_update(int *obj)
{
    DoorF4State *state = ((GameObject *)obj)->extra;
    state->triggerLatch = 0;
    if (((GameObject *)obj)->countF4 == 0) {
        int *src = *(int **)&((GameObject *)obj)->anim.placementData;
        s16 type;
        ((GameObject *)obj)->anim.localPosX = ((ObjPlacement *)src)->posX;
        ((GameObject *)obj)->anim.localPosY = ((ObjPlacement *)src)->posY;
        ((GameObject *)obj)->anim.localPosZ = ((ObjPlacement *)src)->posZ;
        *(s16 *)obj = (s16)((s8) * (s8 *)((char *)src + 0x18) << 8);
        type = ((GameObject *)obj)->anim.seqId;
        if (type == 0x151) {
            if (GameBit_Get(state->gameBitA) != 0) {
                (*gObjectTriggerInterface)->preempt((int)obj, 0x75);
                state->triggerLatch = 1;
            }
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        } else if (type == 0x37a) {
            if (GameBit_Get(state->gameBitA) != 0) {
                (*gObjectTriggerInterface)->preempt((int)obj, 0x8a);
                state->triggerLatch = 1;
            }
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        } else {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
        ((GameObject *)obj)->countF4 = 1;
    }
}

extern f32 lbl_803E3654;
extern f32 lbl_803E3684;
extern f32 lbl_803E364C;
extern f32 lbl_803E3650;
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

void doorf4_init(int *obj, int *params)
{
    DoorF4State *state = ((GameObject *)obj)->extra;
    s16 type;

    ObjMsg_AllocQueue(obj, 4);
    *(s16 *)obj = (s16)((s8) * (s8 *)((char *)params + 0x18) << 8);
    ((GameObject *)obj)->animEventCallback = (void *)doorf4_SeqFn;
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    ((GameObject *)obj)->objectFlags |= 0x6000;
    state->gameBitA = *(s16 *)((char *)params + 0x1e);
    state->unk18 = *(s16 *)((char *)params + 0x20);
    state->openRange = lbl_803E3654;

    type = ((GameObject *)obj)->anim.seqId;
    switch (type) {
    case 193:
    case 196:
        state->gameBitB = 68;
        break;
    case 283:
        state->gameBitB = 152;
        break;
    case 318:
    case 890:
        *(s16 *)&state->sfxOpen = 830;
        *(s16 *)&state->sfxClose = 831;
        break;
    case 200:
        state->openRange = lbl_803E3684;
        break;
    default:
        state->gameBitB = -1;
    }

    ObjGroup_AddObject(obj, 14);

    state->cosYaw = mathSinf(lbl_803E364C * (f32)(int)*(s16 *)obj / lbl_803E3650);
    state->sinYaw = mathCosf(lbl_803E364C * (f32)(int)*(s16 *)obj / lbl_803E3650);
    state->planeD = -(state->cosYaw * ((GameObject *)obj)->anim.localPosX +
                      state->sinYaw * ((GameObject *)obj)->anim.localPosZ);
}


extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
extern f32 sqrtf(f32 x);
extern f32 *Camera_GetCurrentViewSlot(void);
extern void getEnvfxAct(int obj, int target, int id, int p);
extern f32 lbl_803E3648;
extern f32 lbl_803E3658;
extern f32 lbl_803E365C;
extern f32 lbl_803E3660;
extern f32 lbl_803E3664;
extern f32 lbl_803E3668;
extern f32 lbl_803E366C;
extern f32 lbl_803E3670;
extern f32 lbl_803E3674;

int doorf4_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate) {
    int msg;
    int objCount;
    int objIdx;
    int *other;
    int gb;
    int active;
    int *list;
    int *player;
    int i;
    u8 *def;
    DoorF4State *sub;
    int **walk;
    f32 *vs;
    u8 ev;
    f32 ang;
    f32 dist;
    f32 sd;
    f32 s;
    f32 dx;
    f32 dy;
    f32 thr;
    u8 *seq;

    seq = (u8 *)animUpdate;
    def = *(u8 **)&((GameObject *)obj)->anim.placementData;
    sub = ((GameObject *)obj)->extra;
    sd = lbl_803E3648;
    list = ObjList_GetObjects(&objIdx, &objCount);
    animUpdate->sequenceEventActive = 0;
    player = Obj_GetPlayerObject();
    dx = ((GameObject *)player)->anim.localPosX - ((ObjPlacement *)def)->posX;
    dy = ((GameObject *)player)->anim.localPosZ - ((ObjPlacement *)def)->posZ;
    dist = sqrtf(dx * dx + dy * dy);
    if (sub->gameBitA == -1) {
        gb = 1;
    } else {
        gb = GameBit_Get(sub->gameBitA);
    }
    if (ObjMsg_Peek(obj, &msg, 0, 0) != 0) {
        switch (msg) {
        case 0x30002:
            *(u8 *)&sub->active = 1;
            break;
        case 0x30003:
            *(u8 *)&sub->active = 0;
            break;
        }
    }
    active = *(s8 *)&sub->active;
    switch (*(s8 *)(def + 0x19)) {
    case 6:
        if (gb != 0) {
            active = 1;
        }
        break;
    case 0:
        ang = (lbl_803E364C * (f32)(*(s8 *)(def + 0x18) << 8)) / lbl_803E3650;
        sd = mathSinf(ang);
        s = mathCosf(ang);
        sd = -(((ObjPlacement *)def)->posX * sd + ((ObjPlacement *)def)->posZ * s)
           + (sd * ((GameObject *)player)->anim.localPosX + s * ((GameObject *)player)->anim.localPosZ);
        thr = sub->openRange;
        if (dist < thr && gb != 0 && sd < thr && sd > -thr) {
            active = 1;
        }
        if (active != 0 && sub->toggled == 0) {
            if (((GameObject *)obj)->anim.seqId == 200) {
                if (GameBit_Get(0x57) != 0) {
                    getEnvfxAct(0, 0, 0x7f, 0);
                } else {
                    getEnvfxAct(0, 0, 0x7c, 0);
                }
            }
            sub->toggled = 1;
        } else if (active == 0 && sub->toggled == 1) {
            if (((GameObject *)obj)->anim.seqId == 200 && sd <= lbl_803E3648) {
                getEnvfxAct(0, 0, 0xe, 0);
            }
            sub->toggled = 0;
        }
        break;
    case 1:
        if (dist < lbl_803E3654 && gb != 0) {
            ang = (lbl_803E364C * (f32)(*(s8 *)(def + 0x18) << 8)) / lbl_803E3650;
            sd = mathSinf(ang);
            s = mathCosf(ang);
            sd = -(((ObjPlacement *)def)->posX * sd + ((ObjPlacement *)def)->posZ * s)
               + (sd * ((GameObject *)player)->anim.localPosX + s * ((GameObject *)player)->anim.localPosZ);
            if (((GameObject *)obj)->moveF8 == 0) {
                if (sd < lbl_803E3648 && sd > lbl_803E3658) {
                    active = 1;
                }
            } else {
                if (sd < lbl_803E365C && sd > lbl_803E3658) {
                    active = 1;
                }
            }
        }
        break;
    case 2:
        if (gb == 0) {
            if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 8) != 0 && GameBit_Get(0x2c) != 0) {
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
            }
            if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0) {
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                GameBit_Set(sub->gameBitA, 1);
            }
        } else if (gb != 0) {
            active = 1;
        }
        break;
    case 4:
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
        if (gb != 0) {
            i = objIdx;
            walk = (int **)((char *)list + i * 4);
            while (i < objCount && active == 0) {
                other = *walk;
                if (*(s16 *)((char *)other + 0x46) == 0x7c) {
                    dx = *(f32 *)((char *)other + 0xc) - ((ObjPlacement *)def)->posX;
                    dy = *(f32 *)((char *)other + 0x14) - ((ObjPlacement *)def)->posZ;
                    if (sqrtf(dx * dx + dy * dy) < lbl_803E3660) {
                        ang = (lbl_803E364C * (f32)(*(s8 *)(def + 0x18) << 8)) / lbl_803E3650;
                        sd = mathSinf(ang);
                        s = mathCosf(ang);
                        sd = -(((ObjPlacement *)def)->posX * sd + ((ObjPlacement *)def)->posZ * s)
                           + (sd * *(f32 *)((char *)other + 0xc) + s * *(f32 *)((char *)other + 0x14));
                        if (sd < lbl_803E3664 && sd > lbl_803E3668) {
                            active = 1;
                        }
                    }
                }
                walk = walk + 1;
                i = i + 1;
            }
            if (active != 0) {
                if (ObjMsg_Pop(obj, &msg, 0, 0) != 0 && msg < 10 && msg >= 8) {
                    ObjMsg_SendToObject(other, msg, obj, 0);
                }
                if (sd < lbl_803E3648 && ((GameObject *)obj)->moveF8 == 0) {
                    seq[0x90] |= 0x14;
                }
            } else {
                if (((GameObject *)obj)->moveF8 == 1) {
                    seq[0x90] |= 8;
                }
            }
        }
        break;
    case 3:
        if (dist < lbl_803E3654 && gb != 0) {
            ang = (lbl_803E364C * (f32)(*(s8 *)(def + 0x18) << 8)) / lbl_803E3650;
            sd = mathSinf(ang);
            s = mathCosf(ang);
            sd = -(((ObjPlacement *)def)->posX * sd + ((ObjPlacement *)def)->posZ * s)
               + (sd * ((GameObject *)player)->anim.localPosX + s * ((GameObject *)player)->anim.localPosZ);
            if (sd < lbl_803E366C && sd > lbl_803E3670) {
                active = 1;
            }
        }
        break;
    case 5:
        if (GameBit_Get(sub->gameBitB) != 0 && gb == 0) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
            if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0) {
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                GameBit_Set(sub->gameBitA, 1);
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                gb = 1;
            }
        }
        if (gb != 0) {
            active = 1;
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        }
        break;
    }
    if (((GameObject *)obj)->moveF8 == 0) {
        if (active != 0) {
            seq[0x90] |= 1;
        }
    } else if (active == 0) {
        seq[0x90] |= 2;
    }
    ((GameObject *)obj)->moveF8 = active;
    if ((((GameObject *)obj)->anim.seqId == 0x13e || ((GameObject *)obj)->anim.seqId == 0x151)
        && sub->triggerLatch != 0) {
        seq[0x90] |= 1;
    }
    while (ObjMsg_Pop(obj, &msg, 0, 0) != 0) {
    }
    for (i = 0; i < animUpdate->eventCount; i++) {
        ev = animUpdate->eventIds[i];
        if (ev != 0) {
            switch (ev) {
            case 1:
                vs = Camera_GetCurrentViewSlot();
                if (sub->planeD + (sub->cosYaw * vs[3] + sub->sinYaw * vs[5]) < lbl_803E3648) {
                    if (*(s16 *)(def + 0x20) != -1) {
                        GameBit_Set(*(s16 *)(def + 0x20),
                                    (u8)((u8)GameBit_Get(*(s16 *)(def + 0x20)) ^ (u8)*(s16 *)(def + 0x1c)));
                    }
                } else if (*(s16 *)(def + 0x1a) != -1) {
                    GameBit_Set(*(s16 *)(def + 0x1a),
                                (u8)((u8)GameBit_Get(*(s16 *)(def + 0x1a)) ^ (u8)(*(s16 *)(def + 0x1c) >> 8)));
                }
                if (sd <= lbl_803E3648) {
                    switch (((GameObject *)obj)->anim.seqId) {
                    case 0x1a2:
                        ObjMsg_SendToNearbyObjects(0x19c, lbl_803E3674, 0, obj, 0x30006, 0);
                        break;
                    case 0x1ad:
                        ObjMsg_SendToNearbyObjects(0x1ac, lbl_803E3674, 0, obj, 0x30006, 0);
                        break;
                    case 0x1bb:
                        ObjMsg_SendToNearbyObjects(0x1b9, lbl_803E3674, 0, obj, 0x30006, 0);
                        break;
                    case 0x1ea:
                        ObjMsg_SendToNearbyObjects(0x1e7, lbl_803E3674, 0, obj, 0x30006, 0);
                        break;
                    case 0x205:
                        ObjMsg_SendToNearbyObjects(0x202, lbl_803E3674, 0, obj, 0x30006, 0);
                        break;
                    case 0x21a:
                        ObjMsg_SendToNearbyObjects(0x217, lbl_803E3674, 0, obj, 0x30006, 0);
                        break;
                    case 0x238:
                        ObjMsg_SendToNearbyObjects(0x233, lbl_803E3674, 0, obj, 0x30006, 0);
                        break;
                    case 0x23f:
                        ObjMsg_SendToNearbyObjects(0x23c, lbl_803E3674, 0, obj, 0x30006, 0);
                        break;
                    }
                }
                /* fall through */
            case 3:
                if (sub->sfxOpen != 0) {
                    Sfx_PlayFromObject((int)obj, sub->sfxOpen);
                }
                break;
            case 4:
                if (sub->sfxOpen != 0
                    && Sfx_IsPlayingFromObject((int)obj, sub->sfxOpen) != 0) {
                    Sfx_StopFromObject((int)obj, sub->sfxOpen);
                }
                break;
            case 5:
                if (sub->sfxClose != 0 && GameBit_Get(0xcbb) == 0) {
                    Sfx_PlayFromObject((int)obj, sub->sfxClose);
                }
                break;
            case 2:
                vs = Camera_GetCurrentViewSlot();
                if (sub->planeD + (sub->cosYaw * vs[3] + sub->sinYaw * vs[5]) < lbl_803E3648) {
                    if (*(s16 *)(def + 0x20) != -1) {
                        GameBit_Set(*(s16 *)(def + 0x20),
                                    (u8)((u8)GameBit_Get(*(s16 *)(def + 0x20)) ^ (u8)*(s16 *)(def + 0x1c)));
                    }
                } else if (*(s16 *)(def + 0x1a) != -1) {
                    GameBit_Set(*(s16 *)(def + 0x1a),
                                (u8)((u8)GameBit_Get(*(s16 *)(def + 0x1a)) ^ (u8)(*(s16 *)(def + 0x1c) >> 8)));
                }
                switch (((GameObject *)obj)->anim.seqId) {
                case 0x1a2:
                    ObjMsg_SendToNearbyObjects(0x19c, lbl_803E3674, 0, obj, 0x30005, 0);
                    break;
                case 0x1ad:
                    ObjMsg_SendToNearbyObjects(0x1ac, lbl_803E3674, 0, obj, 0x30005, 0);
                    break;
                case 0x1bb:
                    ObjMsg_SendToNearbyObjects(0x1b9, lbl_803E3674, 0, obj, 0x30005, 0);
                    break;
                case 0x1ea:
                    ObjMsg_SendToNearbyObjects(0x1e7, lbl_803E3674, 0, obj, 0x30005, 0);
                    break;
                case 0x205:
                    ObjMsg_SendToNearbyObjects(0x202, lbl_803E3674, 0, obj, 0x30005, 0);
                    break;
                case 0x21a:
                    ObjMsg_SendToNearbyObjects(0x217, lbl_803E3674, 0, obj, 0x30005, 0);
                    break;
                case 0x238:
                    ObjMsg_SendToNearbyObjects(0x233, lbl_803E3674, 0, obj, 0x30005, 0);
                    break;
                case 0x23f:
                    ObjMsg_SendToNearbyObjects(0x23c, lbl_803E3674, 0, obj, 0x30005, 0);
                    break;
                }
                break;
            }
            animUpdate->eventIds[i] = 0;
        }
    }
    if (((GameObject *)obj)->countF4 != 0) {
        ((GameObject *)obj)->countF4 = 0;
        return 3;
    }
    return 0;
}
