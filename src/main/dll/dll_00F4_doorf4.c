/*
 * doorf4 (DLL 0xF4) - the generic triggered "door" / proximity-gate object
 * shared by many map seqIds (193/196/283/284/318/890/200/0x151/0x37a, ...).
 *
 * init caches the spawn yaw as a plane normal (cosYaw,sinYaw,planeD), an
 * open-range threshold and the two game bits read from the placement
 * (gameBitA = open latch at params+0x1E, plus a per-type secondary gate
 * gameBitB). The animation SeqFn (doorf4_SeqFn) is the brain: it measures
 * the player's signed distance through the door plane, folds in inbox
 * messages (open 0x30002 / close 0x30003) and the gameBits, and drives the
 * anim "active/open" bit per a switch on the placement's gate-mode byte
 * (def+0x19). Sequence events then fire open/close sfx, toggle the paired
 * game bit, and broadcast open/close (0x30005/0x30006) to the linked
 * partner objects of each door pair. update() does the one-shot spawn-time
 * placement + initial sequence kick; free() stops any playing open sfx and
 * leaves object group 14.
 */
#include "main/dll/dll_00F4_doorf4.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/camera.h"
#include "main/sfa_shared_decls.h"

/* Per-object extra state for the doorf4 door (doorf4_getExtraSize == 0x24). */
typedef struct DoorF4State
{
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

/* Class-specific placement record for the doorf4 (DLL 0xF4) door family:
 * ObjPlacement common head (0x00..0x17) followed by the door gate fields. */
typedef struct DoorF4Placement
{
    ObjPlacement head; /* 0x00..0x17 */
    s8 yawByte;        /* 0x18: spawn yaw, scaled by <<8 to a binary angle */
    s8 gateMode;       /* 0x19: gate-mode selector (switch in SeqFn) */
    s16 gameBitB;      /* 0x1a: secondary GameBit toggled on far-side open */
    s16 toggleMask;    /* 0x1c: xor masks (low byte near-side, high byte far) */
    s16 gameBitA;      /* 0x1e: open-latch GameBit id */
    s16 gameBitC;      /* 0x20: near-side GameBit toggled on open */
} DoorF4Placement;

STATIC_ASSERT(offsetof(DoorF4Placement, yawByte) == 0x18);
STATIC_ASSERT(offsetof(DoorF4Placement, gameBitC) == 0x20);

#define DOORF4_OBJ_GROUP 14

/* messages received by a door's inbox */
#define DOORMSG_OPEN 0x30002
#define DOORMSG_CLOSE 0x30003
/* messages broadcast to a door's linked partner objects */
#define DOORMSG_PARTNER_CLOSE 0x30005
#define DOORMSG_PARTNER_OPEN 0x30006

extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject();
extern int ObjMsg_Peek();
extern int ObjMsg_Pop();
extern void ObjMsg_SendToNearbyObjects();
extern u32 ObjMsg_SendToObject(void* obj, u32 message, void* sender, u32 param);
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern f32 lbl_803E3680;
extern void objRenderFn_8003b8f4(f32);
extern int Sfx_IsPlayingFromObject(int obj, int sfxId);
extern void Sfx_StopFromObject(int obj, int sfxId);
extern void* Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 lbl_803E3654;
extern f32 lbl_803E3684;
extern f32 gDoorF4Pi;
extern f32 gDoorF4BinaryAngleScale;


extern void* ObjList_GetObjects(int* outA, int* outB);
extern f32 sqrtf(f32 x);
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern f32 lbl_803E3648;
extern f32 lbl_803E3658;
extern f32 lbl_803E365C;
extern f32 lbl_803E3660;
extern f32 lbl_803E3664;
extern f32 lbl_803E3668;
extern f32 lbl_803E366C;
extern f32 lbl_803E3670;
extern f32 lbl_803E3674;

void doorf4_hitDetect(void)
{
}

void doorf4_release(void)
{
}

void doorf4_initialise(void)
{
}

int doorf4_getExtraSize(void) { return 0x24; }
int doorf4_getObjectTypeId(void) { return 0x1; }

void doorf4_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3680);
}

void doorf4_free(int obj)
{
    DoorF4State* state = ((GameObject*)obj)->extra;
    if (state->sfxOpen != 0)
    {
        if (Sfx_IsPlayingFromObject(obj, state->sfxOpen) != 0)
        {
            Sfx_StopFromObject(obj, state->sfxOpen);
        }
    }
    ObjGroup_RemoveObject(obj, DOORF4_OBJ_GROUP);
}

void doorf4_update(int* obj)
{
    DoorF4State* state = ((GameObject*)obj)->extra;
    state->triggerLatch = 0;
    if (((GameObject*)obj)->unkF4 == 0)
    {
        int* src = *(int**)&((GameObject*)obj)->anim.placementData;
        s16 type;
        ((GameObject*)obj)->anim.localPosX = ((ObjPlacement*)src)->posX;
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)src)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)src)->posZ;
        ((GameObject*)obj)->anim.rotX = (s16)((s8) * (s8*)((char*)src + 0x18) << 8);
        type = ((GameObject*)obj)->anim.seqId;
        if (type == 0x151)
        {
            if (GameBit_Get(state->gameBitA) != 0)
            {
                (*gObjectTriggerInterface)->preempt((int)obj, 0x75);
                state->triggerLatch = 1;
            }
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
        else if (type == 0x37a)
        {
            if (GameBit_Get(state->gameBitA) != 0)
            {
                (*gObjectTriggerInterface)->preempt((int)obj, 0x8a);
                state->triggerLatch = 1;
            }
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
        ((GameObject*)obj)->unkF4 = 1;
    }
}

void doorf4_init(int* obj, int* params)
{
    DoorF4State* state = ((GameObject*)obj)->extra;
    s16 type;

    ObjMsg_AllocQueue(obj, 4);
    ((GameObject*)obj)->anim.rotX = (s16)((s8) * (s8*)((char*)params + 0x18) << 8);
    ((GameObject*)obj)->animEventCallback = doorf4_SeqFn;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    ((GameObject*)obj)->objectFlags |= 0x6000;
    state->gameBitA = *(s16*)((char*)params + 0x1e);
    state->unk18 = *(s16*)((char*)params + 0x20);
    state->openRange = lbl_803E3654;

    type = ((GameObject*)obj)->anim.seqId;
    switch (type)
    {
    case 193:
    case 196:
        state->gameBitB = 68;
        break;
    case 283:
    case 284:
        state->gameBitB = 152;
        break;
    case 318:
    case 890:
        *(s16*)&state->sfxOpen = 830;
        *(s16*)&state->sfxClose = 831;
        break;
    case 200:
        state->openRange = lbl_803E3684;
        break;
    default:
        state->gameBitB = -1;
    }

    ObjGroup_AddObject(obj, DOORF4_OBJ_GROUP);

    state->cosYaw = mathSinf(gDoorF4Pi * (f32)(int) * (s16*)obj / gDoorF4BinaryAngleScale);
    state->sinYaw = mathCosf(gDoorF4Pi * (f32)(int) * (s16*)obj / gDoorF4BinaryAngleScale);
    state->planeD = -(state->cosYaw * ((GameObject*)obj)->anim.localPosX +
        state->sinYaw * ((GameObject*)obj)->anim.localPosZ);
}

int doorf4_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int msg;
    int objCount;
    int objIdx;
    int* other;
    int gb;
    u8 gbToggle;
    int active;
    int* list;
    int* player;
    int i;
    DoorF4Placement* def;
    DoorF4State* sub;
    int** walk;
    f32* vs;
    u8 ev;
    f32 ang;
    f32 dist;
    f32 sd;
    f32 s;
    f32 dx;
    f32 dy;
    f32 thr;

    def = *(DoorF4Placement**)&((GameObject*)obj)->anim.placementData;
    sub = ((GameObject*)obj)->extra;
    sd = lbl_803E3648;
    list = ObjList_GetObjects(&objIdx, &objCount);
    animUpdate->sequenceEventActive = 0;
    player = Obj_GetPlayerObject();
    dx = ((GameObject*)player)->anim.localPosX - def->head.posX;
    dy = ((GameObject*)player)->anim.localPosZ - def->head.posZ;
    dist = sqrtf(dx * dx + dy * dy);
    if (sub->gameBitA == -1)
    {
        gb = 1;
    }
    else
    {
        gb = GameBit_Get(sub->gameBitA);
    }
    if (ObjMsg_Peek(obj, &msg, 0, 0) != 0)
    {
        switch (msg)
        {
        case DOORMSG_OPEN:
            *(u8*)&sub->active = 1;
            break;
        case DOORMSG_CLOSE:
            *(u8*)&sub->active = 0;
            break;
        }
    }
    active = *(s8*)&sub->active;
    switch (def->gateMode)
    {
    case 6:
        if (gb != 0)
        {
            active = 1;
        }
        break;
    case 0:
        ang = (gDoorF4Pi * (f32)(def->yawByte << 8)) / gDoorF4BinaryAngleScale;
        sd = mathSinf(ang);
        s = mathCosf(ang);
        sd = -(def->head.posX * sd + def->head.posZ * s)
            + (sd * ((GameObject*)player)->anim.localPosX + s * ((GameObject*)player)->anim.localPosZ);
        thr = sub->openRange;
        if (dist < thr && gb != 0 && sd < thr && sd > -thr)
        {
            active = 1;
        }
        if (active != 0 && sub->toggled == 0)
        {
            if (((GameObject*)obj)->anim.seqId == 200)
            {
                if (GameBit_Get(0x57) != 0)
                {
                    getEnvfxAct(0, 0, 0x7f, 0);
                }
                else
                {
                    getEnvfxAct(0, 0, 0x7c, 0);
                }
            }
            sub->toggled = 1;
        }
        else if (active == 0 && sub->toggled == 1)
        {
            if (((GameObject*)obj)->anim.seqId == 200 && sd <= lbl_803E3648)
            {
                getEnvfxAct(0, 0, 0xe, 0);
            }
            sub->toggled = 0;
        }
        break;
    case 1:
        if (dist < lbl_803E3654 && gb != 0)
        {
            ang = (gDoorF4Pi * (f32)(def->yawByte << 8)) / gDoorF4BinaryAngleScale;
            sd = mathSinf(ang);
            s = mathCosf(ang);
            sd = -(def->head.posX * sd + def->head.posZ * s)
                + (sd * ((GameObject*)player)->anim.localPosX + s * ((GameObject*)player)->anim.localPosZ);
            if (((GameObject*)obj)->unkF8 == 0)
            {
                if (sd < lbl_803E3648 && sd > lbl_803E3658)
                {
                    active = 1;
                }
            }
            else
            {
                if (sd < lbl_803E365C && sd > lbl_803E3658)
                {
                    active = 1;
                }
            }
        }
        break;
    case 2:
        if (gb == 0)
        {
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_DISABLED) != 0 && GameBit_Get(0x2c) != 0)
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            }
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                GameBit_Set(sub->gameBitA, 1);
            }
        }
        else if (gb != 0)
        {
            active = 1;
        }
        break;
    case 4:
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        if (gb != 0)
        {
            for (i = objIdx, walk = (int**)((char*)list + i * 4); i < objCount && active == 0;
                 i++, walk++)
            {
                other = *walk;
                if (((GameObject*)other)->anim.seqId == 0x7c)
                {
                    dx = ((GameObject*)other)->anim.localPosX - def->head.posX;
                    dy = ((GameObject*)other)->anim.localPosZ - def->head.posZ;
                    if (sqrtf(dx * dx + dy * dy) < lbl_803E3660)
                    {
                        ang = (gDoorF4Pi * (f32)(def->yawByte << 8)) / gDoorF4BinaryAngleScale;
                        sd = mathSinf(ang);
                        s = mathCosf(ang);
                        sd = -(def->head.posX * sd + def->head.posZ * s)
                            + (sd * ((GameObject*)other)->anim.localPosX + s * ((GameObject*)other)->anim.localPosZ);
                        if (sd < lbl_803E3664 && sd > lbl_803E3668)
                        {
                            active = 1;
                        }
                    }
                }
            }
            if (active != 0)
            {
                if (ObjMsg_Pop(obj, &msg, 0, 0) != 0 && msg < 10 && msg >= 8)
                {
                    ObjMsg_SendToObject(other, msg, obj, 0);
                }
                if (sd < lbl_803E3648 && ((GameObject*)obj)->unkF8 == 0)
                {
                    animUpdate->sequenceControlFlags |= 0x14;
                }
            }
            else
            {
                if (((GameObject*)obj)->unkF8 == 1)
                {
                    animUpdate->sequenceControlFlags |= 8;
                }
            }
        }
        break;
    case 3:
        if (dist < lbl_803E3654 && gb != 0)
        {
            ang = (gDoorF4Pi * (f32)(def->yawByte << 8)) / gDoorF4BinaryAngleScale;
            sd = mathSinf(ang);
            s = mathCosf(ang);
            sd = -(def->head.posX * sd + def->head.posZ * s)
                + (sd * ((GameObject*)player)->anim.localPosX + s * ((GameObject*)player)->anim.localPosZ);
            if (sd < lbl_803E366C && sd > lbl_803E3670)
            {
                active = 1;
            }
        }
        break;
    case 5:
        if (GameBit_Get(sub->gameBitB) != 0 && gb == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                GameBit_Set(sub->gameBitA, 1);
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                gb = 1;
            }
        }
        if (gb != 0)
        {
            active = 1;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        break;
    }
    if (((GameObject*)obj)->unkF8 == 0)
    {
        if (active != 0)
        {
            animUpdate->sequenceControlFlags |= 1;
        }
    }
    else if (active == 0)
    {
        animUpdate->sequenceControlFlags |= 2;
    }
    ((GameObject*)obj)->unkF8 = active;
    if ((((GameObject*)obj)->anim.seqId == 0x13e || ((GameObject*)obj)->anim.seqId == 0x151)
        && sub->triggerLatch != 0)
    {
        animUpdate->sequenceControlFlags |= 1;
    }
    while (ObjMsg_Pop(obj, &msg, 0, 0) != 0)
    {
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        ev = animUpdate->eventIds[i];
        if (ev != 0)
        {
            switch (ev)
            {
            case 1:
                vs = Camera_GetCurrentViewSlot();
                if (sub->planeD + (sub->cosYaw * vs[3] + sub->sinYaw * vs[5]) < lbl_803E3648)
                {
                    if (def->gameBitC != -1)
                    {
                        gbToggle = (u8)GameBit_Get(def->gameBitC);
                        gbToggle ^= (u8)def->toggleMask;
                        GameBit_Set(def->gameBitC, gbToggle);
                    }
                }
                else if (def->gameBitB != -1)
                {
                    gbToggle = (u8)GameBit_Get(def->gameBitB);
                    gbToggle ^= (u8)(def->toggleMask >> 8);
                    GameBit_Set(def->gameBitB, gbToggle);
                }
                if (sd <= lbl_803E3648)
                {
                    switch (((GameObject*)obj)->anim.seqId)
                    {
                    case 0x1a2:
                        ObjMsg_SendToNearbyObjects(0x19c, lbl_803E3674, 0, obj, DOORMSG_PARTNER_OPEN, 0);
                        break;
                    case 0x1ad:
                        ObjMsg_SendToNearbyObjects(0x1ac, lbl_803E3674, 0, obj, DOORMSG_PARTNER_OPEN, 0);
                        break;
                    case 0x1bb:
                        ObjMsg_SendToNearbyObjects(0x1b9, lbl_803E3674, 0, obj, DOORMSG_PARTNER_OPEN, 0);
                        break;
                    case 0x1ea:
                        ObjMsg_SendToNearbyObjects(0x1e7, lbl_803E3674, 0, obj, DOORMSG_PARTNER_OPEN, 0);
                        break;
                    case 0x205:
                        ObjMsg_SendToNearbyObjects(0x202, lbl_803E3674, 0, obj, DOORMSG_PARTNER_OPEN, 0);
                        break;
                    case 0x21a:
                        ObjMsg_SendToNearbyObjects(0x217, lbl_803E3674, 0, obj, DOORMSG_PARTNER_OPEN, 0);
                        break;
                    case 0x238:
                        ObjMsg_SendToNearbyObjects(0x233, lbl_803E3674, 0, obj, DOORMSG_PARTNER_OPEN, 0);
                        break;
                    case 0x23f:
                        ObjMsg_SendToNearbyObjects(0x23c, lbl_803E3674, 0, obj, DOORMSG_PARTNER_OPEN, 0);
                        break;
                    }
                }
            case 3:
                if (sub->sfxOpen != 0)
                {
                    Sfx_PlayFromObject((int)obj, sub->sfxOpen);
                }
                break;
            case 4:
                if (sub->sfxOpen != 0
                    && Sfx_IsPlayingFromObject((int)obj, sub->sfxOpen) != 0)
                {
                    Sfx_StopFromObject((int)obj, sub->sfxOpen);
                }
                break;
            case 5:
                if (sub->sfxClose != 0 && GameBit_Get(0xcbb) == 0)
                {
                    Sfx_PlayFromObject((int)obj, sub->sfxClose);
                }
                break;
            case 2:
                vs = Camera_GetCurrentViewSlot();
                if (sub->planeD + (sub->cosYaw * vs[3] + sub->sinYaw * vs[5]) < lbl_803E3648)
                {
                    if (def->gameBitC != -1)
                    {
                        gbToggle = (u8)GameBit_Get(def->gameBitC);
                        gbToggle ^= (u8)def->toggleMask;
                        GameBit_Set(def->gameBitC, gbToggle);
                    }
                }
                else if (def->gameBitB != -1)
                {
                    gbToggle = (u8)GameBit_Get(def->gameBitB);
                    gbToggle ^= (u8)(def->toggleMask >> 8);
                    GameBit_Set(def->gameBitB, gbToggle);
                }
                switch (((GameObject*)obj)->anim.seqId)
                {
                case 0x1a2:
                    ObjMsg_SendToNearbyObjects(0x19c, lbl_803E3674, 0, obj, DOORMSG_PARTNER_CLOSE, 0);
                    break;
                case 0x1ad:
                    ObjMsg_SendToNearbyObjects(0x1ac, lbl_803E3674, 0, obj, DOORMSG_PARTNER_CLOSE, 0);
                    break;
                case 0x1bb:
                    ObjMsg_SendToNearbyObjects(0x1b9, lbl_803E3674, 0, obj, DOORMSG_PARTNER_CLOSE, 0);
                    break;
                case 0x1ea:
                    ObjMsg_SendToNearbyObjects(0x1e7, lbl_803E3674, 0, obj, DOORMSG_PARTNER_CLOSE, 0);
                    break;
                case 0x205:
                    ObjMsg_SendToNearbyObjects(0x202, lbl_803E3674, 0, obj, DOORMSG_PARTNER_CLOSE, 0);
                    break;
                case 0x21a:
                    ObjMsg_SendToNearbyObjects(0x217, lbl_803E3674, 0, obj, DOORMSG_PARTNER_CLOSE, 0);
                    break;
                case 0x238:
                    ObjMsg_SendToNearbyObjects(0x233, lbl_803E3674, 0, obj, DOORMSG_PARTNER_CLOSE, 0);
                    break;
                case 0x23f:
                    ObjMsg_SendToNearbyObjects(0x23c, lbl_803E3674, 0, obj, DOORMSG_PARTNER_CLOSE, 0);
                    break;
                }
                break;
            }
            animUpdate->eventIds[i] = 0;
        }
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        ((GameObject*)obj)->unkF4 = 0;
        return 3;
    }
    return 0;
}
