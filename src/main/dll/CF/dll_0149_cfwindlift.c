/*
 * cfwindlift (DLL 0x149, defs CFWindLift + CFTreasWind) - wind lifts
 * at CF and elsewhere. update ramps the lift alpha from its game bit,
 * runs the rise sequence with a squared ramp-in, and tracks up to 14
 * rider slots (riders get pulled by fn_8019C784's per-slot spring
 * model). The three fortress lifts (placement seqIds 0x58-0x5A in the
 * lookup tables) only run once GameBit 0x57 is set - the city's power
 * restored via the three power bases and the main crystal convergence
 * (see cfpowerbase/cfmaincrystal), which is what the freed old
 * CloudRunner sends you off to do. TU = 0x8019C784..0x8019D578.
 */

#include "main/game_object.h"
#include "main/dll/player_motion.h"
#include "main/gamebits.h"
#include "main/audio/music_trigger_ids.h"

extern void cfpowerbase_getExtraSize(void);
extern void cfmaincrystal_getExtraSize(void);

extern void cfpowerbase_getObjectTypeId(void);
extern void cfmaincrystal_getObjectTypeId(void);

extern void cfpowerbase_free(void);
extern void cfmaincrystal_free(void);

extern void cfpowerbase_render(void);
extern void cfmaincrystal_render(void);

extern void cfpowerbase_hitDetect(void);
extern void cfmaincrystal_hitDetect(void);

extern void cfpowerbase_update(void);
extern void cfmaincrystal_update(void);

extern void cfpowerbase_init(void);
extern void cfmaincrystal_init(void);

extern void cfpowerbase_release(void);
extern void cfmaincrystal_release(void);

extern void cfpowerbase_initialise(void);
extern void cfmaincrystal_initialise(void);

#define CFWINDLIFT_OBJGROUP 0x49

#define CFWINDLIFT_OBJFLAG_PARENT_SLACK 0x1000

#define WINDLIFT_SLOTS 14   /* max tracked lift slots */

typedef struct WindliftPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX; /* 0x08 */
    f32 posY; /* 0x0C */
    f32 posZ; /* 0x10 */
    u8 pad14[0x18 - 0x14];
    s16 unk18;
    s16 pullStrength; /* 0x1A: wind pull strength passed to fn_8019C784 */
    u8 pad1C[0x22 - 0x1C];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} WindliftPlacement;

typedef struct WindliftObjectDef
{
    u8 pad0[0x8 - 0x0];
    f32 posX; /* 0x08 */
    f32 posY; /* 0x0C */
    f32 posZ; /* 0x10 */
    u8 pad14[0x18 - 0x14];
    s8 unk18;
    s8 heightByte; /* 0x19: lift height in gWindLiftHeightByteScale units (0 = default) */
    s16 pullStrength; /* 0x1A */
    s16 delay;
    s16 seqId;
    u8 pad20[0x22 - 0x20];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} WindliftObjectDef;

typedef struct
{
    int riderObj;
    f32 f4;
    f32 speedDelta;
    f32 riseSpeed;
    u8 phaseFlags;
    u8 oscCounter;
    u8 pad12[2];
    int linkIndex;
} WindLiftSlot;

/* WindLiftSlot.phaseFlags bits */
#define WLSLOT_RISING 0x1      /* rise force active this frame */
#define WLSLOT_PENDING 0x2     /* pull direction re-evaluation requested */
#define WLSLOT_PULLUP 0x4      /* pulling rider upward */
#define WLSLOT_PULLDOWN 0x8    /* pulling rider downward */
#define WLSLOT_HOLD 0x20       /* rider holding gamebit (grabbed) phase */
#define WLSLOT_RELEASE 0x40    /* rider released phase */
#define WLSLOT_LATCH 0x80      /* lift event latched/consumed */

typedef struct
{
    int duration;
    int seqId;
    int delay;
    int gamebit;
    int pad10;
    int timer;
    WindLiftSlot slots[WINDLIFT_SLOTS];
    int pad168;
    int pad16c;
    f32 liftHeight;
    u8 musicOn : 1;
    u8 active : 1;
    u8 _f2 : 6;
} WindLiftSub;

extern void* ObjGroup_GetObjects();
extern int ObjGroup_RemoveObject();
extern int ObjGroup_AddObject();
extern u32 ObjMsg_SendToObject(void* obj, u32 message, void* sender, u32 param);
extern void objRenderFn_8003b8f4(f32);
extern void* Obj_GetPlayerObject(void);
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803E4190;
extern const f32 lbl_803E416C;
extern void Music_Trigger(int id, int arg);
extern int seqStreamLookupFn_8007fff8(void* table, int count, int key);
extern u8 gWindLiftSeqDurationTable[];
extern u8 gWindLiftSeqGamebitTable[];
extern f32 gWindLiftHeightByteScale;
extern f32 gWindLiftDefaultHeight;
extern const f32 lbl_803E4168;
extern f32 Vec_xzDistance(void* a, void* b);
extern f32 lbl_803E4170;
extern f32 lbl_803E4174;
extern f32 lbl_803E4178;
extern f32 lbl_803E417C;
extern f32 lbl_803E4180;
extern f32 lbl_803E4184;
extern f32 lbl_803E4188;
extern f32 lbl_803E418C;
extern f32 lbl_803E4194;
extern f32 lbl_803E4198;
extern f32 lbl_803E419C;
extern f32 lbl_803E41A0;
extern f32 lbl_803E41A4;
extern f32 lbl_803E41A8;
extern f32 lbl_803E41AC;
extern f32 lbl_803E41B0;
extern f32 lbl_803E41B4;
extern f32 lbl_803E41B8;
extern int Obj_SetActiveModelIndex(int* obj, int idx);
extern f32 lbl_803E41BC;

/* fn_8019C784: per-rider wind lift physics - track the rider while
 * above the lift and in range, send the lift/drop messages on state
 * edges, and integrate the rise speed with ramp-up, oscillation damping
 * and player-mode handoff. The spring model pulls a rider toward the
 * lift column and lifts it with the wind; slot->phaseFlags carries the rider's
 * phase bits. */
void fn_8019C784(int* obj, int* rider, WindLiftSlot* slot, f32 pull, int gb, int pm, u32 dur, f32 height)
{
    char* player;
    f32 lim;
    f32 t;
    f32 d;
    f32 v;
    f32 thr;
    f32 dy;
    f32 dist;
    f32 factor;
    f32 scale;
    u8 flags;
    u8 fl;
    int fe;
    player = Obj_GetPlayerObject();
    dy = ((GameObject*)rider)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    if (dy < lbl_803E416C)
    {
        return;
    }
    dist = Vec_xzDistance((char*)rider + 0x18, (char*)obj + 0x18);
    if (dist > lbl_803E4170 + height && (slot->phaseFlags & 0xe0) == 0)
    {
        return;
    }
    flags = slot->phaseFlags;
    if ((flags & WLSLOT_LATCH) != 0 && gb != 0)
    {
        return;
    }
    if (dist < height)
    {
        if ((flags & 0xe0) == 0 || (flags & WLSLOT_LATCH) != 0)
        {
            if (gb != 0 && (!flags & WLSLOT_LATCH) != 0 && dy < lbl_803E4174)
            {
                slot->phaseFlags |= WLSLOT_LATCH;
                return;
            }
            if ((flags & WLSLOT_PENDING) != 0)
            {
                if (dy / pull > lbl_803E4178)
                {
                    slot->phaseFlags |= WLSLOT_PULLUP;
                    slot->phaseFlags &= ~WLSLOT_PULLDOWN;
                }
                else
                {
                    slot->phaseFlags |= WLSLOT_PULLDOWN;
                    slot->phaseFlags &= ~WLSLOT_PULLUP;
                }
                slot->phaseFlags &= ~WLSLOT_PENDING;
            }
            if (gb == 0)
            {
                slot->phaseFlags |= WLSLOT_RELEASE;
                slot->phaseFlags &= ~WLSLOT_HOLD;
                ObjMsg_SendToObject(rider, 0xf, obj, (((slot->phaseFlags & 0xe0) >> 4) << 8) | dur);
                slot->phaseFlags &= ~WLSLOT_LATCH;
            }
            else
            {
                if (dy > lbl_803E417C)
                {
                    ObjMsg_SendToObject(rider, 0xf, obj, (((slot->phaseFlags & 0xe0) >> 4) << 8) | dur);
                }
                slot->phaseFlags |= WLSLOT_HOLD;
                slot->phaseFlags &= ~WLSLOT_RELEASE;
            }
        }
        scale = lbl_803E4180;
        fl = slot->phaseFlags;
        fe = fl & 0xe;
        if (fe != 0 && (fl & WLSLOT_PULLDOWN) != 0 && gb == 0)
        {
            pull = pull * lbl_803E4184;
        }
        pull = pull * lbl_803E4184;
        if (pull <= lbl_803E4170)
        {
            return;
        }
        if (dy < lbl_803E4188)
        {
            dy = lbl_803E4188;
        }
        if (gb == 0)
        {
            lim = pull - (pull / lbl_803E418C) * (slot->riseSpeed * (slot->riseSpeed * slot->riseSpeed));
            if (dy > lim)
            {
                t = lbl_803E416C;
            }
            else
            {
                d = lim - dy;
                if (d > lbl_803E4174)
                {
                    t = lbl_803E4190;
                }
                else
                {
                    t = d / lbl_803E4174;
                }
            }
            factor = t;
            slot->phaseFlags |= WLSLOT_RISING;
            if (((slot->riseSpeed < lbl_803E4194 && slot->oscCounter % 2 != 0)
                    || (slot->riseSpeed > lbl_803E4198 && slot->oscCounter % 2 == 0))
                && (slot->phaseFlags & WLSLOT_PULLDOWN) != 0)
            {
                if (slot->oscCounter++ > 2)
                {
                    slot->phaseFlags &= ~WLSLOT_PULLDOWN;
                    slot->phaseFlags |= WLSLOT_PULLUP;
                }
            }
        }
        else
        {
            v = slot->riseSpeed;
            if (fe != 0)
            {
                thr = lbl_803E4168;
            }
            else
            {
                thr = lbl_803E419C;
            }
            if (v > thr)
            {
                slot->oscCounter = 1;
            }
            scale = scale * lbl_803E41A0;
            if (slot->oscCounter == 0)
            {
                if ((slot->phaseFlags & 0xe) != 0)
                {
                    factor = lbl_803E4190 - dy / (lbl_803E41A4 * pull);
                }
                else
                {
                    factor = lbl_803E4190 - dy / (lbl_803E41A8 * pull);
                }
                if (factor < lbl_803E416C)
                {
                    factor = lbl_803E416C;
                }
                factor = factor * factor;
            }
            else
            {
                factor = lbl_803E41AC;
            }
        }
        slot->speedDelta = scale * factor - lbl_803E41B0;
        slot->riseSpeed = slot->riseSpeed + slot->speedDelta;
        if (slot->riseSpeed > lbl_803E41B4)
        {
            slot->riseSpeed = *(f32*)&lbl_803E41B4;
        }
        if (lbl_803E416C == slot->riseSpeed)
        {
            slot->riseSpeed = lbl_803E41B8;
        }
        if (dy < lbl_803E4174 && gb != 0)
        {
            slot->riseSpeed = lbl_803E416C;
            slot->oscCounter = 0;
            ObjMsg_SendToObject(rider, 0x10, obj, gb);
            slot->phaseFlags |= WLSLOT_LATCH;
            if (pm != 0)
            {
                ((GameObject*)player)->anim.velocityY = lbl_803E416C;
            }
        }
        if (pm != 0)
        {
            Player_SetLiftVelocityY((int)rider, slot->riseSpeed);
        }
        else
        {
            ((GameObject*)rider)->anim.localPosY = slot->riseSpeed * timeDelta + ((GameObject*)rider)->anim.localPosY;
            ((GameObject*)rider)->anim.velocityY = slot->riseSpeed * timeDelta;
        }
    }
    else
    {
        if (pm != 0)
        {
            Player_SetLiftVelocityY((int)rider, lbl_803E416C);
        }
        if (pm == 0)
        {
            ObjMsg_SendToObject(rider, 0x10, obj, gb);
            slot->phaseFlags &= ~0xf1;
            slot->riseSpeed = lbl_803E416C;
            slot->oscCounter = 0;
        }
    }
}

int windlift_getExtraSize(void) { return 0x178; }

int windlift_getObjectTypeId(void) { return 0x0; }

void windlift_free(int* obj)
{
    void* p = Obj_GetPlayerObject();
    if (p == NULL || Player_GetLiftVelocityY((int)p) == lbl_803E416C)
    {
        Music_Trigger(MUSICTRIG_DIM_Cavern, 0);
    }
    ObjGroup_RemoveObject(obj, CFWINDLIFT_OBJGROUP);
}

void windlift_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4190);
}

void windlift_hitDetect(void)
{
}

/* windlift_update: fade the lift opacity with its gamebit, spin up
 * over the first second, then assign every nearby group-0x16 object
 * (and the player) to a rider slot and run the lift physics on each. */
void windlift_update(int* obj)
{
    u8* def;
    WindLiftSub* sub = ((GameObject*)obj)->extra;
    int level;
    char* player;
    f32 pull;
    int idx;
    int j;
    int found;
    int count;
    int** objs;
    int gb2;
    def = (u8*)((GameObject*)obj)->anim.placement;
    if (sub->active)
    {
        level = (int)(lbl_803E41BC * timeDelta + (f32)(int)((GameObject*)obj)->anim.alpha);
        if (sub->gamebit != -1 && GameBit_Get(sub->gamebit) == 0)
        {
            sub->active = 0;
        }
    }
    else
    {
        level = (int)-(lbl_803E41BC * timeDelta - (f32)(int)((GameObject*)obj)->anim.alpha);
        if (sub->gamebit != -1 && GameBit_Get(sub->gamebit) != 0)
        {
            sub->active = 1;
        }
    }
    ((GameObject*)obj)->anim.alpha = (level < 0) ? 0 : ((level > 0xff) ? 0xff : level);
    /* the fortress lifts (table durations 1-4) stay dead until the
       city's power is restored (0x57, the crystal convergence) */
    if ((GameBit_Get(0x57) != 0 || sub->duration > 0xa) && sub->active)
    {
        int t = sub->timer;
        sub->timer = t + 1;
        if (t < 0x3c && GameBit_Get(sub->seqId) == 0)
        {
            ((GameObject*)obj)->anim.rotX -= ((framesThisStep * 100) * (sub->timer * sub->timer)) / 0x3c;
            Obj_SetActiveModelIndex(obj, 0);
            return;
        }
        Obj_SetActiveModelIndex(obj, 1);
        gb2 = GameBit_Get(sub->delay);
        {
            int m = framesThisStep * 0xb6;
            ((GameObject*)obj)->anim.rotX -= m * ((gb2 << 2) + 0xe);
        }
        pull = (f32)((WindliftPlacement*)def)->pullStrength;
        player = Obj_GetPlayerObject();
        if (GameBit_Get(sub->seqId) != 0)
        {
            if (!sub->musicOn)
            {
                sub->musicOn = 1;
                Music_Trigger(MUSICTRIG_DIM_Cavern, 1);
            }
            if (player != NULL)
            {
                fn_8019C784(obj, (int*)player, &sub->slots[0], pull, gb2, 1, sub->duration, sub->liftHeight);
            }
        }
        else
        {
            if (sub->musicOn)
            {
                Music_Trigger(MUSICTRIG_DIM_Cavern, 0);
                sub->musicOn = 0;
            }
            if ((sub->slots[0].phaseFlags & 0xe0) != 0)
            {
                u8 b;
                Player_SetLiftVelocityY((int)player, lbl_803E416C);
                b = sub->slots[0].phaseFlags;
                if ((b & 0xe) != 0)
                {
                    sub->slots[0].phaseFlags = b | WLSLOT_PENDING;
                }
                sub->slots[0].riseSpeed = lbl_803E416C;
                sub->slots[0].oscCounter = 0;
                sub->slots[0].phaseFlags &= ~0xf1;
            }
        }
        objs = ObjGroup_GetObjects(0x16, &count);
        count = count + 1;
        if (count > 0xe)
        {
            count = 0xe;
        }
        for (j = 1; j < WINDLIFT_SLOTS; j++)
        {
            sub->slots[j].linkIndex = -1;
        }
        for (idx = 1; idx < count; idx++)
        {
            found = -1;
            for (j = 1; j < WINDLIFT_SLOTS; j++)
            {
                if ((u32)sub->slots[j].riderObj == (u32) * objs)
                {
                    found = j;
                }
            }
            if (found == -1)
            {
                for (j = 1; j < WINDLIFT_SLOTS; j++)
                {
                    if ((u32)sub->slots[j].riderObj == 0)
                    {
                        found = j;
                        sub->slots[j].phaseFlags = 0;
                        sub->slots[j].phaseFlags &= ~0xf1;
                        sub->slots[j].f4 = lbl_803E4168;
                        sub->slots[j].riseSpeed = lbl_803E416C;
                        sub->slots[j].speedDelta = lbl_803E416C;
                        sub->slots[j].riderObj = 0;
                        sub->slots[j].oscCounter = 0;
                        j = 2000;
                    }
                }
                if (found == -1)
                {
                    return;
                }
                sub->slots[found].riderObj = (int)*objs;
            }
            sub->slots[found].linkIndex = found;
            {
                int* rider = *objs;
                if ((((GameObject*)rider)->objectFlags & CFWINDLIFT_OBJFLAG_PARENT_SLACK) != 0)
                {
                    objs++;
                }
                else if (rider != NULL)
                {
                    fn_8019C784(obj, *objs++, &sub->slots[found], pull, gb2, 0, sub->duration, sub->liftHeight);
                }
            }
        }
        for (j = 1; j < WINDLIFT_SLOTS; j++)
        {
            if (sub->slots[j].linkIndex == -1)
            {
                sub->slots[j].riderObj = 0;
            }
        }
    }
}

/* windlift_init: look up the lift's sequence timings, scale its rise
 * height from the def byte, arm it from the gamebits and clear all 14
 * rider slots. */
void windlift_init(int* obj, u8* def)
{
    int i;
    WindLiftSub* sub = ((GameObject*)obj)->extra;
    sub->seqId = ((WindliftObjectDef*)def)->seqId;
    sub->duration = seqStreamLookupFn_8007fff8(gWindLiftSeqDurationTable, 4, sub->seqId);
    sub->gamebit = seqStreamLookupFn_8007fff8(gWindLiftSeqGamebitTable, 3, sub->seqId);
    if (sub->gamebit == 0)
    {
        sub->gamebit = -1;
    }
    if (sub->duration == 0)
    {
        sub->duration = 100;
    }
    sub->delay = ((WindliftObjectDef*)def)->delay;
    sub->timer = 0;
    if (((WindliftObjectDef*)def)->heightByte != 0)
    {
        sub->liftHeight = gWindLiftHeightByteScale * (f32)((WindliftObjectDef*)def)->heightByte;
    }
    else
    {
        sub->liftHeight = gWindLiftDefaultHeight;
    }
    ((GameObject*)obj)->anim.rootMotionScale =
        (*(f32*)(*(char**)&((GameObject*)obj)->anim.modelInstance + 4) * sub->liftHeight) / gWindLiftDefaultHeight;
    /* skip the rise-in ramp after the convergence cutscene (0x57)
       or for long lifts */
    if (GameBit_Get(0x57) != 0 || sub->duration >= 0xa)
    {
        sub->timer = 0x3c;
    }
    sub->active = 1;
    if (sub->gamebit != -1)
    {
        if (GameBit_Get(sub->gamebit) != 0)
        {
            sub->timer = 0x3c;
        }
        else
        {
            sub->active = 0;
            ((GameObject*)obj)->anim.alpha = 0;
        }
    }
    {
        WindLiftSub* p = sub;
        for (i = 0; i < WINDLIFT_SLOTS; i++)
        {
            p->slots[i].phaseFlags = 0;
            p->slots[i].phaseFlags &= ~0xf1;
            p->slots[i].f4 = lbl_803E4168;
            p->slots[i].riseSpeed = lbl_803E416C;
            p->slots[i].speedDelta = lbl_803E416C;
            p->slots[i].riderObj = 0;
            p->slots[i].oscCounter = 0;
        }
    }
    ObjGroup_AddObject(obj, CFWINDLIFT_OBJGROUP);
}

void windlift_release(void)
{
}

void windlift_initialise(void)
{
}

u8 gWindLiftSeqDurationTable[] = {
    0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x59, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x0A, 0xD7, 0x00, 0x00, 0x00, 0x04,
};

u8 gWindLiftSeqGamebitTable[] = {
    0x00, 0x00, 0x0A, 0x94, 0x00, 0x00, 0x00, 0x95,
    0x00, 0x00, 0x0A, 0x98, 0x00, 0x00, 0x00, 0x95,
    0x00, 0x00, 0x0A, 0x99, 0x00, 0x00, 0x00, 0x95,
};

/* descriptor/ptr table auto 0x80322a80-0x80322b28 */
u32 gWindLiftObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)windlift_initialise, (u32)windlift_release, 0x00000000, (u32)windlift_init, (u32)windlift_update, (u32)windlift_hitDetect, (u32)windlift_render, (u32)windlift_free, (u32)windlift_getObjectTypeId, (u32)windlift_getExtraSize };
u32 gCFPowerBaseObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)cfpowerbase_initialise, (u32)cfpowerbase_release, 0x00000000, (u32)cfpowerbase_init, (u32)cfpowerbase_update, (u32)cfpowerbase_hitDetect, (u32)cfpowerbase_render, (u32)cfpowerbase_free, (u32)cfpowerbase_getObjectTypeId, (u32)cfpowerbase_getExtraSize };
u32 gCFMainCrystalObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)cfmaincrystal_initialise, (u32)cfmaincrystal_release, 0x00000000, (u32)cfmaincrystal_init, (u32)cfmaincrystal_update, (u32)cfmaincrystal_hitDetect, (u32)cfmaincrystal_render, (u32)cfmaincrystal_free, (u32)cfmaincrystal_getObjectTypeId, (u32)cfmaincrystal_getExtraSize };
