/*
 * dimcannon (DLL 0x1C6) - DIM lava cannon; a stationary turret that tracks
 * and fires cannonballs at the player, with a manned-control mode (fireState 3)
 * in which the player aims with the stick, charges with A, and fires on release.
 * The 0x1D6 sub-variant is a falling-debris prop shared with DIMwooddoor.
 */
#include "main/dll/DIM/dimcannon_state.h"
#include "main/camera_interface.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/dll/DIM/DIMlevcontrol.h"
#include "main/dll/player_status.h"
#include "main/objseq.h"
#include "main/resource.h"

extern u64 ObjGroup_RemoveObject();
extern u32 ObjPath_GetPointWorldPosition();


#pragma scheduling on
#pragma peephole on
extern void objRenderFn_8003b8f4(f32 x);
extern f32 lbl_803E48E8;
STATIC_ASSERT(sizeof(DimCannonState) == 0xb4);
extern void* lbl_803DDB50;
extern void ObjMsg_AllocQueue(int* obj, int n);
extern int fn_801B2550(int* obj, int p2, ObjAnimUpdateState* animUpdate);
extern f32 lbl_803E48B8;
extern void DIMwooddoor_updateFallingDebris(int* obj);
extern void DIMwooddoor_updateShardAim(int* obj, f32 a, f32 b, f32 c, f32 d);
extern void DIMwooddoor_spawnShard(int* obj, int p2);
extern f32 getXZDistance(f32 * a, f32 * b);
extern void* fn_802972A8(void* player);
extern void buttonDisable(int chan, int mask);
extern u8 framesThisStep;
extern f32 timeDelta;
extern int lbl_803DBF10;
extern int lbl_803DBF0C;
extern f32 lbl_803E48EC;
extern f32 lbl_803E48F0;
extern f32 lbl_803DBEF4;
extern void setAButtonIcon(int icon);
extern void setBButtonIcon(int icon);
extern void hudFn_8011f38c(int v);
extern s16* objModelGetVecFn_800395d8(int* obj, int p2);
extern s8 padGetStickX(int chan);
extern void playerAddRemoveMagic(void* player, int amount);
extern u32 getButtonsJustPressed(int chan);
extern u32 getButtonsHeld(int chan);
extern u32 getButtonsJustPressedIfNotBusy(int chan);
extern u8 lbl_803DBF00;
extern s16 lbl_803DBF02;
extern s16 lbl_803DBF04;
extern f32 lbl_803DBF08;
extern f32 lbl_803DBEF8;
extern f32 lbl_803DBEFC;

#pragma scheduling off
#pragma peephole off
void dimcannon_hitDetect(void)
{
}

void dimcannon_release(void)
{
}

void dimcannon_initialise(void)
{
}

void dimcannon_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* def;
    u8* sub;
    s16 saved;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->anim.seqId != 0x1d6)
    {
        sub = ((GameObject*)obj)->extra;
        saved = ((GameObject*)obj)->anim.rotX;
        ((GameObject*)obj)->anim.rotX = (s16)((s8)def[0x28] << 8);
        ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E48E8);
        ((GameObject*)obj)->anim.rotX = saved;
        ObjPath_GetPointWorldPosition((int)obj, 0, (f32*)(sub + 0x8c), (f32*)(sub + 0x90), (f32*)(sub + 0x94), 0);
    }
    else
    {
        ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E48E8);
    }
}

void dimlavasmash_free(void);

typedef struct DimcannonPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    u8 pad20[0x26 - 0x20];
    s16 unk26;
    s8 unk28;
    u8 pad29[0x30 - 0x29];
} DimcannonPlacement;

typedef struct DimcannonState
{
    u8 pad0[0x7 - 0x0];
    u8 unk7;
    u8 pad8[0x9 - 0x8];
    s8 unk9;
    s8 unkA;
    s8 unkB;
    u8 padC[0x10 - 0xC];
} DimcannonState;

/* dimcannon extra block (0xb4); the head is the per-cannonball column
 * arrays walked via state + i*4 (kept raw), this names the scalar tail. */

int dimcannon_getExtraSize(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x1d6) return 0xc;
    return 0xb4;
}

int dimcannon_getObjectTypeId(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x1d6) return 0x0;
    return 0x0;
}

#pragma dont_inline on
#pragma dont_inline reset

void dimcannon_free(int* obj)
{
    if (((GameObject*)obj)->anim.seqId != 0x1d6)
    {
        ((void (*)(void))((int**)*gGameUIInterface)[0x18])();
        Resource_Release(lbl_803DDB50);
        lbl_803DDB50 = NULL;
    }
    ObjGroup_RemoveObject(obj, 3);
}

#define DIMCANNON_MAP_EVENT_SLOT_PLAYER_OPERATED 0x13

void dimcannon_init(int* obj, int* arg)
{
    ObjMsg_AllocQueue(obj, 4);

    if (((GameObject*)obj)->anim.seqId == 0x1d6)
    {
        void* state;
        int* p;
        ((GameObject*)obj)->unkF4 = 0;
        p = *(int**)&((GameObject*)obj)->anim.modelState;
        if (p != 0)
        {
            *(int*)&((ObjHitsPriorityState*)p)->secondaryRadiusY |= 0xc10;
            p = *(int**)&((GameObject*)obj)->anim.modelState;
            *(u32*)&((ObjHitsPriorityState*)p)->secondaryRadiusY |= 0x8000LL;
        }
        state = ((GameObject*)obj)->extra;
        ((DimcannonState*)state)->unk9 = randomGetRange(-0x64, 0x64);
        ((DimcannonState*)state)->unkA = randomGetRange(-0x64, 0x64);
        ((DimcannonState*)state)->unkB = randomGetRange(-0x64, 0x64);
        ((DimcannonState*)state)->unk7 = 1;
        p = *(int**)&((GameObject*)obj)->anim.hitReactState;
        if (p != 0)
        {
            *(s16*)&((ObjHitsPriorityState*)p)->trackContactMask = 1;
        }
        ((GameObject*)obj)->objectFlags |= 0x4000;
    }
    else
    {
        void* state = ((GameObject*)obj)->extra;
        u8 i;

        if (((GameObject*)obj)->anim.mapEventSlot == DIMCANNON_MAP_EVENT_SLOT_PLAYER_OPERATED)
        {
            int v = 0;
            if (GameBit_Get(0xc17) && GameBit_Get(0xa21))
            {
                v = 1;
            }
            ((DimCannonState*)state)->unkB2 = v;
        }

        for (i = 0; i < 0xa; i += 5)
        {
            *(f32*)((char*)state + i * 4 + 0x14) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)state + i * 4 + 0x3c) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)state + i * 4 + 0x64) = ((GameObject*)obj)->anim.localPosZ;
            *(f32*)((char*)state + i * 4 + 0x18) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)state + i * 4 + 0x40) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)state + i * 4 + 0x68) = ((GameObject*)obj)->anim.localPosZ;
            *(f32*)((char*)state + i * 4 + 0x1c) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)state + i * 4 + 0x44) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)state + i * 4 + 0x6c) = ((GameObject*)obj)->anim.localPosZ;
            *(f32*)((char*)state + i * 4 + 0x20) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)state + i * 4 + 0x48) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)state + i * 4 + 0x70) = ((GameObject*)obj)->anim.localPosZ;
            *(f32*)((char*)state + i * 4 + 0x24) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)state + i * 4 + 0x4c) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)state + i * 4 + 0x74) = ((GameObject*)obj)->anim.localPosZ;
        }

        ((DimCannonState*)state)->unkAF = 0x80;
        ((DimCannonState*)state)->unk98 = lbl_803E48B8;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x8;
        ((GameObject*)obj)->animEventCallback = fn_801B2550;
        ((GameObject*)obj)->anim.rotX = (s16)((s8) * (s8*)((char*)arg + 0x28) << 8);
        lbl_803DDB50 = Resource_Acquire(0x79, 1);
        if (GameBit_Get(*(s16*)((char*)arg + 0x1a)))
        {
            *(u8*)&((DimCannonState*)state)->unkB0 = 0x3c;
            ((DimCannonState*)state)->fireState = 5;
        }
        ((DimCannonState*)state)->unk8C = ((GameObject*)obj)->anim.localPosX;
        ((DimCannonState*)state)->unk90 = ((GameObject*)obj)->anim.localPosY;
        ((DimCannonState*)state)->unk94 = ((GameObject*)obj)->anim.localPosZ;
    }

    ((GameObject*)obj)->objectFlags |= 0x2000;
}

void dimcannon_update(int* obj)
{
    extern void* Obj_GetPlayerObject(void);
    char* state;
    void* player;
    int* src = *(int**)&((GameObject*)obj)->anim.placementData;

    if (((GameObject*)obj)->anim.seqId == 0x1d6)
    {
        DIMwooddoor_updateFallingDebris(obj);
        return;
    }

    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x8) && GameBit_Get(((DimcannonPlacement*)src)->unk1A))
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x8);
    }

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (fn_802972A8(player) != 0)
    {
        *(int*)(state + 0x0) = 0;
    }
    else
    {
        *(void**)(state + 0x0) = player;
    }

    ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);

    switch (((DimCannonState*)state)->fireState)
    {
    case 0:
        if (GameBit_Get(((DimcannonPlacement*)src)->unk1C))
        {
            ((DimCannonState*)state)->fireState = 4;
        }
        break;
    case 5:
        {
            s8 t = ((DimCannonState*)state)->unkB0;
            if (t > 0)
            {
                ((DimCannonState*)state)->unkB0 = (s8)(t - framesThisStep);
            }
            else if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x1)
            {
                int* focusObj;
                ((DimCannonState*)state)->unkAE = 0;
                ((DimCannonState*)state)->unkB1 = 0;
                focusObj = obj;
                (*gCameraInterface)->setMode(0x51, 1, 0, 4, &focusObj, 0x32, 0xff);
                buttonDisable(0, 0x100);
                ((DimCannonState*)state)->fireState = 3;
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                *(u8*)&((DimCannonState*)state)->unkB0 = 0x3c;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x8;
            }
            ((DimCannonState*)state)->unkAD = 0;
            ((DimCannonState*)state)->aimYaw = 0;
            ((DimCannonState*)state)->aimPitch = 0;
            break;
        }
    case 4:
        DIMwooddoor_updateShardAim(obj, *(f32*)&((DimCannonState*)state)->unk4, *(f32*)&((DimCannonState*)state)->unk8,
                                   ((DimCannonState*)state)->unkC, ((DimCannonState*)state)->unk10);
        if (GameBit_Get(((DimcannonPlacement*)src)->unk1A))
        {
            ((DimCannonState*)state)->fireState = 5;
        }
        else if (*(void**)(state + 0x0) != 0 && !GameBit_Get(((DimcannonPlacement*)src)->unk1E))
        {
            f32 d = getXZDistance(&((GameObject*)obj)->anim.worldPosX,
                                  (f32*)(*(char**)(state + 0x0) + 0x18));
            int v = ((DimcannonPlacement*)src)->unk26 * lbl_803DBF10;
            if (d < v / lbl_803E48EC)
            {
                ((DimCannonState*)state)->fireState = 1;
            }
        }
        ((DimCannonState*)state)->unkAD = 0;
        ((DimCannonState*)state)->aimYaw = 0;
        ((DimCannonState*)state)->aimPitch = 0;
        break;
    case 1:
        if (GameBit_Get(((DimcannonPlacement*)src)->unk1A))
        {
            ((DimCannonState*)state)->fireState = 5;
            break;
        }
        if (GameBit_Get(((DimcannonPlacement*)src)->unk1E))
        {
            ((DimCannonState*)state)->fireState = 4;
            break;
        }
        if (*(void**)(state + 0x0) != 0)
        {
            ((DimCannonState*)state)->unkAF += framesThisStep;
            if (((DimCannonState*)state)->unkAF > 0xa)
            {
                char* e;
                u8 j;
                ((DimCannonState*)state)->unkAF = 0;
                for (j = 0; j < 9; j++)
                {
                    e = state + j * 4;
                    *(f32*)(e + 0x14) = *(f32*)(e + 0x18);
                    *(f32*)(e + 0x3c) = *(f32*)(e + 0x40);
                    *(f32*)(e + 0x64) = *(f32*)(e + 0x68);
                    if (j == 0 || *(f32*)(e + 0x3c) > *(f32*)&((DimCannonState*)state)->unk8)
                    {
                        *(f32*)&((DimCannonState*)state)->unk8 = *(f32*)(e + 0x3c);
                    }
                }
                *(f32*)(state + 0x38) = *(f32*)(*(char**)(state + 0x0) + 0xc);
                *(f32*)(state + 0x60) = *(f32*)(*(char**)(state + 0x0) + 0x10);
                ((DimCannonState*)state)->unk88 = *(f32*)(*(char**)(state + 0x0) + 0x14);
                *(f32*)&((DimCannonState*)state)->unk4 = *(f32*)(state + 0x14);
                ((DimCannonState*)state)->unkC = *(f32*)(state + 0x64);
            }
            if (((DimCannonState*)state)->aimYaw > 0)
            {
                ((DimCannonState*)state)->aimYaw -= framesThisStep;
            }
            if (((DimCannonState*)state)->aimPitch > 0)
            {
                ((DimCannonState*)state)->aimPitch -= framesThisStep;
            }
            ((DimCannonState*)state)->unk10 = getXZDistance(&((GameObject*)obj)->anim.worldPosX,
                                                            (f32*)(*(char**)(state + 0x0) + 0x18));
            DIMwooddoor_updateShardAim(obj, *(f32*)&((DimCannonState*)state)->unk4,
                                       *(f32*)&((DimCannonState*)state)->unk8,
                                       ((DimCannonState*)state)->unkC, ((DimCannonState*)state)->unk10);
            DIMwooddoor_spawnShard(obj, 0);
            {
                f32 d2 = ((DimCannonState*)state)->unk10;
                int v = ((DimcannonPlacement*)src)->unk26 * lbl_803DBF0C;
                if (d2 > v / lbl_803E48EC)
                {
                    ((DimCannonState*)state)->fireState = 4;
                }
            }
        }
        else
        {
            ((DimCannonState*)state)->fireState = 4;
        }
        break;
    }

    lbl_803DBEF4 = lbl_803E48F0;
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E48F0, timeDelta, NULL);
}

int fn_801B2550(int* obj, int p2, ObjAnimUpdateState* animUpdate)
{
    extern void* Obj_GetPlayerObject(void);
    char* state;
    int* src = *(int**)&((GameObject*)obj)->anim.placementData;
    int delta;
    u8 done = 0;
    int camMode;

    animUpdate->sequenceEventActive = 0;
    animUpdate->hitVolumePair &= ~0x608;
    state = ((GameObject*)obj)->extra;

    if (((DimCannonState*)state)->fireState == 0x3)
    {
        s16* vec;
        s8 timer;
        void* player;

        player = Obj_GetPlayerObject();
        setAButtonIcon(0x16);
        setBButtonIcon(0x17);
        hudFn_8011f38c(1);
        camMode = (*gCameraInterface)->getMode();
        if (camMode != 0x51 && camMode != 0x4c)
        {
            int* focusObj = obj;
            (*gCameraInterface)->setMode(0x51, 1, 0, 4, &focusObj, 0x32, 0xff);
        }
        if (camMode != 0x51)
        {
            return 0;
        }
        vec = objModelGetVecFn_800395d8(obj, 0);
        timer = ((DimCannonState*)state)->unkB0;
        if (timer > 0)
        {
            ((DimCannonState*)state)->unkB0 = (s8)(timer - framesThisStep);
            if (((DimCannonState*)state)->unkB0 <= 0)
            {
                (*gGameUIInterface)->initAirMeter(lbl_803DBF00, 0x5d5);
            }
        }
        else
        {
            if (!GameBit_Get(0xdb))
            {
                (*gGameUIInterface)->showNpcDialogue(0x4b9, 0x14, 0x8c, 1);
                GameBit_Set(0xdb, 1);
            }
            delta = (int)(-lbl_803DBF08 * padGetStickX(0));
            if (delta != 0)
            {
                s16 mag = *(s16*)((char*)vec + 0x2) < 0 ? -*(s16*)((char*)vec + 0x2) : *(s16*)((char*)vec + 0x2);
                if (mag > lbl_803DBF02 - lbl_803DBF04)
                {
                    int sc, sd;
                    sd = delta < 0 ? -1 : (delta > 0 ? 1 : 0);
                    sc = *(s16*)((char*)vec + 0x2) < 0 ? -1 : (*(s16*)((char*)vec + 0x2) > 0 ? 1 : 0);
                    if (sc == sd)
                    {
                        delta = delta * (lbl_803DBF02 - mag);
                        delta = delta / lbl_803DBF04;
                    }
                }
                *(s16*)((int)vec + 0x2) = (s16)(*(s16*)((int)vec + 0x2) + delta);
                Sfx_KeepAliveLoopedObjectSound((u32)obj, 0x1ff);
            }
            else
            {
                if (((DimCannonState*)state)->unkA8 != 0)
                {
                    Sfx_PlayFromObject((u32)obj, 0x1fe);
                }
            }
            ((DimCannonState*)state)->unkA8 = delta;
            if (((DimCannonState*)state)->aimYaw > 0)
            {
                ((DimCannonState*)state)->aimYaw -= framesThisStep;
            }
            if (((DimCannonState*)state)->aimPitch > 0)
            {
                ((DimCannonState*)state)->aimPitch -= framesThisStep;
            }
            if ((getButtonsHeld(0) & 0x100) && ((DimCannonState*)state)->aimYaw <= 0)
            {
                buttonDisable(0, 0x100);
                if (Player_GetCurrentMagic((int)player) >= 1)
                {
                    ((DimCannonState*)state)->unkAE += framesThisStep;
                    if (Sfx_IsPlayingFromObjectChannel((u32)obj, 2) == 0)
                    {
                        Sfx_PlayFromObject((u32)obj, 0x201);
                        Sfx_PlayFromObject((u32)obj, 0x202);
                    }
                }
                else
                {
                    Sfx_PlayFromObject((u32)obj, 0x40c);
                }
            }
            else
            {
                Sfx_StopObjectChannel((u32)obj, 2);
            }
            if (((DimCannonState*)state)->unkAE > lbl_803DBF00)
            {
                ((DimCannonState*)state)->unkAE = lbl_803DBF00;
            }
            (*gGameUIInterface)->runAirMeter(((DimCannonState*)state)->unkAE);
            ((DimCannonState*)state)->unk98 = (f32)((DimCannonState*)state)->unkAE * lbl_803DBEFC + lbl_803DBEF8;
            if ((getButtonsJustPressedIfNotBusy(0) & 0x100) ||
                ((DimCannonState*)state)->unkAE == lbl_803DBF00)
            {
                if (((DimCannonState*)state)->aimYaw <= 0 && Player_GetCurrentMagic((int)player) >= 1)
                {
                    buttonDisable(0, 0x100);
                    playerAddRemoveMagic(player, -1);
                    ((DimCannonState*)state)->unkAD = 1;
                    ((DimCannonState*)state)->unkAE = 0;
                }
            }
            DIMwooddoor_spawnShard(obj, 1);
            if (((GameObject*)obj)->anim.mapEventSlot == DIMCANNON_MAP_EVENT_SLOT_PLAYER_OPERATED && ((DimCannonState*)state)->unkB2 == 0 &&
                GameBit_Get(0xc17) && GameBit_Get(0xa21))
            {
                ((DimCannonState*)state)->unkB2 = 1;
                ((DimCannonState*)state)->unkB1 = 1;
            }
            {
                u8 b1 = ((DimCannonState*)state)->unkB1;
                if (b1 != 0)
                {
                    ((DimCannonState*)state)->unkB1 += framesThisStep;
                    if (((DimCannonState*)state)->unkB1 > 0x3c)
                    {
                        done = 1;
                    }
                }
            }
            if (done != 0 || (getButtonsJustPressed(0) & 0x200))
            {
                buttonDisable(0, 0x200);
                hudFn_8011f38c(0);
                (*gGameUIInterface)->airMeterSetShutdown();
                (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
                ((DimCannonState*)state)->fireState = 5;
                *(u8*)&((DimCannonState*)state)->unkB0 = 0x3c;
                animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x8);
                if (Sfx_IsPlayingFromObjectChannel((u32)obj, 8) != 0)
                {
                    Sfx_IsPlayingFromObjectChannel((u32)obj, 0);
                }
                Sfx_StopObjectChannel((u32)obj, 2);
            }
            ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803DBEF4, timeDelta, NULL);
        }
    }
    else
    {
        s16* vec2;
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
        vec2 = objModelGetVecFn_800395d8(obj, 0);
        *(s16*)((char*)vec2 + 0x2) =
            (s16)(((GameObject*)obj)->anim.rotX - ((s8) * (s8*)((char*)src + 0x28) << 8));
        ((GameObject*)obj)->anim.rotX = (s16)((s8) * (s8*)((char*)src + 0x28) << 8);
        ((DimCannonState*)state)->fireState = 4;
    }

    return 0;
}
