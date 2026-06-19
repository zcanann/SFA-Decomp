/*
 * carryable (DLL 0x2F) - generic pick-up-and-carry prop object.
 *
 * The object joins object group 0x10 at init and leaves it on free. Its
 * extra state (CarryableUpdateHeldState) tracks a carry phase in unk5
 * (0 = resting, 1 = grabbed/carried, 2 = being put down) plus a small
 * flag byte at offset 7. Carryable_updateHeld drives the per-frame
 * behaviour: while resting it watches for a grab (surface code 6 under the
 * player + the A-button slot free), then runs vertical hit-detection
 * (hitDetectFn_80065e50) to settle the prop onto the surface beneath it and
 * record the highest surface type it overlaps; while carried it watches the
 * drop button, replays the put-down, and forwards a carry message to the
 * player object. Drop/save persists the prop's resting position through
 * saveGame_saveObjectPos. Carryable_updateRenderState toggles the model's
 * shadow-fade based on whether a sequence is playing.
 *
 * flag byte (state[7]) bits: 0x01 just-grabbed, 0x02 (inverted accessor),
 * 0x04, 0x08 suppress position save.
 */
#include "main/game_object.h"
#include "main/dll/player_objects.h"

typedef struct CarryableUpdateHeldState
{
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    u8 pad4[0x5 - 0x4];
    s8 unk5;
    u8 unk6;
    u8 unk7;
    u8 unk8;
    u8 pad9[0x10 - 0x9];
} CarryableUpdateHeldState;

extern void* Obj_GetPlayerObject(void);
extern void playerSetHeldObject(void* player, int held);
extern u32 buttonGetDisabled(int idx);
extern void buttonDisable(int index, u32 flags);
extern u32 getButtonsJustPressed(int idx);
extern int fn_80295BF0(void* player);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int hitDetectFn_80065e50(u8* obj, f32 x, f32 y, f32 z, f32*** list, int a, int b);
extern f32 timeDelta;
extern const f32 lbl_803E06D8, lbl_803E06DC, lbl_803E06E0, lbl_803E06E4, lbl_803E06E8;
extern void saveGame_saveObjectPos(int* obj);

void objSaveFn_800ea774(int* obj)
{
    u8* sub = ((GameObject*)obj)->extra;
    sub[5] = 0;
    sub[6] = 0;
    if ((sub[7] & 8) == 0)
    {
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E06D8;
        saveGame_saveObjectPos(obj);
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E06D8;
    }
}

void Carryable_stopCarrying(int* obj, u8* param2)
{
    void* player = Obj_GetPlayerObject();
    int held;
    param2[5] = 0;
    Player_GetHeldObject((int)player, &held);
    if ((int*)held == obj)
    {
        playerSetHeldObject(player, 0);
    }
}

void Carryable_setFlag08(u8* state, u8 enable)
{
    if (enable != 0)
    {
        state[7] |= 8;
    }
    else
    {
        state[7] &= ~8;
    }
}

s32 Carryable_getFlag04(u8* state) { return (state[7] & 4) != 0; }

void Carryable_setFlag04(u8* state, u8 enable)
{
    if (enable != 0)
    {
        state[7] |= 4;
    }
    else
    {
        state[7] &= ~4;
    }
}

void Carryable_setFlag02Inverted(u8* state, u8 clear)
{
    if (clear != 0)
    {
        state[7] &= ~2;
    }
    else
    {
        state[7] |= 2;
    }
}

u8 Carryable_getSurfaceType(u8* state) { return state[8]; }

s32 Carryable_getFlag01(u8* state) { return state[7] & 1; }

s32 Carryable_isHeld(u8* state) { return *(s8*)(state + 0x5); }

void Carryable_free(int x) { ObjGroup_RemoveObject(x, 0x10); }

int Carryable_updateRenderState(int* obj, int flag)
{
    int* p50 = *(int**)&((GameObject*)obj)->anim.modelInstance;
    if (((ObjDef*)p50)->shadowType == 2)
    {
        if (((GameObject*)obj)->seqIndex == -1)
        {
            ((GameObject*)obj)->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        else
        {
            ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if (((GameObject*)obj)->unkF8 != 0)
    {
        if (flag != -1) return 0;
    }
    else
    {
        if (flag == 0) return 0;
    }
    return 1;
}

int Carryable_updateHeld(u8* obj)
{
    f32** list;
    u8* held;
    void* player;
    held = ((GameObject*)obj)->extra;
    ((CarryableUpdateHeldState*)held)->unk8 = 0;
    ((CarryableUpdateHeldState*)held)->unk7 &= ~1;
    player = Obj_GetPlayerObject();
    if (((CarryableUpdateHeldState*)held)->unk5 == 0)
    {
        struct
        {
            u8 a, b, c, d, e;
        } * t;
        int v = 0;
        t = (void*)*(u8**)(obj + 0x78);
        if ((t[((GameObject*)obj)->unkE4].e & 0xf) == 6
            && (buttonGetDisabled(0) & 0x100) == 0
            && (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0
            && ((GameObject*)obj)->unkF8 == 0)
        {
            *(s16*)held = 0;
            buttonDisable(0, 0x100);
            v = 1;
        }
        ((CarryableUpdateHeldState*)held)->unk5 = v;
        if (((CarryableUpdateHeldState*)held)->unk5 != 0)
        {
            ((CarryableUpdateHeldState*)held)->unk7 |= 1;
            ((CarryableUpdateHeldState*)held)->unk6 = 1;
        }
        if (((GameObject*)obj)->unkF8 == 0)
        {
            int cnt, i, j;
            f32** p;
            u8* hit;
            ObjHits_SyncObjectPositionIfDirty(obj);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
            if ((((CarryableUpdateHeldState*)held)->unk7 & 2) == 0)
            {
                ((GameObject*)obj)->anim.velocityY = -(lbl_803E06DC * timeDelta - ((GameObject*)obj)->anim.velocityY);
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)
                    ->anim.localPosY;
            }
            cnt = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                       ((GameObject*)obj)->anim.localPosZ, &list, 0, 1);
            hit = 0;
            i = 0;
            p = list;
            for (j = cnt; j > 0; j--)
            {
                if (*(s8*)((u8*)*p + 0x14) != 0xe)
                {
                    if (((GameObject*)obj)->anim.localPosY < **p && ((GameObject*)obj)->anim.localPosY > **p -
                        lbl_803E06E0)
                    {
                        hit = *(u8**)(list[i] + 4);
                        ((GameObject*)obj)->anim.localPosY = *list[i];
                        ((GameObject*)obj)->anim.velocityY = lbl_803E06E4;
                        break;
                    }
                }
                p++;
                i++;
            }
            i = 0;
            for (; cnt > 0; cnt--)
            {
                f32 d = ((GameObject*)obj)->anim.localPosY - *list[i];
                if (d < lbl_803E06E4)
                {
                    d = -d;
                }
                if (d < lbl_803E06E8)
                {
                    s8 t2 = *(s8*)((u8*)list[i] + 0x14);
                    if (t2 > ((CarryableUpdateHeldState*)held)->unk8)
                    {
                        *(s8*)&((CarryableUpdateHeldState*)held)->unk8 = t2;
                    }
                }
                i++;
            }
            if (hit != 0)
            {
                u8* q = *(u8**)(hit + 0x58);
                u8 c = *(u8*)(q + 0x10f);
                *(u8*)(q + 0x10f) = c + 1;
                ((void**)(q + 0x100))[(s8)c] = obj;
            }
        }
    }
    else
    {
        ObjHits_MarkObjectPositionDirty(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        if ((getButtonsJustPressed(0) & 0x100) != 0)
        {
            if ((((CarryableUpdateHeldState*)held)->unk7 & 4) != 0 || fn_80295BF0(player) == 0)
            {
                Sfx_PlayFromObject(0, 0x10a);
            }
            else
            {
                buttonDisable(0, 0x100);
                ((CarryableUpdateHeldState*)held)->unk6 = 0;
            }
        }
        if (((GameObject*)obj)->unkF8 == 1)
        {
            ((CarryableUpdateHeldState*)held)->unk5 = 2;
        }
        if (((CarryableUpdateHeldState*)held)->unk5 == 2 && ((GameObject*)obj)->unkF8 == 0)
        {
            u8* h2 = ((GameObject*)obj)->extra;
            *(u8*)&((CarryableUpdateHeldState*)h2)->unk5 = 0;
            ((CarryableUpdateHeldState*)h2)->unk6 = 0;
            if ((((CarryableUpdateHeldState*)h2)->unk7 & 8) == 0)
            {
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E06D8;
                saveGame_saveObjectPos((int*)obj);
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E06D8;
            }
        }
        if (*(s8*)&((CarryableUpdateHeldState*)held)->unk6 != 0)
        {
            ObjMsg_SendToObject(player, 0x100008, obj,
                                (((CarryableUpdateHeldState*)held)->unk2 << 16) | (u16) * (s16*)held);
        }
    }
    return ((CarryableUpdateHeldState*)held)->unk5;
}

void Carryable_init(int obj, int state)
{
    CarryableUpdateHeldState* s = (CarryableUpdateHeldState*)state;
    ObjGroup_AddObject(obj, 0x10);
    s->unk2 = 0;
    s->unk5 = 0;
    s->pad4[0] = 0;
    s->unk6 = 0;
    ((GameObject*)obj)->unkF8 = 0;
}

void Carryable_release(void)
{
}

void Carryable_initialise(void)
{
}

