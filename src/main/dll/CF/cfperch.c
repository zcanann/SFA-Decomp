#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/cfperch.h"

#define SMALLBASKET_LINKED_ID_BASE 0x40000
#define SMALLBASKET_ROB_WAVE_DIRECT_ID 0x66
#define SMALLBASKET_ROB_WAVE_ID_65D0 0x65d0
#define SMALLBASKET_ROB_WAVE_ID_65D2 0x65d2
#define SMALLBASKET_ROB_WAVE_ID_65D5 0x65d5
#define SMALLBASKET_ROB_WAVE_ID_65D6 0x65d6
#define SMALLBASKET_ROB_WAVE_ID_65D7 0x65d7
#define GAMEBIT_SFX_MUTE 0xa71

extern void* Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32 * a, f32 * b);
extern int GameBit_Get(int id);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern f32 lbl_803E39AC;
extern f32 lbl_803E39BC;
extern f32 lbl_803E39C0;
extern f32 lbl_803E39C4;

extern void ObjGroup_AddObject(int obj, int group);
extern void ObjHits_ClearHitVolumes(int obj);

f32 fn_80183204(int obj)
{
    u8* state = ((GameObject*)obj)->extra;
    return lbl_803E39AC - (f32)(u32)
    state[0x13] / (f32)(u32)
    state[0x28];
}

void fn_80183250(int obj, int def)
{
    int state31;
    int player;
    f32 oldVel;
    int sum;
    u32 adj;
    u32 v;
    f32 limit;

    state31 = *(int*)&((GameObject*)obj)->anim.placementData;
    player = (int)Obj_GetPlayerObject();
    if ((*(u16*)(*(int*)&((GameObject*)obj)->anim.parent + 0xb0) & 0x1000) != 0)
    {
        ((GameObject*)obj)->anim.localPosX = *(f32*)(def + 0x24);
        ((GameObject*)obj)->anim.velocityX = 0.0f;
    }
    else
    {
        oldVel = ((GameObject*)obj)->anim.velocityX;
        sum = *(s16*)(*(int*)&((GameObject*)obj)->anim.parent + 0x4) + *(u16*)(def + 0x20);
        ((GameObject*)obj)->anim.velocityX = -(f32)sum / *(f32*)(def + 0x1c);
        if ((oldVel <= 0.0f && ((GameObject*)obj)->anim.velocityX >= 0.0f) ||
            (oldVel >= 0.0f && ((GameObject*)obj)->anim.velocityX <= 0.0f))
        {
            v = *(u32*)(state31 + 0x14);
            adj = v - SMALLBASKET_LINKED_ID_BASE;
            if ((adj == SMALLBASKET_ROB_WAVE_ID_65D7) ||
                ((adj - SMALLBASKET_ROB_WAVE_ID_65D5) <=
                    (SMALLBASKET_ROB_WAVE_ID_65D6 - SMALLBASKET_ROB_WAVE_ID_65D5)) ||
                (v == SMALLBASKET_ROB_WAVE_DIRECT_ID) || (adj == SMALLBASKET_ROB_WAVE_ID_65D0) ||
                (adj == SMALLBASKET_ROB_WAVE_ID_65D2))
            {
                if (Vec_distance(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX) <
                    lbl_803E39BC)
                {
                    if ((u32)GameBit_Get(GAMEBIT_SFX_MUTE) == 0)
                    {
                        Sfx_PlayFromObject(obj, SFXfend_rob_wave);
                    }
                }
            }
        }
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX + ((GameObject*)obj)->anim.velocityX;
        if (((GameObject*)obj)->anim.localPosX > (limit = lbl_803E39C0 + *(f32*)(def + 0x24)))
        {
            ((GameObject*)obj)->anim.localPosX = limit;
        }
        else
        {
            limit = *(f32*)(def + 0x24) - lbl_803E39C4;
            if (((GameObject*)obj)->anim.localPosX < limit)
            {
                ((GameObject*)obj)->anim.localPosX = limit;
            }
        }
    }
}
