#include "global.h"
#include "dolphin/mtx.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/baddie_state.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/waterfx_interface.h"
#include "main/game_object.h"
#include "main/newshadows_audio_api.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "track/intersect.h"

typedef struct
{
    s16 id;
    s16 unk2;
    s16 unk4;
    f32 scale;
    Vec pos;
} SplashFxParams;

extern u8 lbl_8030E8B0[];
extern f32 lbl_803DEE20;
extern f32 lbl_803DEE24;
extern f32 lbl_803DEE28;

void* jumptable_8030E9B4[11] = {
    (void*)((u8*)objAudioFn_8006ef38 + 0x9C), (void*)((u8*)objAudioFn_8006ef38 + 0x54),
    (void*)((u8*)objAudioFn_8006ef38 + 0x9C), (void*)((u8*)objAudioFn_8006ef38 + 0x5C),
    (void*)((u8*)objAudioFn_8006ef38 + 0x64), (void*)((u8*)objAudioFn_8006ef38 + 0x6C),
    (void*)((u8*)objAudioFn_8006ef38 + 0x74), (void*)((u8*)objAudioFn_8006ef38 + 0x94),
    (void*)((u8*)objAudioFn_8006ef38 + 0x7C), (void*)((u8*)objAudioFn_8006ef38 + 0x8C),
    (void*)((u8*)objAudioFn_8006ef38 + 0x84)};
void* jumptable_8030E9E0[11] = {
    (void*)((u8*)fn_8006F388 + 0x70), (void*)((u8*)fn_8006F388 + 0x28),
    (void*)((u8*)fn_8006F388 + 0x70), (void*)((u8*)fn_8006F388 + 0x30),
    (void*)((u8*)fn_8006F388 + 0x38), (void*)((u8*)fn_8006F388 + 0x40),
    (void*)((u8*)fn_8006F388 + 0x48), (void*)((u8*)fn_8006F388 + 0x68),
    (void*)((u8*)fn_8006F388 + 0x50), (void*)((u8*)fn_8006F388 + 0x60),
    (void*)((u8*)fn_8006F388 + 0x58)};

void objAudioFn_8006ef38(GameObject* obj, ObjAnimEventList* events, u8 type, void* points, void* state, f32 unused,
                         f32 scale)
{
    Vec v;
    SplashFxParams ps;
    u8* tbl;
    u16* sfxTab;
    u8 flags;
    u8 i;
    int sfx;
    u8 vecIdx;
    u8 cnt;
    f32* vec;
    int n;
    void* desc;

    tbl = lbl_8030E8B0;
    switch (type)
    {
    case 1:
        sfxTab = (u16*)tbl;
        break;
    case 3:
        sfxTab = (u16*)(tbl + 0x14);
        break;
    case 4:
        sfxTab = (u16*)(tbl + 0x3C);
        break;
    case 5:
        sfxTab = (u16*)(tbl + 0x64);
        break;
    case 6:
        sfxTab = (u16*)(tbl + 0x50);
        break;
    case 8:
        sfxTab = (u16*)(tbl + 0x78);
        break;
    case 10:
        sfxTab = (u16*)(tbl + 0x8C);
        break;
    case 9:
        sfxTab = (u16*)(tbl + 0xA0);
        break;
    case 7:
        sfxTab = (u16*)(tbl + 0x28);
        break;
    default:
        sfxTab = (u16*)(tbl + 0x28);
        break;
    }
    flags = 0;
    for (i = 0; i < events->triggerCount; i++)
    {
        switch (events->triggeredIds[i])
        {
        case 1:
            flags |= 1;
            vecIdx = 0;
            break;
        case 2:
            flags |= 2;
            vecIdx = 1;
            break;
        case 3:
            flags |= 4;
            vecIdx = 2;
            break;
        case 4:
            flags |= 8;
            vecIdx = 3;
            break;
        }
    }
    if (flags == 0)
    {
        return;
    }
    if (!(((BaddieState*)state)->contactSfxFlags & 0x10) && ((BaddieState*)state)->contactSfxMuted != 0)
    {
        return;
    }
    n = ((BaddieState*)state)->surfaceSoundIndex;
    if (n < 0 || n >= 0x23)
    {
        n = 0;
    }
    else
    {
        n = tbl[0xb4 + n];
    }
    sfx = n;
    desc = ((BaddieState*)state)->contactObj;
    if (desc != NULL)
    {
        switch (((GameObject*)desc)->anim.seqId)
        {
        case 0x5d:
        case 0x99:
        case 0x1db:
        case 0x223:
            sfx = 4;
        }
    }
    if (sfxTab != NULL)
    {
        vec = (f32*)points + vecIdx * 3;
        if (((BaddieState*)state)->waterDepth > lbl_803DEE20)
        {
            (*gWaterfxInterface)->spawnImpactSurface((u8*)obj, flags, (f32*)points, (u8*)state, unused);
            sfx = 5;
        }
        if (obj == Obj_GetPlayerObject())
        {
            if (*(s16*)(*(u32*)&obj->extra + 0x81a) == 1)
            {
                Sfx_PlayFromObject(0, SFXTRIG_foot_ice_scuff);
            }
            Sfx_PlayFromObject(0, sfxTab[sfx]);
        }
        else
        {
            Sfx_PlayAtPositionFromObject((int)obj, vec[0], vec[1], vec[2], sfxTab[sfx]);
        }
    }
    if (i == 5)
    {
        return;
    }
    i = 0;
    scale = lbl_803DEE24 * scale;
    while (flags != 0)
    {
        vec = (f32*)points + i * 3;
        v.x = vec[0];
        v.y = vec[1];
        v.z = vec[2];
        if (flags & 1)
        {
            if (obj->anim.classId == 1 || obj->anim.seqId == 0x416)
            {
                playerEarthWalkerAudioFn_8006f950((u8*)obj, (f32*)&v, i & 1, sfx);
            }
            ps.pos.x = vec[0];
            ps.pos.y = vec[1];
            ps.pos.z = vec[2];
            ps.scale = scale;
            ps.id = sfx;
            ps.unk4 = 0;
            ps.unk2 = 0;
            v.x = lbl_803DEE28 * obj->anim.velocityX;
            v.y = lbl_803DEE28 * obj->anim.velocityY;
            v.z = lbl_803DEE28 * obj->anim.velocityZ;
            if (sfx == 6 || sfx == 3)
            {
                cnt = randomGetRange(2, 4);
                while (cnt != 0)
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x7e6, &ps, 0x200001, -1, &v);
                    cnt--;
                }
            }
            else if (sfx == 2)
            {
                cnt = randomGetRange(4, 8);
                while (cnt != 0)
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x7e6, &ps, 0x200001, -1, &v);
                    cnt--;
                }
            }
        }
        flags = flags >> 1;
        i++;
    }
}

void* fn_8006F388(u32 i)
{
    u8* base = lbl_8030E8B0;
    switch (i)
    {
    case 1:
        return base;
    case 3:
        return base + 0x14;
    case 4:
        return base + 0x3C;
    case 5:
        return base + 0x64;
    case 6:
        return base + 0x50;
    case 8:
        return base + 0x78;
    case 10:
        return base + 0x8C;
    case 9:
        return base + 0xA0;
    case 7:
        return base + 0x28;
    default:
        return base + 0x28;
    }
}
