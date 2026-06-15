#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"

typedef struct KtlazerwallPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
} KtlazerwallPlacement;


typedef struct KtlazerwallState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    s32 unk10;
} KtlazerwallState;

int ktlazerwall_getExtraSize(void) { return 0x14; }

int ktlazerwall_getObjectTypeId(void) { return 0x0; }

void ktlazerwall_hitDetect(void)
{
}

void ktlazerwall_initialise(void)
{
}

void ktlazerwall_release(void)
{
}

void ktlazerwall_free(int obj)
{
    char* p = ((GameObject*)obj)->extra;
    void* m = *(void**)&((KtlazerwallState*)p)->unk10;
    if (m != 0)
    {
        mm_free(m);
        *(void**)&((KtlazerwallState*)p)->unk10 = 0;
    }
}

void ktlazerwall_init(int obj, char* arg)
{
    char* p = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s8)arg[0x18] << 8);
    ((KtlazerwallState*)p)->unk4 = lbl_803E6898;
    ((KtlazerwallState*)p)->unkC = lbl_803E68BC * (f32)(int)
    randomGetRange(0x50, 0x78);
    if ((s32)randomGetRange(0, 1) != 0)
    {
        ((KtlazerwallState*)p)->unkC = -((KtlazerwallState*)p)->unkC;
    }
}

void ktlazerwall_update(int obj)
{
    int q = *(int*)&((GameObject*)obj)->anim.placementData;
    u8* runtime = ((GameObject*)obj)->extra;
    int cur;
    int mode;
    int i;
    runtime[1] = runtime[0];
    runtime[0] &= ~3;
    cur = (s16)GameBit_Get(((KtlazerwallPlacement*)q)->unk1A);
    if (cur >= ((KtlazerwallPlacement*)q)->unk1C)
    {
        runtime[0] |= 4;
    }
    else
    {
        runtime[0] &= ~4;
        if (GameBit_Get(((KtlazerwallPlacement*)q)->unk1E) == 0)
        {
            return;
        }
    }
    ((GameObject*)obj)->anim.rotZ += 910;
    if (cur >= 15 && (runtime[0] & 9) == 0)
    {
        GameBit_Set(((KtlazerwallPlacement*)q)->unk1E, 1);
        runtime[0] |= 9;
        ktrexfloorswitch_spawnEnergyArc(obj, lbl_803E68B8, 120);
        (*gPartfxInterface)->spawnObject((void*)obj, 1150, NULL, 2, -1, NULL);
        for (i = 10; i != 0; i--)
        {
            mode = 2;
            (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
        }
        ((KtlazerwallState*)runtime)->unk4 = (f32)(int)
        randomGetRange(1, 60);
    }
    if (runtime[0] & 4)
    {
        mode = 0;
        (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
        mode = 1;
        (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
        if ((runtime[1] & 4) == 0)
        {
            Sfx_PlayFromObject(obj, SFXmn_sml_trex_snap3);
        }
    }
    if (runtime[0] & 8)
    {
        mode = 0;
        (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
        mode = 2;
        (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
    }
    if ((runtime[0] & 8) == 0 && (runtime[1] & 8) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_blkhit_c);
    }
    {
        f32 timer = ((KtlazerwallState*)runtime)->unk4;
        f32 limit = lbl_803E6898;
        if (timer > limit)
        {
            ((KtlazerwallState*)runtime)->unk4 = timer - timeDelta;
            if (((KtlazerwallState*)runtime)->unk4 <= limit)
            {
                Sfx_PlayFromObject(obj, SFXmv_bflconc1);
                ((KtlazerwallState*)runtime)->unk4 = lbl_803E6898;
            }
        }
    }
}

void ktlazerwall_render(int obj)
{
    char* p = ((GameObject*)obj)->extra;
    int q = *(int*)&((GameObject*)obj)->anim.placementData;
    int m;
    if (*(void**)&((KtlazerwallState*)p)->unk10 != 0)
    {
        ((KtlazerwallState*)p)->unk8 -= timeDelta;
        if (((KtlazerwallState*)p)->unk8 <= lbl_803E6898)
        {
            f32 t = lbl_803E68B0 * ((KtlazerwallState*)p)->unkC;
            m = ((KtlazerwallState*)p)->unk10;
            *(f32*)(m + 0x10) = *(f32*)(m + 0x10) - t * lbl_803E68B4;
            ((KtlazerwallState*)p)->unk8 = (f32)(int)
            randomGetRange(0xa, 0x78);
        }
        else
        {
            m = ((KtlazerwallState*)p)->unk10;
            *(f32*)(m + 0x10) = ((KtlazerwallState*)p)->unkC * timeDelta + *(f32*)(m + 0x10);
        }
        lightningRender(*(void**)&((KtlazerwallState*)p)->unk10);
        *(u16*)(((KtlazerwallState*)p)->unk10 + 0x20) += framesThisStep;
        m = ((KtlazerwallState*)p)->unk10;
        if (*(u16*)(m + 0x20) >= *(u16*)(m + 0x22))
        {
            mm_free((void*)m);
            ((KtlazerwallState*)p)->unk10 = 0;
            *(u8*)p &= ~8;
            GameBit_Set(((KtlazerwallPlacement*)q)->unk1E, 0);
        }
    }
}
