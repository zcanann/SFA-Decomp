#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/dll/cnthitobjec_state.h"

#include "main/audio/sfx_ids.h"
#pragma peephole on
#pragma scheduling on
int cnthitobjec_getExtraSize(void) { return 0xc; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int cnthitobjec_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void cnthitobjec_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void cnthitobjec_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void cnthitobjec_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void cnthitobjec_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;
    if (*(u8 *)(setup + 0x19) == 2 && ((CntHitFlags *)(state + 9))->disabled == 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7430);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int cnthitobjec_emitHitEvents(int obj, int p2, int p3)
{
    int i;
    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        spawnExplosion(obj, (f32)(u32)*(u8 *)(p3 + (i + 0x81)), 1, 1, 1, 1, 0, 1, 0);
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void cnthitobjec_hitDetect(int obj)
{
    int setup = *(int *)&((GameObject *)obj)->anim.placementData;
    int state = *(int *)&((GameObject *)obj)->extra;
    int hit;
    int dmg;
    int amount;
    int model;

    if (((CntHitObjectState *)state)->unk0 == 0) {
        return;
    }
    hit = ObjHits_GetPriorityHit(obj, 0, 0, &dmg);
    if (hit == 0) {
        return;
    }
    if (((CntHitObjectState *)state)->unk8 == 0) {
        return;
    }
    if (arrayIndexOf(((CntHitObjectState *)state)->unk4, ((CntHitObjectState *)state)->unk8, hit) == -1) {
        return;
    }
    ((CntHitObjectState *)state)->unk0 = ((CntHitObjectState *)state)->unk0 - dmg;
    if (*(u8 *)(setup + 0x19) == 2) {
        Obj_SetModelColorFadeRecursive(obj, 30, 200, 0, 0, 1);
        Sfx_PlayFromObject(obj, 1174);
    }
    if (((CntHitObjectState *)state)->unk0 <= 0) {
        int s = *(int *)&((GameObject *)obj)->anim.placementData;
        ((CntHitObjectState *)state)->unk0 = 0;
        GameBit_Set(*(s16 *)(s + 0x1e), 1);
        if (*(u8 *)(s + 0x19) != 0) {
            if (*(u8 *)(s + 0x19) == 2) {
                amount = 80;
            } else {
                amount = *(s16 *)(s + 0x1c);
            }
            model = *(int *)(*(int *)&((GameObject *)obj)->anim.placementData + 0x14);
            if (model != 0x470EA && model != 0x480F5 && model != 0x46710 &&
                model != 0x49B43) {
                spawnExplosion(obj, (f32)amount, 1, 1, 1, 1, 0, 1, 0);
            }
            if (*(u8 *)(setup + 0x19) == 2) {
                Sfx_PlayFromObject(obj, 1175);
            }
        }
    } else {
        Sfx_PlayFromObject(obj, SFXdn_hightop_ambi1);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void cnthitobjec_init(int obj, int setup)
{
    int state = *(int *)&((GameObject *)obj)->extra;

    ((CntHitObjectState *)state)->unk0 = 0;
    *(s8 *)(setup + 0x18) = (s8)((u32)(s8)*(s8 *)(setup + 0x18) % 3);
    ((CntHitObjectState *)state)->unk4 = lbl_8032BEF8[(s8)*(s8 *)(setup + 0x18)];
    ((CntHitObjectState *)state)->unk8 = lbl_803DC42C[(s8)*(s8 *)(setup + 0x18)];
    if (*(void **)(state + 4) == (void *)&lbl_803DC428) {
        ObjHits_ClearSourceMask(8);
    }
    if (*(u8 *)(setup + 0x19) == 2) {
        *(s16 *)obj = *(s16 *)(setup + 0x1c);
    } else {
        ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        ((CntHitFlags *)(state + 9))->disabled = 1;
        ObjHits_DisableObject(obj);
    }
    ((GameObject *)obj)->animEventCallback = (void *)cnthitobjec_emitHitEvents;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void cnthitobjec_update(int obj)
{
    int setup;
    int state = *(int *)&((GameObject *)obj)->extra;
    setup = *(int *)&((GameObject *)obj)->anim.placementData;

    if (((CntHitFlags *)(state + 9))->disabled == 0) {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
            ((CntHitFlags *)(state + 9))->disabled = 1;
            ObjHits_DisableObject(obj);
        }
    }

    if (((CntHitFlags *)(state + 9))->disabled == 0 && ((CntHitObjectState *)state)->unk0 == 0 &&
        (u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        ObjHits_EnableObject(obj);
        ((CntHitObjectState *)state)->unk0 = *(s16 *)(setup + 0x1a);
        if (*(u8 *)(setup + 0x19) != 2) {
            ObjHitbox_SetSphereRadius(obj, *(s16 *)(setup + 0x1c));
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int mcupgrade_SeqFn(int obj, int p2, int setup)
{
    if (*(u8 *)(setup + 0x8b) != 0) {
        (*(void (**)(int, int, int, int))(*gGameUIInterface + 0x38))(
            *(s16 *)(*(int *)&((GameObject *)obj)->anim.placementData + 0x1a), 0x14, 0x8c, 0);
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset
