/*
 * infopoint (DLL 0x00EC) - a non-colliding "information point" decoration
 * object. It loads a body of game text (gameTextGet) plus a shared font/
 * texture asset (asset 616) at init, parks the text + a scroll/fade timer
 * in its extra-state block, and renders the prompt billboard each frame
 * (InfoPoint_render). When the player triggers it (resetHitboxMode bit 0)
 * it disables the A-button and runs trigger sequence 0.
 *
 * InfoPoint_SeqFn handles the trigger sequence: events 1/2 toggle a s16
 * flag at extra+0x16; events 3/4 are no-ops.
 */
#include "main/game_object.h"
#include "main/pad_api.h"
#include "main/objseq.h"
#include "main/objanim_update.h"
#include "main/object_render_legacy.h"
#include "main/dll/dll_00EC_infopoint.h"
#include "main/textrender_api.h"
#include "main/texture.h"

#define INFOPOINT_OBJFLAG_HITDETECT_DISABLED 0x2000

/* shared font/texture asset loaded at init (see file header). */
#define INFOPOINT_TEXTURE_FONT 616

#define PAD_BUTTON_A 0x100

extern f32 lbl_803E3B70;
extern int lbl_803219A0[];
extern int lbl_80321990[];

#pragma scheduling off
#pragma peephole off
int InfoPoint_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    InfopointState* state = obj->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            state->flag = 0xff;
            break;
        case 2:
            state->flag = 0;
            break;
        case 3:
            break;
        case 4:
            break;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

int InfoPoint_getExtraSize(void)
{
    return 0x20;
}
int InfoPoint_getObjectTypeId(void)
{
    return 0x0;
}

void InfoPoint_free(void)
{
}

#pragma scheduling off
#pragma peephole off
void InfoPoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E3B70);
}
#pragma peephole reset
#pragma scheduling reset

void InfoPoint_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
void InfoPoint_update(GameObject* obj)
{
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
    {
        buttonDisable(0, PAD_BUTTON_A);
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
    }
}

void InfoPoint_init(int* obj, u8* def)
{
    InfopointState* state = ((GameObject*)obj)->extra;
    int* txt;
    ((GameObject*)obj)->animEventCallback = InfoPoint_SeqFn;
    if (*(void**)lbl_803219A0 == NULL)
    {
        *(int*)lbl_803219A0 = (int)textureLoadAsset(INFOPOINT_TEXTURE_FONT);
    }
    state->unk08 = (int)lbl_80321990;
    txt = gameTextGet(((InfopointObjectDef*)def)->textId);
    state->textValue = **(int**)((char*)txt + 8);
    state->timer = 100;
    state->text = (int)txt;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)((InfopointObjectDef*)def)->rotXByte << 8);
    state->unk18 = 2;
    state->unk10 = ((InfopointObjectDef*)def)->unk1B;
    state->flag = 0;
    ((GameObject*)obj)->objectFlags |= INFOPOINT_OBJFLAG_HITDETECT_DISABLED;
}
#pragma peephole reset
#pragma scheduling reset

void InfoPoint_release(void)
{
}

void InfoPoint_initialise(void)
{
}
