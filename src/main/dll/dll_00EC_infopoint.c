/*
 * infopoint (DLL 0x00EC) - a non-colliding "information point" decoration
 * object. It loads a body of game text (gameTextGet) plus a shared font/
 * texture asset (asset 616) at init, parks the text + a scroll/fade timer
 * in its extra-state block, and renders the prompt billboard each frame
 * (infopoint_render). When the player triggers it (resetHitboxMode bit 0)
 * it disables the A-button and runs trigger sequence 0.
 *
 * InfoPoint_SeqFn handles the trigger sequence: events 1/2 toggle a s16
 * flag at extra+0x16; events 3/4 are no-ops.
 */
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/objanim_update.h"
#include "main/dll/VF/vf_shared.h"
#include "main/dll/infopointstate_struct.h"

#define INFOPOINT_OBJFLAG_HITDETECT_DISABLED 0x2000

#define PAD_BUTTON_A 0x100

typedef struct InfopointObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 textId;             /* 0x18: game-text id passed to gameTextGet */
    u8 pad1A[0x1B - 0x1A];
    u8 unk1B;
    u8 rotXByte;            /* 0x1C: rotX in 1/256 turns (<< 8 into anim.rotX) */
    u8 pad1D;
    u8 unk1E;
    u8 unk1F;
} InfopointObjectDef;

extern f32 lbl_803E3B70;
extern void buttonDisable(int port, u32 mask);
extern int textureLoadAsset(int id);
extern void* gameTextGet(int textId);
extern int lbl_803219A0[];
extern int lbl_80321990[];

void infopoint_hitDetect(void)
{
}

void infopoint_free(void)
{
}

void infopoint_release(void)
{
}

void infopoint_initialise(void)
{
}

int infopoint_getExtraSize(void) { return 0x20; }
int infopoint_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
void infopoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E3B70);
}

void infopoint_update(GameObject* obj)
{
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
    {
        buttonDisable(0, PAD_BUTTON_A);
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
    }
}

int InfoPoint_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    InfopointState* state = ((GameObject*)obj)->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1: state->flag = 0xff;
            break;
        case 2: state->flag = 0;
            break;
        case 3: break;
        case 4: break;
        }
    }
    return 0;
}

void infopoint_init(int* obj, u8* def)
{
    InfopointState* state = ((GameObject*)obj)->extra;
    int* txt;
    ((GameObject*)obj)->animEventCallback = InfoPoint_SeqFn;
    if (*(void**)lbl_803219A0 == NULL)
    {
        *(int*)lbl_803219A0 = textureLoadAsset(616);
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
