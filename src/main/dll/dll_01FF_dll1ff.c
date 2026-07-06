/*
 * dll1ff (DLL 0x1FF) - a grabbable object the player can hang from.
 *
 * While free (grabPhase 0) the object falls (velocityY integrated by
 * timeDelta) and probes nearby surfaces with hitDetectFn_80065e50; on
 * contact it snaps to the surface top and registers itself in that
 * surface owner's slot list. When the player grabs it (resetHitboxMode
 * bit 1, unkF8 toggles) it disables its own hit volume, latches a
 * pending message (msgHi/msgLo), and on the action button (0x100)
 * releases and forwards the message via ObjMsg_SendToObject. Render
 * gates model-state shadow fade-out on the active trigger sequence.
 */
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/gameplay_runtime.h"
#include "main/pad.h"

/* dll_1FF_getExtraSize == 0x8 (grabbable hook). */
typedef struct Dll1FFState
{
    s16 msgLo;
    s16 msgHi;
    u8 pad4;
    s8 grabPhase; /* 0 free, 1 held, 2 releasing */
    s8 sendFlag; /* pending send flag */
    u8 pad7;
} Dll1FFState;

typedef struct Dll1FFSlot
{
    int obj;
} Dll1FFSlot;

/* registry on the landed surface owner: up to 3 grabbed-object slots */
typedef struct Dll1FFSlots
{
    u8 pad[0x100];
    Dll1FFSlot slots[3];
    u8 pad2[3];
    u8 count;
} Dll1FFSlots;

#define DLL1FF_BUTTON_ACTION 0x100  /* action-button mask (button-just-pressed / disable) */
#define DLL1FF_MSG_GRAB 0x100008    /* ObjMsg kind sent on release */

extern void ObjMsg_SendToObject(void* to, int msg, int obj, int param);
extern const f32 lbl_803E5D80;

void dll_1FF_free_nop(void)
{
}

void dll_1FF_hitDetect_nop(void)
{
}

void dll_1FF_release_nop(void)
{
}

void dll_1FF_initialise_nop(void)
{
}

int dll_1FF_getExtraSize_ret_8(void) { return 0x8; }

int dll_1FF_getObjectTypeId(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x146) return 0x2;
    return 0x0;
}

void dll_1FF_init(s16* a, s8* b)
{
    a[0] = (s16)((s32)b[0x18] << 8);
    a[1] = -0x8000;
}

/* visible is -1 while held (unkF8 set), otherwise a 0/non-0 flag; gate
   shadow fade-out on whether a trigger sequence is active. */
void dll_1FF_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderModelAndHitVolumes(void* obj, int p1, int p2, int p3, int p4, f32 scale);
    s32 v;
    if (((GameObject*)obj)->unkF8 != 0)
    {
        v = visible;
        if (v != -1) return;
    }
    else
    {
        v = visible;
        if (v == 0) return;
    }
    if (((ObjAnimComponent*)obj)->modelInstance->shadowType == 2)
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
    objRenderModelAndHitVolumes(obj, p1, p2, p3, p4, lbl_803E5D80);
}

void dll_1FF_update(int obj)
{

    extern void buttonDisable(int port, u32 mask);
    extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);
    extern f32 timeDelta;
    extern const f32 lbl_803E5D84;
    extern const f32 lbl_803E5D88;
    extern const f32 lbl_803E5D8C;
    void* player;
    Dll1FFState* state;
    int grab[1];
    int count;
    char* landed;
    int i;
    u8 slot;
    char* surf;
    int hitList[2];

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (state->grabPhase == 0)
    {
        grab[0] = 0;
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0 && ((GameObject*)obj)->unkF8 == 0)
        {
            state->msgLo = grab[0];
            state->msgHi = 0x28;
            buttonDisable(0, DLL1FF_BUTTON_ACTION);
            grab[0] = 1;
        }
        state->grabPhase = grab[0];
        if (state->grabPhase != 0)
        {
            state->sendFlag = 1;
        }
        if (((GameObject*)obj)->unkF8 == 0)
        {
            ObjHits_EnableObject(obj);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~
                INTERACT_FLAG_DISABLED);
            ((GameObject*)obj)->anim.velocityY = -(lbl_803E5D84 * timeDelta - ((GameObject*)obj)->anim.velocityY);
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->
                anim.localPosY;
            count = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                         ((GameObject*)obj)->anim.localPosZ, hitList, 0, 1);
            landed = NULL;
            for (i = 0; i < count; i++)
            {
                surf = ((char**)hitList[0])[i];
                if (*(s8*)(surf + 0x14) != 14)
                {
                    if (((GameObject*)obj)->anim.localPosY < *(f32*)surf)
                    {
                        if (((GameObject*)obj)->anim.localPosY > *(f32*)surf - lbl_803E5D88 || i == 0)
                        {
                            landed = *(char**)(surf + 0x10);
                            ((GameObject*)obj)->anim.localPosY = *(f32*)surf;
                            ((GameObject*)obj)->anim.velocityY = lbl_803E5D8C;
                        }
                    }
                }
            }
            if (landed != NULL)
            {
                Dll1FFSlots* ts = *(Dll1FFSlots**)(landed + 0x58);
                slot = ts->count;
                ts->count += 1;
                ts->slots[(s8)slot].obj = obj;
            }
        }
    }
    else
    {
        ObjHits_DisableObject(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
        if ((getButtonsJustPressed(0) & DLL1FF_BUTTON_ACTION) != 0)
        {
            state->sendFlag = 0;
            buttonDisable(0, DLL1FF_BUTTON_ACTION);
        }
        if (((GameObject*)obj)->unkF8 == 1)
        {
            state->grabPhase = 2;
        }
        if (state->grabPhase == 2 && ((GameObject*)obj)->unkF8 == 0)
        {
            state->grabPhase = 0;
            state->sendFlag = 0;
        }
        if (state->sendFlag != 0)
        {
            ObjMsg_SendToObject(player, DLL1FF_MSG_GRAB, obj,
                                ((int)state->msgHi << 16) | ((int)state->msgLo & 0xffff));
        }
    }
}
