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
#include "main/audio/sfx_ids.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/game_object.h"

STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

/* pressureswitch_getExtraSize == 0x8. */

/* wmlasertarget_getExtraSize == 0x4. */

/* WM_colrise_getExtraSize == 0x4. */

/* wmtorch_getExtraSize == 0x10. */

typedef struct LightSourceState
{
    void* light;
    f32 fxTimer;
    u8 pad08[4];
    f32 sparkTimer;
    int gameBit; /* 0x10: -1 none */
    u8 mode; /* 0x14: 1 = hit-toggleable */
    u8 fxType;
    u8 fxArg;
    u8 lit; /* 0x17 */
    u8 litPrev;
    u8 sparks; /* 0x19 */
    u8 loopFlags; /* 0x1a: bit0 = looped */
    u8 pad1B;
} LightSourceState;

STATIC_ASSERT(sizeof(LightSourceState) == 0x1c);

/* dll_1FF_getExtraSize == 0x8 (grabbable hook). */
typedef struct Dll1FFState
{
    s16 msgLo;
    s16 msgHi;
    u8 pad4;
    s8 grabPhase; /* 0 free, 1 held, 2 releasing */
    u8 sendFlag; /* 0x6 */
    u8 pad7;
} Dll1FFState;

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

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

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined8 FUN_80006ba8();
extern uint FUN_80006c00();
extern undefined4 FUN_8001771c();
extern uint FUN_80017a98();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjMsg_SendToObject();
extern int FUN_800632f4();

/* float constants for the byte-parity twins FUN_801f1634/FUN_801f2b94;
   distinct addresses from dll_1FF_update's lbl_803E5D8x set (own symbols,
   not the same globals - cannot be consolidated). */
extern f32 lbl_803DC074;
extern f32 lbl_803E6A1C;
extern f32 lbl_803E6A20;
extern f32 lbl_803E6A24;
extern f32 lbl_803E6A80;

extern f32 timeDelta;
extern f32 lbl_803E5D80;

/* Byte-parity twin of dll_1FF_update: the raw casts (undefined types,
   (int)state + N byte offsets, CONCAT22) are load-bearing - rewriting
   the state accesses as Dll1FFState struct fields changes codegen and
   breaks the match, so this is kept verbatim. param_9 is the GameObject;
   the leading params are forwarded to ObjMsg_SendToObject. */
void FUN_801f1634(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    char count;
    float surfTop;
    float snapBand;
    float riseSpeed;
    int hit;
    u8 grabPhase;
    float* surf;
    uint buttons;
    int off;
    float surface;
    int i;
    undefined4 in_r7; /* trailing varargs forwarded to ObjMsg_SendToObject */
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined2* state;
    undefined8 player;
    int hitList[3];

    state = ((GameObject*)param_9)->extra;
    hit = FUN_80017a98();
    if (*(char*)((int)state + 5) == '\0')
    {
        grabPhase = 0;
        if (((*(byte*)&((GameObject*)param_9)->anim.resetHitboxMode & 1) != 0) && (((GameObject*)param_9)->unkF8 == 0))
        {
            *state = 0;
            state[1] = 0x28;
            FUN_80006ba8(0, DLL1FF_BUTTON_ACTION);
            grabPhase = 1;
        }
        *(u8*)((int)state + 5) = grabPhase;
        if (*(char*)((int)state + 5) != '\0')
        {
            *(u8*)(state + 3) = 1;
        }
        if (((GameObject*)param_9)->unkF8 == 0)
        {
            ObjHits_EnableObject(param_9);
            *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.
                resetHitboxMode & 0xf7;
            ((GameObject*)param_9)->anim.velocityY = -(lbl_803E6A1C * lbl_803DC074 - ((GameObject*)param_9)->anim.
                velocityY);
            ((GameObject*)param_9)->anim.localPosY =
                ((GameObject*)param_9)->anim.velocityY * lbl_803DC074 + ((GameObject*)param_9)->anim.localPosY;
            hit = FUN_800632f4((double)((GameObject*)param_9)->anim.localPosX,
                               (double)((GameObject*)param_9)->anim.localPosY,
                               (double)((GameObject*)param_9)->anim.localPosZ, param_9, hitList, 0, 1);
            riseSpeed = lbl_803E6A24;
            snapBand = lbl_803E6A20;
            surface = 0.0;
            i = 0;
            off = 0;
            if (0 < hit)
            {
                do
                {
                    surf = *(float**)(hitList[0] + off);
                    if (*(char*)(surf + 5) != '\x0e')
                    {
                        surfTop = *surf;
                        if ((((GameObject*)param_9)->anim.localPosY < surfTop) &&
                            ((surfTop - snapBand < ((GameObject*)param_9)->anim.localPosY || (i == 0))))
                        {
                            surface = surf[4];
                            ((GameObject*)param_9)->anim.localPosY = surfTop;
                            ((GameObject*)param_9)->anim.velocityY = riseSpeed;
                        }
                    }
                    off = off + 4;
                    i = i + 1;
                    hit = hit + -1;
                }
                while (hit != 0);
            }
            if (surface != 0.0)
            {
                hit = *(int*)((int)surface + 0x58);
                count = *(char*)(hit + 0x10f);
                *(char*)(hit + 0x10f) = count + '\x01';
                *(uint*)(hit + count * 4 + 0x100) = param_9;
            }
        }
    }
    else
    {
        player = ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
        buttons = FUN_80006c00(0);
        if ((buttons & DLL1FF_BUTTON_ACTION) != 0)
        {
            *(u8*)(state + 3) = 0;
            player = FUN_80006ba8(0, DLL1FF_BUTTON_ACTION);
        }
        if (((GameObject*)param_9)->unkF8 == 1)
        {
            *(u8*)((int)state + 5) = 2;
        }
        if ((*(char*)((int)state + 5) == '\x02') && (((GameObject*)param_9)->unkF8 == 0))
        {
            *(u8*)((int)state + 5) = 0;
            *(u8*)(state + 3) = 0;
        }
        if (*(char*)(state + 3) != '\0')
        {
            ObjMsg_SendToObject(player, param_2, param_3, param_4, param_5, param_6, param_7, param_8, hit, DLL1FF_MSG_GRAB,
                                param_9, CONCAT22(state[1], *state), in_r7, in_r8, in_r9, in_r10);
        }
    }
}

/* proximity check against the player: when out of range play the
   release effect, otherwise emit the eggylaugh sfx. The short* param and
   its raw byte offsets (param_1 + 0x5c, + 0xc) are the byte-parity form -
   retyping to a struct pointer rescales the arithmetic and breaks the
   match, so it is kept raw. */
void FUN_801f2b94(short* param_1)
{
    int handle;
    double dist;

    if (*(char*)(*(int*)(param_1 + 0x5c) + 0xc) == '\x02')
    {
        *param_1 = *param_1 + 0x32;
    }
    handle = FUN_80017a98();
    dist = (double)FUN_8001771c((float*)(handle + 0x18), (float*)(param_1 + 0xc));
    if ((double)lbl_803E6A80 <= dist)
    {
        FUN_8000680c((int)param_1, 0x40);
    }
    else
    {
        FUN_80006824((uint)param_1, SFXmn_eggylaugh216);
    }
}

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
    extern void objRenderFn_8003b8f4(void* obj, int p1, int p2, int p3, int p4, f32 scale);
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
    objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E5D80);
}

#pragma opt_strength_reduction off

void dll_1FF_update(int obj)
{
    extern void*Obj_GetPlayerObject(void);
    extern void buttonDisable(int a, int b);
    extern uint getButtonsJustPressed(int pad);
    extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int* list, int a, int b);
    extern f32 timeDelta;
    extern f32 lbl_803E5D84;
    extern const f32 lbl_803E5D88;
    extern const f32 lbl_803E5D8C;
    void* player;
    Dll1FFState* state;
    int grab;
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
        grab = 0;
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0 && ((GameObject*)obj)->unkF8 == 0)
        {
            state->msgLo = (s16)grab;
            state->msgHi = 0x28;
            buttonDisable(0, DLL1FF_BUTTON_ACTION);
            grab = 1;
        }
        state->grabPhase = (s8)grab;
        if (state->grabPhase != 0)
        {
            state->sendFlag = 1;
        }
        if (((GameObject*)obj)->unkF8 == 0)
        {
            ObjHits_EnableObject(obj);
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~
                8);
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
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
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
        if (*(s8*)&state->sendFlag != 0)
        {
            ObjMsg_SendToObject(player, DLL1FF_MSG_GRAB, obj,
                                ((int)state->msgHi << 16) | ((int)state->msgLo & 0xffff));
        }
    }
}
