/*
 * drlightbea (DLL 0x27C) - a lightning-beam effect that arcs from this
 * object to a target while its placement game bit (0x20) is set.
 *
 * The target is either another placed object (resolved by id via
 * dll_2E_func0A when the placement target byte at 0x19 is non-zero) or
 * the player. While active, render keeps the beam's endpoints synced to
 * the live source/target positions, advances its lifetime counter and
 * frees the beam once it expires. The extra state (0xc bytes) holds the
 * lightningCreate handle at offset 0 and the active/free bit flags at
 * offset 4.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"

typedef struct DrlightbeaPlacement
{
    u8 pad0[0x19 - 0x0];
    s8 targetId;   /* 0x19: placed-object target id, or 0 to use the player */
    u8 pad1A[0x20 - 0x1A];
    s16 gameBit;   /* 0x20: enables the beam while set */
    u8 pad22[0x28 - 0x22];
} DrlightbeaPlacement;

/* Per-object extra state block (drlightbea_getExtraSize == 0xc): holds the
 * lightningCreate buffer handle at 0 and the active/free bit flags at 4. */
typedef struct DrLightBeaState
{
    void* handle;          /* 0x00: lightningCreate buffer, or NULL */
    DrLightBeaFlags flags; /* 0x04 */
} DrLightBeaState;

int drlightbea_getExtraSize(void) { return 0xc; }

int drlightbea_getObjectTypeId(void) { return 0; }

void drlightbea_free(int obj)
{
    DrLightBeaState* state = *(DrLightBeaState**)&((GameObject*)obj)->extra;
    void* buffer = state->handle;

    if (buffer != NULL)
    {
        mm_free(buffer);
        state->handle = NULL;
    }
}

void drlightbea_hitDetect(void)
{
}

void drlightbea_update(int obj)
{
    DrLightBeaState* state = *(DrLightBeaState**)&((GameObject*)obj)->extra;
    if (state->flags.bit40)
    {
        Obj_FreeObject(obj);
    }
}

void drlightbea_init(int obj)
{
    DrLightBeaState* state = *(DrLightBeaState**)&((GameObject*)obj)->extra;
    state->flags.bit80 = 0;
    state->handle = NULL;
    state->flags.bit40 = 0;
}

void drlightbea_release(void)
{
}

void drlightbea_initialise(void)
{
}

void drlightbea_render(int obj, int p2, int p3, int p4, int p5)
{
    DrLightBeaState* state = *(DrLightBeaState**)&((GameObject*)obj)->extra;
    int setup = *(int*)&((GameObject*)obj)->anim.placementData;
    int player;
    f32 targetXform[6];
    f32 sourcePos[3];
    f32 targetPos[3];

    if (state->flags.bit80)
    {
        *(f32*)((int)state->handle + 0) = ((GameObject*)obj)->anim.localPosX;
        *(f32*)((int)state->handle + 4) = ((GameObject*)obj)->anim.localPosY;
        *(f32*)((int)state->handle + 8) = ((GameObject*)obj)->anim.localPosZ;
        if (((DrlightbeaPlacement*)setup)->targetId == 0)
        {
            player = Obj_GetPlayerObject();
            *(f32*)((int)state->handle + 0xc) = ((GameObject*)player)->anim.localPosX;
            *(f32*)((int)state->handle + 0x10) = lbl_803E6BB8 + ((GameObject*)player)->anim.localPosY;
            *(f32*)((int)state->handle + 0x14) = ((GameObject*)player)->anim.localPosZ;
        }
        lightningRender(state->handle);
        *(u16*)((int)state->handle + 0x20) += 1;
        if (*(u16*)((int)state->handle + 0x20) >= *(u16*)((int)state->handle + 0x22))
        {
            mm_free(state->handle);
            state->handle = NULL;
            state->flags.bit80 = 0;
            if (*(u32*)&((ObjPlacement*)setup)->mapId == 0xffffffff)
            {
                state->flags.bit40 = 1;
            }
        }
    }
    else
    {
        if (state->handle != NULL)
        {
            mm_free(state->handle);
            state->handle = NULL;
        }
        state->flags.bit80 = GameBit_Get(((DrlightbeaPlacement*)setup)->gameBit);
        if (state->flags.bit80)
        {
            Sfx_PlayFromObject(obj, SFXfend_pep_snoreout);
            sourcePos[0] = ((GameObject*)obj)->anim.localPosX;
            sourcePos[1] = ((GameObject*)obj)->anim.localPosY;
            sourcePos[2] = ((GameObject*)obj)->anim.localPosZ;
            if (((DrlightbeaPlacement*)setup)->targetId != 0 &&
                dll_2E_func0A(((DrlightbeaPlacement*)setup)->targetId, targetXform) != 0)
            {
                targetPos[0] = targetXform[3];
                targetPos[1] = targetXform[4];
                targetPos[2] = targetXform[5];
            }
            else
            {
                player = Obj_GetPlayerObject();
                targetPos[0] = ((GameObject*)player)->anim.localPosX;
                targetPos[1] = lbl_803E6BB8 + ((GameObject*)player)->anim.localPosY;
                targetPos[2] = ((GameObject*)player)->anim.localPosZ;
            }
            state->handle = lightningCreate(sourcePos, targetPos, lbl_803E6BBC, lbl_803E6BC0,
                                            randomGetRange(5, 0xf), 0x60, 0);
        }
    }
}
