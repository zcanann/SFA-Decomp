/*
 * DragonRock Shrine special door (DLL 0x177; "DFSH_Door2Speci", shared by
 * Door3S/Door4S). A door whose texture fades in and then pulses: state 0
 * waits for its gamebit, state 1 ramps the texture alpha up to 0x100, and
 * state 2 drives a cosine pulse of the texture id.
 */
#include "main/game_object.h"
#include "main/objtexture.h"
#include "main/gamebits.h"
#include "main/dll/VF/vf_shared.h"

typedef struct DFSHDoor2SpeciPlacement
{
    u8 pad0[0x1B - 0x0];
    u8 unk1B;
    u8 pad1C[0x22 - 0x1C];
    s16 gameBit;
    u8 pad24[0x28 - 0x24];
} DFSHDoor2SpeciPlacement;

typedef struct DFDoorSpeciExtra
{
    u16 phase;
    u8 pad02;
    u8 state;
    u8 pad04[2];
} DFDoorSpeciExtra;

typedef enum DFSHDoor2SpeciState
{
    DFSH_DOOR2SPECI_STATE_WAIT_FOR_GAMEBIT = 0,
    DFSH_DOOR2SPECI_STATE_FADE_IN = 1,
    DFSH_DOOR2SPECI_STATE_PULSE = 2,
} DFSHDoor2SpeciState;

extern float mathCosf(float x);
extern f32 lbl_803E4E30;
extern f32 lbl_803E4E34;
extern f32 lbl_803E4E38;
extern f32 lbl_803E4E3C;
extern f32 lbl_803E4E40;

int DFSH_Door2Speci_SeqFn(int obj)
{
    ObjTextureRuntimeSlot* texture;
    DFDoorSpeciExtra* extra;
    int objDef;
    int alpha;
    u32 phaseStep;
    f32 phase;

    extra = ((GameObject*)obj)->extra;
    objDef = *(int*)&((GameObject*)obj)->anim.placementData;
    switch (extra->state)
    {
    case DFSH_DOOR2SPECI_STATE_WAIT_FOR_GAMEBIT:
        if (GameBit_Get(((DFSHDoor2SpeciPlacement*)objDef)->gameBit) != 0)
        {
            extra->state = DFSH_DOOR2SPECI_STATE_FADE_IN;
        }
        break;
    case DFSH_DOOR2SPECI_STATE_FADE_IN:
        texture = objFindTexture((void*)obj, 0, 0);
        if (texture != NULL)
        {
            alpha = texture->textureId + framesThisStep * 0x10;
            if (alpha > 0x100)
            {
                alpha = 0x100;
                extra->state = DFSH_DOOR2SPECI_STATE_PULSE;
            }
            texture->textureId = alpha;
        }
        break;
    case DFSH_DOOR2SPECI_STATE_PULSE:
    default:
        texture = objFindTexture((void*)obj, 0, 0);
        if (texture != NULL)
        {
            phaseStep = (extra->phase + framesThisStep * 800) & 0xffff;
            extra->phase = phaseStep;
            phase = (lbl_803E4E3C * (f32)(u32)extra->phase) / lbl_803E4E40;
            texture->textureId = (s32) - (lbl_803E4E34 * (lbl_803E4E38 - mathCosf(phase)) - lbl_803E4E30);
        }
        break;
    }
    return 0;
}

int dfsh_door2speci_getExtraSize(void)
{
    return sizeof(DFDoorSpeciExtra);
}

int dfsh_door2speci_getObjectTypeId(void)
{
    return 0;
}

void dfsh_door2speci_free(void)
{
}

void dfsh_door2speci_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 visibleFlag;

    visibleFlag = visible;
    if (visibleFlag != 0)
    {
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4E38);
    }
}

void dfsh_door2speci_hitDetect(void)
{
}

void dfsh_door2speci_update(void)
{
}

void dfsh_door2speci_init(int obj, int def)
{
    int state;
    ObjTextureRuntimeSlot* texture;

    state = *(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = DFSH_Door2Speci_SeqFn;
    if (GameBit_Get((int)*(short*)(def + 0x22)) != 0)
    {
        *(unsigned char*)(state + 3) = 2;
    }
    else
    {
        *(unsigned char*)(state + 3) = 0;
    }
    texture = objFindTexture((void*)obj, 0, 0);
    if (texture != NULL)
    {
        if (*(unsigned char*)(state + 3) == 2)
        {
            texture->textureId = 1;
        }
        else
        {
            texture->textureId = 0;
        }
    }
    *(short*)state = 0;
}

void dfsh_door2speci_release(void)
{
}

void dfsh_door2speci_initialise(void)
{
}
