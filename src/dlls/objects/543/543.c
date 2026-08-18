/* DLL 0x021F */
#include "dlls/object_descriptor.h"
#include "game/objects/object_setup.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/expgfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/audio/sfx_play_api.h"

#define VFP_PLATFORM_LAVABLOCK_OBJ 960


typedef struct VfpPlatformState
{
    s16 gameBitId;
    u8 state;
    u8 axisMode;
    s16 timer;
} VfpPlatformState;

typedef struct VfpPlatformPlacement
{
    ObjPlacement base;
    s8 rotXByte;
    u8 axisMode;
    u8 pad1A[6];
    s16 gameBitId;
} VfpPlatformPlacement;

STATIC_ASSERT(sizeof(VfpPlatformState) == 0x6);

void VFP_Platform_updateLavaBlock(GameObject* obj);
int VFP_Platform_getExtraSize(void);
int VFP_Platform_getObjectTypeId(void);
void VFP_Platform_free(int obj);
void VFP_Platform_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void VFP_Platform_hitDetect(void);
void VFP_Platform_update(GameObject* obj);
void VFP_Platform_init(GameObject* obj, VfpPlatformPlacement* data);
void VFP_Platform_release(void);
void VFP_Platform_initialise(void);

void VFP_Platform_updateLavaBlock(GameObject* obj)
{
    ObjPlacement* placement = (ObjPlacement*)obj->anim.placementData;
    VfpPlatformState* state = obj->extra;
    if (mainGetBit(state->gameBitId) != 0)
    {
        state->state = 6;
    }
    switch (state->state)
    {
    case 6:
        if (obj->anim.localPosZ < placement->posZ)
        {
            obj->anim.localPosZ = obj->anim.localPosZ + timeDelta;
            if (obj->anim.localPosZ >= placement->posZ)
            {
                obj->anim.localPosZ = placement->posZ;
            }
        }
        else if (obj->anim.localPosZ > placement->posZ)
        {
            obj->anim.localPosZ = obj->anim.localPosZ - timeDelta;
            if (obj->anim.localPosZ <= placement->posZ)
            {
                obj->anim.localPosZ = placement->posZ;
            }
        }
        else
        {
            if (mainGetBit(state->gameBitId) == 0)
            {
                state->state = 3;
            }
        }
        break;
    case 0:
        if (mainGetBit(state->gameBitId) == 0)
        {
            state->state = 3;
        }
        break;
    case 1:
    {
        s16 timer = state->timer;
        if (timer != 0)
        {
            state->timer -= (s16)timeDelta;
            if (state->timer <= 0)
            {
                state->timer = 0;
            }
        }
        else if (state->axisMode == 0)
        {
            if (obj->anim.localPosZ == placement->posZ - 120.0f)
            {
                state->state = 2;
            }
            if (obj->anim.localPosZ == 120.0f + placement->posZ)
            {
                state->state = 3;
            }
        }
        else
        {
            if (obj->anim.localPosZ == placement->posZ - 120.0f)
            {
                state->state = 4;
            }
            if (obj->anim.localPosZ == 120.0f + placement->posZ)
            {
                state->state = 5;
            }
        }
        break;
    }
    case 2:
    {
        f32 thr;
        f32 z = obj->anim.localPosZ;
        if (z < (thr = 120.0f, thr + placement->posZ))
        {
            obj->anim.localPosZ = z + timeDelta;
            if (obj->anim.localPosZ >= thr + placement->posZ)
            {
                obj->anim.localPosZ = thr + placement->posZ;
                state->state = 1;
                state->timer = 20;
            }
        }
        break;
    }
    case 3:
    {
        f32 thr;
        if (obj->anim.localPosZ > placement->posZ - (thr = 120.0f))
        {
            obj->anim.localPosZ = obj->anim.localPosZ - timeDelta;
            if (obj->anim.localPosZ <= placement->posZ - thr)
            {
                obj->anim.localPosZ = placement->posZ - thr;
                state->state = 1;
                state->timer = 20;
            }
        }
        break;
    }
    }
}

int VFP_Platform_getExtraSize(void)
{
    return 0x6;
}

int VFP_Platform_getObjectTypeId(void)
{
    return 0x0;
}

void VFP_Platform_free(int obj)
{
    (*gExpgfxInterface)->freeSource2(obj);
}

void VFP_Platform_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    VfpPlatformState* state = obj->extra;
    s32 isVisible = visible;
    if (isVisible != 0 && state->axisMode != 0x63)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)((int)obj, p2, p3, p4, p5, 1.0f);
    }
}

void VFP_Platform_hitDetect(void)
{
}

void VFP_Platform_update(GameObject* obj)
{
    ObjPlacement* params = (ObjPlacement*)(obj)->anim.placementData;
    VfpPlatformState* state = (obj)->extra;
    int xi;
    int yi;
    int txi;
    int tyi;
    u8 s3 = state->axisMode;
    if (s3 == 10)
    {
        if (mainGetBit(state->gameBitId) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
    }
    else
    {
        xi = (obj)->anim.localPosX;
        yi = (obj)->anim.localPosZ;
        txi = params->posX;
        tyi = params->posZ;
        if (s3 != 99)
        {
            if ((obj)->anim.romDefNo == VFP_PLATFORM_LAVABLOCK_OBJ)
            {
                VFP_Platform_updateLavaBlock(obj);
            }
            else
            {
                switch (state->state)
                {
                case 0:
                    if (mainGetBit(state->gameBitId) != 0)
                    {
                        state->state = 1;
                    }
                    break;
                case 1:
                {
                    s16 timer = state->timer;
                    if (timer != 0)
                    {
                        state->timer -= (s16)timeDelta;
                        if (state->timer <= 0)
                        {
                            state->timer = 0;
                        }
                    }
                    else if (s3 == 0)
                    {
                        if (yi == tyi - 60)
                        {
                            state->state = 2;
                            Sfx_PlayFromObject(obj, SFXTRIG_en_ripefruit11);
                        }
                        if (yi == tyi)
                        {
                            state->state = 3;
                            Sfx_PlayFromObject(obj, SFXTRIG_en_ripefruit11);
                        }
                    }
                    else if (s3 == 3)
                    {
                        if (xi == txi - 60)
                        {
                            state->state = 2;
                            Sfx_PlayFromObject(obj, SFXTRIG_en_ripefruit11);
                        }
                        if (xi == txi)
                        {
                            state->state = 3;
                            Sfx_PlayFromObject(obj, SFXTRIG_en_ripefruit11);
                        }
                    }
                    else
                    {
                        if (yi == tyi + 60)
                        {
                            state->state = 4;
                            Sfx_PlayFromObject(obj, SFXTRIG_en_ripefruit11);
                        }
                        if (yi == tyi)
                        {
                            state->state = 5;
                            Sfx_PlayFromObject(obj, SFXTRIG_en_ripefruit11);
                        }
                    }
                    break;
                }
                case 2:
                    if (s3 == 3 && xi < txi)
                    {
                        (obj)->anim.localPosX = (obj)->anim.localPosX + timeDelta;
                        if ((int)(obj)->anim.localPosX >= txi)
                        {
                            (obj)->anim.localPosX = txi;
                            state->state = 1;
                        }
                    }
                    else if (yi < tyi)
                    {
                        (obj)->anim.localPosZ += timeDelta;
                        if ((int)(obj)->anim.localPosZ >= tyi)
                        {
                            (obj)->anim.localPosZ = tyi;
                            state->state = 1;
                        }
                    }
                    break;
                case 3:
                    if (s3 == 3 && xi > txi - 60)
                    {
                        (obj)->anim.localPosX = (obj)->anim.localPosX - timeDelta;
                        if ((int)(obj)->anim.localPosX <= txi - 60)
                        {
                            (obj)->anim.localPosX = (txi - 60);
                            state->state = 1;
                            state->timer = 200;
                        }
                    }
                    else if (yi > tyi - 60)
                    {
                        (obj)->anim.localPosZ -= timeDelta;
                        if ((int)(obj)->anim.localPosZ <= tyi - 60)
                        {
                            (obj)->anim.localPosZ = (tyi - 60);
                            state->state = 1;
                            state->timer = 200;
                        }
                    }
                    break;
                case 4:
                    if (s3 == 3 && xi > txi)
                    {
                        (obj)->anim.localPosX = (obj)->anim.localPosX - timeDelta;
                        if ((int)(obj)->anim.localPosX <= txi)
                        {
                            (obj)->anim.localPosX = txi;
                            state->state = 1;
                        }
                    }
                    else if (yi > tyi)
                    {
                        (obj)->anim.localPosZ -= timeDelta;
                        if ((int)(obj)->anim.localPosZ <= tyi)
                        {
                            (obj)->anim.localPosZ = tyi;
                            state->state = 1;
                        }
                    }
                    break;
                case 5:
                    if (s3 == 3 && xi < txi + 60)
                    {
                        (obj)->anim.localPosX = (obj)->anim.localPosX + timeDelta;
                        if ((int)(obj)->anim.localPosX >= txi + 60)
                        {
                            (obj)->anim.localPosX = (txi + 60);
                            state->state = 1;
                            state->timer = 200;
                        }
                    }
                    else if (yi < tyi + 60)
                    {
                        (obj)->anim.localPosZ += timeDelta;
                        if ((int)(obj)->anim.localPosZ >= tyi + 60)
                        {
                            (obj)->anim.localPosZ = (tyi + 60);
                            state->state = 1;
                            state->timer = 200;
                        }
                    }
                    break;
                }
            }
        }
    }
}

void VFP_Platform_init(GameObject* obj, VfpPlatformPlacement* data)
{
    VfpPlatformPlacement* def = data;
    VfpPlatformState* state = obj->extra;
    obj->anim.rotX = (((s32)def->rotXByte) << 8);
    state->gameBitId = def->gameBitId;
    state->state = 0;
    state->axisMode = def->axisMode;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void VFP_Platform_release(void)
{
}

void VFP_Platform_initialise(void)
{
}

ObjectDescriptor gVFP_PlatformObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_Platform_initialise,
    (ObjectDescriptorCallback)VFP_Platform_release,
    0,
    (ObjectDescriptorCallback)VFP_Platform_init,
    (ObjectDescriptorCallback)VFP_Platform_update,
    (ObjectDescriptorCallback)VFP_Platform_hitDetect,
    (ObjectDescriptorCallback)VFP_Platform_render,
    (ObjectDescriptorCallback)VFP_Platform_free,
    (ObjectDescriptorCallback)VFP_Platform_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)VFP_Platform_getExtraSize,
};
