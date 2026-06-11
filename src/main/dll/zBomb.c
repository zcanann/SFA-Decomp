#include "main/game_object.h"
#include "main/dll/fruit.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/zBomb.h"
#include "main/objanim_internal.h"

static inline int* ZBomb_GetActiveModel(DfpTargetBlockObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

extern undefined4 streamFn_8000a380();
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void Model_GetVertexPosition(int modelData, int vertexIndex, float* outPosition);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void* args, int arg9);

extern s32 lbl_80329B78[];
extern f32 timeDelta;
extern f32 lbl_803E648C;
extern f32 lbl_803E6494;
extern f32 lbl_803E64AC;
extern f32 lbl_803E64B0;
extern f32 lbl_803E64C4;
extern f32 lbl_803E64C8;
extern f32 lbl_803E64CC;
extern f32 lbl_803E64D0;
extern f32 lbl_803E64D4;

/*
 * --INFO--
 *
 * Function: dfptargetblock_update
 * EN v1.0 Address: 0x80208B70
 * EN v1.0 Size: 524b
 */
void dfptargetblock_update(DfpTargetBlockObject* obj)
{
    u8 mode;
    undefined bitVal;
    DfpTargetBlockState* state;
    DfpTargetBlockHome* home;
    float buf[6];

    state = (DfpTargetBlockState*)obj->state;
    home = obj->home;
    if (obj->objectType == DFPTARGETBLOCK_HOME_OBJECT_TYPE)
    {
        buf[3] = lbl_803E648C;
        buf[4] = lbl_803E64C4;
        buf[5] = lbl_803E648C;
        objfx_spawnArcedBurst((int)obj, 5, lbl_803E64C8, 1, 2, 0x32, lbl_803E64C4,
                              lbl_803E64C4, lbl_803E64B0, buf, 0);
    }
    else
    {
        if (state->completionSfxReady == '\0')
        {
            bitVal = GameBit_Get((int)state->completionSfxId);
            state->completionSfxReady = bitVal;
        }
        if (state->stateSfxReady == '\0')
        {
            bitVal = GameBit_Get((int)state->stateSfxId);
            state->stateSfxReady = bitVal;
        }
        if (((state->completionSfxReady == '\0') && (state->stateSfxReady != '\0')) &&
            (mode = state->mode, mode != DFPTARGETBLOCK_MODE_SETTLED))
        {
            if ((mode == DFPTARGETBLOCK_MODE_RAISING) || (mode == DFPTARGETBLOCK_MODE_RESETTING))
            {
                if (obj->y <= home->y)
                {
                    obj->y = obj->y + timeDelta;
                    if (obj->y >= home->y)
                    {
                        obj->y = home->y;
                        state->mode = DFPTARGETBLOCK_MODE_ACTIVE;
                    }
                }
            }
            else if (mode == DFPTARGETBLOCK_MODE_LOWERING)
            {
                if (obj->y >= home->y - lbl_803E64AC)
                {
                    obj->y = lbl_803E6494 * timeDelta + obj->y;
                    if (obj->y <= home->y - lbl_803E64AC)
                    {
                        obj->y = home->y - lbl_803E64AC;
                        state->mode = DFPTARGETBLOCK_MODE_SETTLED;
                        GameBit_Set((int)state->completionSfxId, 1);
                    }
                }
            }
            else if (state->pathState != NULL)
            {
                (*gPathControlInterface)->update(obj, state->pathState, timeDelta);
                (*gPathControlInterface)->apply(obj, state->pathState);
                (*gPathControlInterface)->advance(obj, state->pathState, timeDelta);
            }
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: dfptargetblock_init
 * EN v1.0 Address: 0x80208D7C
 * EN v1.0 Size: 600b
 */

void dfptargetblock_init(DfpTargetBlockObject* obj, int arg2)
{
    char pointCount;
    bool found;
    int count;
    int entry;
    undefined bitVal;
    int j;
    int i;
    DfpTargetBlockState* state;
    int model;
    double fconv;
    DfpTargetBlockPoint point;

    state = (DfpTargetBlockState*)obj->state;
    model = *ZBomb_GetActiveModel(obj);
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x4000;
    if (obj->objectType == DFPTARGETBLOCK_HOME_OBJECT_TYPE)
    {
        lbl_80329B78[0] = (int)obj->x;
        lbl_80329B78[1] = (int)obj->y;
        lbl_80329B78[2] = (int)obj->z;
    }
    else
    {
        fconv = (double)lbl_803E64CC;
        for (i = 0; i < (int)(uint) * (ushort*)(model + 0xe4); i = i + 1)
        {
            Model_GetVertexPosition(model, i, &point.x);
            if ((double)point.y < fconv)
            {
                fconv = (double)point.y;
            }
        }
        for (i = 0; i < (int)(uint) * (ushort*)(model + 0xe4); i = i + 1)
        {
            Model_GetVertexPosition(model, i, &point.x);
            if ((double)point.y == fconv)
            {
                found = false;
                pointCount = state->floorPointCount;
                for (j = 0; j < pointCount; j = j + 1)
                {
                    entry = (int)state + j * 12;
                    if ((point.x == *(float*)(entry + 4)) && (point.z == *(float*)(entry + 12)))
                    {
                        found = true;
                        j = (int)pointCount;
                    }
                }
                if (!found)
                {
                    count = (int)state->floorPointCount;
                    state->floorPoints[count].x = point.x;
                    state->floorPoints[(int)state->floorPointCount].y = point.y;
                    state->floorPoints[(int)state->floorPointCount].z = point.z;
                    state->floorPointCount = state->floorPointCount + '\x01';
                }
            }
        }
        state->mode = DFPTARGETBLOCK_MODE_RAISING;
        obj->y = obj->y - lbl_803E64AC;
        state->completionSfxId = *(short*)(arg2 + 0x1e);
        state->stateSfxId = *(short*)(arg2 + 0x20);
        bitVal = GameBit_Get((int)state->completionSfxId);
        state->completionSfxReady = bitVal;
        bitVal = GameBit_Get((int)state->stateSfxId);
        state->stateSfxReady = bitVal;
        if (state->completionSfxReady != '\0')
        {
            obj->x = obj->x + lbl_803E64D0;
            obj->z = obj->z + lbl_803E64D4;
            state->mode = DFPTARGETBLOCK_MODE_SETTLED;
        }
    }
    return;
}

void dfptargetblock_release(void)
{
}

void dfptargetblock_initialise(void)
{
}

s32 lbl_80329B78[] = {0, 0, 0};

ObjectDescriptor10WithPadding gDfptargetblockObjDescriptor = {
    {
        0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)dfptargetblock_initialise,
        (ObjectDescriptorCallback)dfptargetblock_release,
        0,
        (ObjectDescriptorCallback)dfptargetblock_init,
        (ObjectDescriptorCallback)dfptargetblock_update,
        (ObjectDescriptorCallback)dfptargetblock_hitDetect,
        (ObjectDescriptorCallback)dfptargetblock_render,
        (ObjectDescriptorCallback)dfptargetblock_free,
        (ObjectDescriptorCallback)dfptargetblock_getObjectTypeId,
        dfptargetblock_getExtraSize,
    },
    0,
};
