/* === moved from main/dll/DF/rope.c [801C04B8-801C053C) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll_000A_expgfx.h"











extern void ModelLightStruct_free(void* light);
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern void objRenderFn_8003b8f4(f32 scale);


extern f32 timeDelta;
extern EffectInterface** gPartfxInterface;
extern void Sfx_PlayFromObject(int obj, int id);
extern void doRumble(f32 v);
extern void modelLightStruct_setEnabled(int light, int v, f32 f);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern int Obj_GetPlayerObject(void);

/*
 * --INFO--
 *
 * Function: dimbossgut2_updateTracking
 * EN v1.0 Address: 0x801BF048
 * EN v1.0 Size: 652b
 * EN v1.1 Address: 0x801BF5FC
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dimbossgut2_free
 * EN v1.0 Address: 0x801BF2F0
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801BF8A4
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dimbossgut2_render
 * EN v1.0 Address: 0x801BF37C
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801BF930
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dimbossgut2_update
 * EN v1.0 Address: 0x801BF3E8
 * EN v1.0 Size: 716b
 * EN v1.1 Address: 0x801BF99C
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dimbossgut2_init
 * EN v1.0 Address: 0x801BF6B4
 * EN v1.0 Size: 540b
 * EN v1.1 Address: 0x801BFC68
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void lightSetFieldBC_8001db14(int light, int v);
extern void modelLightStruct_setLightKind(int light, int v);
extern void modelLightStruct_setDiffuseColor(int light, int a, int b, int c, int d);


/*
 * --INFO--
 *
 * Function: DIMbossspit_updateBurst
 * EN v1.0 Address: 0x801BF8D8
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x801BFE8C
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: DIMbossspit_free
 * EN v1.0 Address: 0x801BFB70
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801C0124
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: DIMbossspit_render
 * EN v1.0 Address: 0x801BFBC4
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801C0178
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: DIMbossspit_update
 * EN v1.0 Address: 0x801BFC2C
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x801C01E0
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: DIMbossspit_init
 * EN v1.0 Address: 0x801BFEB4
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x801C0468
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



/* Trivial 4b 0-arg blr leaves. */















/*
 * --INFO--
 *
 * Function: magicmaker_update
 * EN v1.0 Address: 0x801C0080
 * EN v1.0 Size: 624b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */








void dimbossfire_hitDetect(void)
{
}

/*
 * --INFO--
 *
 * Function: dimbossfire_free
 * EN v1.0 Address: 0x801C04C8
 * EN v1.0 Size: 100b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossfire_free(int obj)
{
    int o = obj;
    int state;
    void* light;

    state = *(int*)(o + 0xb8);
    light = *(void**)(state + 0x10);
    if (light != 0)
    {
        ModelLightStruct_free(light);
        *(undefined4*)(state + 0x10) = 0;
    }
    (*gExpgfxInterface)->freeSource2((u32)o);
}

void dimbossfire_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

/* 8b "li r3, N; blr" returners. */
int dimbossgut2_setScale(void);
int dimbossfire_getExtraSize(void) { return 0x14; }
int dimbossfire_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
void magicmaker_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/DF/DFcradle.h"
#include "main/effect_interfaces.h"

typedef struct DimbossfireState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    s32 light;
    u8 pad14[0x18 - 0x14];
} DimbossfireState;


extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void CameraShake_Start(f32 magnitude, f32 duration, f32 param_3);
extern void doRumble(f32 val);
extern void* memcpy(void* dst, const void* src, u32 size);
extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a);
extern void lightSetFieldBC_8001db14(int light, int value);
extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);
extern uint GameBit_Get(int eventId);
extern f32 Vec_distance(float* posA, float* posB);
extern undefined4 ObjHits_DisableObject();
extern undefined8 ObjGroup_RemoveObject(int obj, int groupId);
extern undefined4 ObjGroup_AddObject(int obj, int groupId);

extern f32 lbl_80325D68[];
extern f32 lbl_803E4DA0;
extern f32 lbl_803E4DA4;
extern f32 lbl_803E4DA8;
extern f32 lbl_803E4DAC;
extern f32 lbl_803E4DB0;
extern f32 lbl_803E4DB4;
extern f32 lbl_803E4DB8;
extern f32 lbl_803E4DBC;
extern f32 lbl_803E4DC0;
extern f32 lbl_803E4DD0;
extern f32 lbl_803E4DD4;
extern f32 lbl_803E4DE0;
extern f32 lbl_803E4DE4;
extern f32 lbl_803E4DE8;


/*
 * --INFO--
 *
 * Function: dimbossfire_update
 * EN v1.0 Address: 0x801C053C
 * EN v1.0 Size: 1136b
 * EN v1.1 Address: 0x801C0AF0
 * EN v1.1 Size: 1136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossfire_update(int obj)
{
    extern u32 randomGetRange(int min, int max);
    extern undefined4 GameBit_Set(int eventId, int value);
    extern int objCreateLight(int obj, int param_2);
    extern void modelLightStruct_setDistanceAttenuation(f32 min, f32 max, int light);
    uint bitVal;
    int* light;
    int ref;
    int placement;
    byte* state;
    float heat;

    state = ((GameObject*)obj)->extra;
    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    if ((int)*(short*)(placement + 0x20) != 0xffffffff)
    {
        bitVal = GameBit_Get((int)*(short*)(placement + 0x20));
        if (bitVal != 0)
        {
            GameBit_Set((int)*(short*)(placement + 0x20), 0);
            *state = *state | 1;
            ((DimbossfireState*)state)->unk4 = lbl_80325D68[state[1]];
            ((DimbossfireState*)state)->unk8 = ((DimbossfireState*)state)->unk4;
            state[1] += 1;
            if (state[1] >= 10)
            {
                state[1] = 0;
            }
        }
    }
    else
    {
        ((DimbossfireState*)state)->unkC = ((DimbossfireState*)state)->unkC - timeDelta;
        if (((DimbossfireState*)state)->unkC <= lbl_803E4DA0)
        {
            ((DimbossfireState*)state)->unkC = (f32)(int)
            randomGetRange(0xf0, 0x1e0);
            *state = *state | 1;
            ((DimbossfireState*)state)->unk4 = lbl_80325D68[state[1]];
            ((DimbossfireState*)state)->unk8 = ((DimbossfireState*)state)->unk4;
            state[1] += 1;
            if (state[1] >= 10)
            {
                state[1] = 0;
            }
        }
    }
    if (((DimbossfireState*)state)->unk4 > lbl_803E4DA0)
    {
        if ((*state & 1) != 0)
        {
            *state = *state & 0xfe;
            ObjHits_SetHitVolumeSlot(obj, 9, 1, 0);
            ObjHitbox_SetSphereRadius(obj, 0xf);
            ObjHits_EnableObject(obj);
            if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
            {
                ref = 0;
                do
                {
                    if (*(short*)(placement + 0x1a) == 0)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x4cc, NULL, 2, -1, NULL);
                    }
                    else
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x4c9, NULL, 2, -1, NULL);
                    }
                    ref = ref + 1;
                }
                while (ref < 0x32);
            }
            ref = Obj_GetPlayerObject();
            if ((ref != 0) && ((*(ushort*)(ref + 0xb0) & 0x1000) == 0))
            {
                heat = Vec_distance((float*)&((GameObject*)obj)->anim.worldPosX, (float*)(ref + 0x18));
                if (heat <= lbl_803E4DA4)
                {
                    heat = lbl_803E4DA8 - heat / lbl_803E4DA4;
                    CameraShake_Start(lbl_803E4DAC * heat, lbl_803E4DAC, lbl_803E4DB0);
                    doRumble(lbl_803E4DB4 * heat);
                }
            }
            if (((DimbossfireState*)state)->light == 0)
            {
                light = (int*)objCreateLight(obj, 1);
                *(int**)&((DimbossfireState*)state)->light = light;
                if (((DimbossfireState*)state)->light != 0)
                {
                    modelLightStruct_setLightKind(((DimbossfireState*)state)->light, 2);
                    lightSetFieldBC_8001db14(((DimbossfireState*)state)->light, 1);
                    if (*(short*)(placement + 0x1a) == 0)
                    {
                        modelLightStruct_setDiffuseColor(((DimbossfireState*)state)->light, 0x7f, 0xff, 0, 0);
                    }
                    else
                    {
                        modelLightStruct_setDiffuseColor(((DimbossfireState*)state)->light, 0xff, 0x7f, 0, 0);
                    }
                    modelLightStruct_setDistanceAttenuation(lbl_803E4DB8, lbl_803E4DBC,
                                                            ((DimbossfireState*)state)->light);
                    modelLightStruct_setEnabled(((DimbossfireState*)state)->light, 1, lbl_803E4DA0);
                    modelLightStruct_setEnabled(((DimbossfireState*)state)->light, 0,
                                                ((DimbossfireState*)state)->unk4 / lbl_803E4DC0);
                }
            }
            Sfx_PlayFromObject(obj, SFXar_boost16);
        }
        ((DimbossfireState*)state)->unk4 = ((DimbossfireState*)state)->unk4 - timeDelta;
        if (((DimbossfireState*)state)->unk4 > lbl_803E4DA0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x4ca, NULL, 2, -1, NULL);
            if (*(short*)(placement + 0x1a) == 0)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x4cd, NULL, 2, -1, NULL);
            }
            else
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x4cb, NULL, 2, -1, NULL);
            }
        }
        else
        {
            ((DimbossfireState*)state)->unk4 = lbl_803E4DA0;
            if (*(uint*)&((DimbossfireState*)state)->light != 0)
            {
                ModelLightStruct_free(*(void**)&((DimbossfireState*)state)->light);
                ((DimbossfireState*)state)->light = 0;
            }
            ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
            ObjHitbox_SetSphereRadius(obj, 0);
            ObjHits_DisableObject(obj);
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: dimbossfire_init
 * EN v1.0 Address: 0x801C09AC
 * EN v1.0 Size: 172b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossfire_init(int obj, undefined4 arg2, int placement)
{
    extern u32 randomGetRange(int min, int max);
    uint ua;
    undefined randVal;
    int state;

    state = *(int*)&((GameObject*)obj)->extra;
    ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
    ObjHitbox_SetSphereRadius(obj, 0);
    ObjHits_DisableObject(obj);
    if (placement == 0)
    {
        ((DimbossfireState*)state)->unkC = (f32)(int)
        randomGetRange(0xf0, 0x1e0);
        randVal = randomGetRange(0, 9);
        *(undefined*)(state + 1) = randVal;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: dimbossfire_release
 * EN v1.0 Address: 0x801C0A58
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C0B30
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossfire_release(void)
{
}

/*
 * --INFO--
 *
 * Function: dimbossfire_initialise
 * EN v1.0 Address: 0x801C0A5C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C0B34
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbossfire_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: ccriverflow_getExtraSize
 * EN v1.0 Address: 0x801C0A60
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801C0B38
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ccriverflow_getExtraSize(void)
{
    return 1;
}

/*
 * --INFO--
 *
 * Function: ccriverflow_free
 * EN v1.0 Address: 0x801C0A68
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ccriverflow_free(CCriverflowObject* obj)
{
    if (obj->state->active != 0)
    {
        ObjGroup_RemoveObject((int)obj, CCRIVERFLOW_OBJECT_GROUP);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: ccriverflow_render
 * EN v1.0 Address: 0x801C0A9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C0B88
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ccriverflow_render(void)
{
}

/*
 * --INFO--
 *
 * Function: ccriverflow_update
 * EN v1.0 Address: 0x801C0AA0
 * EN v1.0 Size: 148b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ccriverflow_update(CCriverflowObject* obj)
{
    uint isGameBitSet;
    CCriverflowMapData* mapData;
    CCriverflowState* state;

    mapData = obj->mapData;
    if (mapData->gameBit != -1)
    {
        state = obj->state;
        isGameBitSet = GameBit_Get((int)mapData->gameBit);
        if (isGameBitSet != 0)
        {
            if (state->active != 0)
            {
                state->active = 0;
                ObjGroup_RemoveObject((int)obj, CCRIVERFLOW_OBJECT_GROUP);
            }
        }
        else if (state->active == 0)
        {
            state->active = 1;
            ObjGroup_AddObject((int)obj, CCRIVERFLOW_OBJECT_GROUP);
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: ccriverflow_init
 * EN v1.0 Address: 0x801C0B34
 * EN v1.0 Size: 196b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ccriverflow_init(CCriverflowObject* obj, CCriverflowMapData* params)
{
    if (params->gameBit == -1)
    {
        ObjGroup_AddObject((int)obj, CCRIVERFLOW_OBJECT_GROUP);
        obj->state->active = 1;
    }
    obj->angle = (u16)params->angleByte << 8;
    obj->height = obj->model->baseHeight;
    obj->height = (f32)(u32)
    params->heightOffset * lbl_803E4DD0 + obj->height;
    if (obj->height < lbl_803E4DD4)
    {
        obj->height = *(f32*)&lbl_803E4DD4;
    }
    if (params->speedByte == 0)
    {
        params->speedByte = CCRIVERFLOW_DEFAULT_SPEED;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: fn_801C0BF8
 * EN v1.0 Address: 0x801C0BF8
 * EN v1.0 Size: 616b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801C0BF8(void* templateData, int angle, float* startNode, float* endNode, short* out)
{
    int startX;
    int startY;
    int startZ;
    int endX;
    int endY;
    int endZ;
    int i;
    short* vertex;
    float angleRadians;
    double vertexX;

    startX = (int)(lbl_803E4DE0 * startNode[0]);
    startY = (int)(lbl_803E4DE0 * startNode[1]);
    startZ = (int)(lbl_803E4DE0 * startNode[2]);
    endX = (int)(lbl_803E4DE0 * endNode[0]);
    endY = (int)(lbl_803E4DE0 * endNode[1]);
    endZ = (int)(lbl_803E4DE0 * endNode[2]);
    memcpy(out, templateData, 0x60);

    angleRadians = (lbl_803E4DE4 * (float)(short)angle) / lbl_803E4DE8;
    vertex = out;
    for (i = 0; i < 6; i++)
    {
        vertexX = (float)(int)*vertex;
        *vertex = (short)(int)(vertexX * mathCosf(angleRadians));
        vertex[2] = (short)(int)(-vertexX * mathSinf(angleRadians));
        vertex += 8;
    }

    out[0] += startX;
    out[1] += startY;
    out[2] += startZ;
    out[0x18] += endX;
    out[0x19] += endY;
    out[0x1a] += endZ;
    out[8] += startX;
    out[9] += startY;
    out[10] += startZ;
    out[0x20] += endX;
    out[0x21] += endY;
    out[0x22] += endZ;
    out[0x10] += startX;
    out[0x11] += startY;
    out[0x12] += startZ;
    out[0x28] += endX;
    out[0x29] += endY;
    out[0x2a] += endZ;
    return;
}
