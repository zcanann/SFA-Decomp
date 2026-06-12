/* DLL 0x1E7 - DIMBossFire [801C04B8-801C053C) */
#include "main/dll_000A_expgfx.h"

extern void ModelLightStruct_free(void* light);
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_EnableObject();
extern void objRenderFn_8003b8f4(f32 scale);

extern f32 timeDelta;
extern EffectInterface** gPartfxInterface;
extern void Sfx_PlayFromObject(int obj, int id);
extern void doRumble(f32 v);
extern void modelLightStruct_setEnabled(int light, int v, f32 f);
extern int Obj_GetPlayerObject(void);

extern void lightSetFieldBC_8001db14(int light, int v);
extern void modelLightStruct_setLightKind(int light, int v);
extern void modelLightStruct_setDiffuseColor(int light, int a, int b, int c, int d);

/* Trivial 4b 0-arg blr leaves. */

void dimbossfire_hitDetect(void)
{
}

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
extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a);
extern void lightSetFieldBC_8001db14(int light, int value);
extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);
extern uint GameBit_Get(int eventId);
extern f32 Vec_distance(float* posA, float* posB);
extern undefined4 ObjHits_DisableObject();

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

void dimbossfire_release(void)
{
}

void dimbossfire_initialise(void)
{
}

int ccriverflow_getExtraSize(void);
