/*
 * DLL 0x0215 - wmnewcrystal (gResourceDescriptors[0x215]): the blue/green power
 * crystals at Krazoa Palace (map 'warlock'). TU: 0x801F943C-0x801F9804.
 * The warlock romlist places all three variants (defs 890/891/892 'WM_newcrystal',
 * types 0x783 blue / 0x784 green / 0x785): Krystal's crystal-prison set seen in
 * the finale. While the active game bit is set, the blue crystal runs its two glow
 * effects every sequence tick (plus an ambient particle pair until the ambient bit
 * is granted) and the green crystal sprays directional bursts from its two path
 * points. Sequence event 1 is the on-camera finale detonation: the object is pulled
 * 100 units toward the camera, blown up via the shared spawnExplosion() (the same
 * engine routine - and therefore the same effect and sound - as the gunpowder
 * barrels), and hidden. Event 2 retires the green crystal's bursts.
 */
#include "main/dll/WM/wm_shared.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/camera.h"

#define WMNEWCRYSTAL_GAMEBIT_ACTIVE 0xd27
#define WMNEWCRYSTAL_GAMEBIT_AMBIENT_FX 0xe49
#define WMNEWCRYSTAL_OBJECT_BLUE 0x783
#define WMNEWCRYSTAL_OBJECT_GREEN 0x784
#define WMNEWCRYSTAL_PARTICLE_ID 0x7ed

typedef struct WmNewCrystalState
{
    u8 fxState[0x34];    /* 0x00: primary glow-effect block (WM_newcrystalFn_800969b0) */
    u8 altFxState[0x34]; /* 0x34: secondary glow-effect block */
    u8 active;           /* 0x68: green crystal still bursting */
    u8 pad69[3];
} WmNewCrystalState;

STATIC_ASSERT(offsetof(WmNewCrystalState, altFxState) == 0x34);
STATIC_ASSERT(offsetof(WmNewCrystalState, active) == 0x68);
STATIC_ASSERT(sizeof(WmNewCrystalState) == 0x6C);

/* layout-compatible with the PartFxSpawnParams head (effect_interfaces.h) */
typedef struct WmNewCrystalParticleParams
{
    u8 pad0[6];
    s16 pathPoint; /* 0x06 */
    u8 pad8[4];
    f32 x; /* 0x0C */
    f32 y; /* 0x10 */
    f32 z; /* 0x14 */
} WmNewCrystalParticleParams;

STATIC_ASSERT(offsetof(WmNewCrystalParticleParams, pathPoint) == 0x06);
STATIC_ASSERT(offsetof(WmNewCrystalParticleParams, x) == 0x0C);
STATIC_ASSERT(sizeof(WmNewCrystalParticleParams) == 0x18);

extern void PSVECSubtract(f32 * a, f32 * b, f32 * out);
extern void PSVECNormalize(f32 * src, f32 * dst);
extern void PSVECScale(f32* src, f32* dst, f32 scale);
extern void PSVECAdd(f32 * a, f32 * b, f32 * out);
extern void spawnExplosion(int* obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern void WM_newcrystalFn_800969b0(int* obj, void* params, f32 a, f32 b, f32 c, f32 d, f32 e,
                                     int enabled);
extern void objfx_spawnDirectionalBurst(int* obj, int idx, f32 scale, int kind, int mode, int chance,
                                        f32 speed, void* origin, int flags);

int wmnewcrystal_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* actor);
int wmnewcrystal_getExtraSize(void);
int wmnewcrystal_getObjectTypeId(void);
void wmnewcrystal_free(void);
void wmnewcrystal_render(int p1, int p2, int p3, int p4, int p5, s8 vis);
void wmnewcrystal_hitDetect(void);
void wmnewcrystal_update(void);
void wmnewcrystal_init(GameObject* obj, void* setup);
void wmnewcrystal_release(void);
void wmnewcrystal_initialise(void);

ObjectDescriptor gWM_newcrystalObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    wmnewcrystal_initialise,
    wmnewcrystal_release,
    0,
    (ObjectDescriptorCallback)wmnewcrystal_init,
    wmnewcrystal_update,
    wmnewcrystal_hitDetect,
    (ObjectDescriptorCallback)wmnewcrystal_render,
    wmnewcrystal_free,
    (ObjectDescriptorCallback)wmnewcrystal_getObjectTypeId,
    wmnewcrystal_getExtraSize,
};

int wmnewcrystal_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* actor)
{
    WmNewCrystalState* state;
    WmNewCrystalParticleParams params;
    f32 cameraDelta[3];
    int i;

    state = obj->extra;
    for (i = 0; i < actor->eventCount; i++)
    {
        switch (actor->eventIds[i])
        {
        case 1:
            PSVECSubtract((f32*)((char*)Camera_GetCurrentViewSlot() + 0xc),
                          &obj->anim.localPosX, cameraDelta);
            PSVECNormalize(cameraDelta, cameraDelta);
            PSVECScale(cameraDelta, cameraDelta, 100.0f);
            PSVECAdd(&obj->anim.localPosX, cameraDelta, &obj->anim.localPosX);
            obj->anim.worldPosX = obj->anim.localPosX;
            obj->anim.worldPosY = obj->anim.localPosY;
            obj->anim.worldPosZ = obj->anim.localPosZ;
            spawnExplosion((int*)obj, 100.0f, 1, 1, 0, 0, 0, 0, 0);
            obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
            if (obj->anim.seqId == WMNEWCRYSTAL_OBJECT_BLUE)
            {
                GameBit_Set(WMNEWCRYSTAL_GAMEBIT_ACTIVE, 0);
            }
            break;
        case 2:
            state->active = 0;
            break;
        }
    }

    if (GameBit_Get(WMNEWCRYSTAL_GAMEBIT_ACTIVE) == 0)
    {
        return 0;
    }

    if (obj->anim.seqId == WMNEWCRYSTAL_OBJECT_BLUE)
    {
        if (GameBit_Get(WMNEWCRYSTAL_GAMEBIT_AMBIENT_FX) == 0)
        {
            (*gPartfxInterface)->spawnObject(obj, WMNEWCRYSTAL_PARTICLE_ID, NULL, 2, -1, NULL);
            /* params is uninitialized here on purpose - retail passes the raw
               stack block for this effect */
            (*gPartfxInterface)->spawnObject(obj, WMNEWCRYSTAL_PARTICLE_ID, &params, 2, -1, NULL);
        }
        WM_newcrystalFn_800969b0((int*)obj, state, 640.0f, 36.0f, -60.0f, 5.0f, 100.0f, 1);
        WM_newcrystalFn_800969b0((int*)obj, state->altFxState, 640.0f, 36.0f, 60.0f, 5.0f, 0.0f, 1);
    }
    else if (obj->anim.seqId == WMNEWCRYSTAL_OBJECT_GREEN && state->active != 0)
    {
        ObjPath_GetPointLocalPosition((int)obj, 0, &params.x, &params.y, &params.z);
        params.x *= obj->anim.rootMotionScale;
        params.y *= obj->anim.rootMotionScale;
        params.z *= obj->anim.rootMotionScale;
        params.pathPoint = 1;
        objfx_spawnDirectionalBurst((int*)obj, 5, 2.0f, 1, 1, 10, 4.0f, &params, 0);

        ObjPath_GetPointLocalPosition((int)obj, 1, &params.x, &params.y, &params.z);
        params.x *= obj->anim.rootMotionScale;
        params.y *= obj->anim.rootMotionScale;
        params.z *= obj->anim.rootMotionScale;
        params.pathPoint = 0;
        objfx_spawnDirectionalBurst((int*)obj, 5, 2.0f, 1, 1, 10, 4.0f, &params, 0);
    }
    return 0;
}

int wmnewcrystal_getExtraSize(void) { return sizeof(WmNewCrystalState); }

int wmnewcrystal_getObjectTypeId(void) { return 0x0; }

void wmnewcrystal_free(void)
{
}

void wmnewcrystal_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f); /* literal, not the named 1.0 extern (#71 pool shape) */
}

void wmnewcrystal_hitDetect(void)
{
}

void wmnewcrystal_update(void)
{
}

void wmnewcrystal_init(GameObject* obj, void* setup)
{
    WmNewCrystalState* state = obj->extra;
    obj->animEventCallback = wmnewcrystal_SeqFn;
    if ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) > 1)
    {
        GameBit_Set(WMNEWCRYSTAL_GAMEBIT_ACTIVE, 1);
        state->active = 1;
    }
}

void wmnewcrystal_release(void)
{
}

void wmnewcrystal_initialise(void)
{
}

/* descriptor/ptr table auto 0x80328e90-0x80329050 */
extern u8 dll_219_free[];
extern u8 dll_219_getExtraSize_ret_4[];
extern u8 dll_219_getObjectTypeId[];
extern u8 dll_219_hitDetect_nop[];
extern u8 dll_219_init[];
extern u8 dll_219_initialise_nop[];
extern u8 dll_219_release_nop[];
extern u8 dll_219_render_nop[];
extern u8 dll_219_update[];
extern u8 dll_21B_free[];
extern u8 dll_21B_getExtraSize_ret_4[];
extern u8 dll_21B_getObjectTypeId[];
extern u8 dll_21B_hitDetect_nop[];
extern u8 dll_21B_init[];
extern u8 dll_21B_initialise_nop[];
extern u8 dll_21B_release_nop[];
extern u8 dll_21B_render_nop[];
extern u8 dll_21B_update[];
extern u8 vfpladders_free[];
extern u8 vfpladders_getExtraSize[];
extern u8 vfpladders_getObjectTypeId[];
extern u8 vfpladders_hitDetect[];
extern u8 vfpladders_init[];
extern u8 vfpladders_initialise[];
extern u8 vfpladders_release[];
extern u8 vfpladders_render[];
extern u8 vfpladders_update[];
extern u8 vfplevelcontrol_free[];
extern u8 vfplevelcontrol_getExtraSize[];
extern u8 vfplevelcontrol_getObjectTypeId[];
extern u8 vfplevelcontrol_hitDetect[];
extern u8 vfplevelcontrol_init[];
extern u8 vfplevelcontrol_initialise[];
extern u8 vfplevelcontrol_release[];
extern u8 vfplevelcontrol_render[];
extern u8 vfplevelcontrol_update[];
extern u8 vfplift_free[];
extern u8 vfplift_getExtraSize[];
extern u8 vfplift_getObjectTypeId[];
extern u8 vfplift_hitDetect[];
extern u8 vfplift_init[];
extern u8 vfplift_initialise[];
extern u8 vfplift_release[];
extern u8 vfplift_render[];
extern u8 vfplift_update[];
extern u8 vfpminifire_free[];
extern u8 vfpminifire_getExtraSize[];
extern u8 vfpminifire_getObjectTypeId[];
extern u8 vfpminifire_hitDetect[];
extern u8 vfpminifire_init[];
extern u8 vfpminifire_initialise[];
extern u8 vfpminifire_release[];
extern u8 vfpminifire_render[];
extern u8 vfpminifire_update[];
extern u8 vfpobjcreator_free[];
extern u8 vfpobjcreator_getExtraSize[];
extern u8 vfpobjcreator_getObjectTypeId[];
extern u8 vfpobjcreator_hitDetect[];
extern u8 vfpobjcreator_init[];
extern u8 vfpobjcreator_initialise[];
extern u8 vfpobjcreator_release[];
extern u8 vfpobjcreator_render[];
extern u8 vfpobjcreator_update[];
extern u8 vfpstatueball_free[];
extern u8 vfpstatueball_getExtraSize[];
extern u8 vfpstatueball_getObjectTypeId[];
extern u8 vfpstatueball_hitDetect[];
extern u8 vfpstatueball_init[];
extern u8 vfpstatueball_initialise[];
extern u8 vfpstatueball_release[];
extern u8 vfpstatueball_render[];
extern u8 vfpstatueball_update[];

u32 gVFP_LevelControlObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)vfplevelcontrol_initialise, (u32)vfplevelcontrol_release, 0x00000000, (u32)vfplevelcontrol_init, (u32)vfplevelcontrol_update, (u32)vfplevelcontrol_hitDetect, (u32)vfplevelcontrol_render, (u32)vfplevelcontrol_free, (u32)vfplevelcontrol_getObjectTypeId, (u32)vfplevelcontrol_getExtraSize };
u32 gVFP_ObjCreatorObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)vfpobjcreator_initialise, (u32)vfpobjcreator_release, 0x00000000, (u32)vfpobjcreator_init, (u32)vfpobjcreator_update, (u32)vfpobjcreator_hitDetect, (u32)vfpobjcreator_render, (u32)vfpobjcreator_free, (u32)vfpobjcreator_getObjectTypeId, (u32)vfpobjcreator_getExtraSize };
u32 lbl_80328F00[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)vfpminifire_initialise, (u32)vfpminifire_release, 0x00000000, (u32)vfpminifire_init, (u32)vfpminifire_update, (u32)vfpminifire_hitDetect, (u32)vfpminifire_render, (u32)vfpminifire_free, (u32)vfpminifire_getObjectTypeId, (u32)vfpminifire_getExtraSize };
u32 dll_219[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)dll_219_initialise_nop, (u32)dll_219_release_nop, 0x00000000, (u32)dll_219_init, (u32)dll_219_update, (u32)dll_219_hitDetect_nop, (u32)dll_219_render_nop, (u32)dll_219_free, (u32)dll_219_getObjectTypeId, (u32)dll_219_getExtraSize_ret_4 };
u32 gVFP_statueballObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)vfpstatueball_initialise, (u32)vfpstatueball_release, 0x00000000, (u32)vfpstatueball_init, (u32)vfpstatueball_update, (u32)vfpstatueball_hitDetect, (u32)vfpstatueball_render, (u32)vfpstatueball_free, (u32)vfpstatueball_getObjectTypeId, (u32)vfpstatueball_getExtraSize };
u32 dll_21B[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)dll_21B_initialise_nop, (u32)dll_21B_release_nop, 0x00000000, (u32)dll_21B_init, (u32)dll_21B_update, (u32)dll_21B_hitDetect_nop, (u32)dll_21B_render_nop, (u32)dll_21B_free, (u32)dll_21B_getObjectTypeId, (u32)dll_21B_getExtraSize_ret_4 };
u32 gVFP_LaddersObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)vfpladders_initialise, (u32)vfpladders_release, 0x00000000, (u32)vfpladders_init, (u32)vfpladders_update, (u32)vfpladders_hitDetect, (u32)vfpladders_render, (u32)vfpladders_free, (u32)vfpladders_getObjectTypeId, (u32)vfpladders_getExtraSize };
u32 gVFPLiftObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)vfplift_initialise, (u32)vfplift_release, 0x00000000, (u32)vfplift_init, (u32)vfplift_update, (u32)vfplift_hitDetect, (u32)vfplift_render, (u32)vfplift_free, (u32)vfplift_getObjectTypeId, (u32)vfplift_getExtraSize };
