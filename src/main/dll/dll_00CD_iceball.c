/*
 * iceball (DLL 0x00CD) - the ChukChuk ice-spitter's projectile.
 *
 * iceball_update integrates the iceball each frame: an unkF4 lifetime timer,
 * primed to 0xb4 (180 frames), counts down by timeDelta (freeing the object at
 * <0), gravity (lbl_803E2E54) and drag (lbl_803E2E58) are applied to the Y
 * velocity, the model is spun (rotX/rotY/rotZ += 910), and it is moved + given
 * a radius-5 hit sphere.
 * On contact it plays an impact effect and goes invisible for 120 frames
 * before freeing:
 *   - fn_8015FCCC runs when the iceball strikes the player or Tricky: it
 *     notifies the owning ChukChuk (vtable msg 0x80) and bursts particles,
 *     keyed by the obj's seqId (0x2cb / 100 / 0x30a).
 *   - fn_8015FBEC runs for any other contact: a Krazoa-impact burst keyed by
 *     seqId (0x2cb / 100 / 0x30a).
 * iceball_init primes the lifetime (0xb4) and full alpha; render/free toggle
 * the camera view-Y offset for the impact shake.
 *
 * This TU also owns the ChukChuk object descriptor (gChukChukObjDescriptor);
 * the ChukChuk handlers themselves live in the sibling DLL 0x00CC.
 */
#include "main/dll/chukchukstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll/scarab.h"
#include "main/sfa_shared_decls.h"
extern void ObjHitbox_SetSphereRadius(int objPtr, s16 radius);
extern void ObjHits_SetHitVolumeSlot(u32 objPtr, int hitVolume, int hitType, int sourceSlot);
extern void ObjHits_DisableObject(u32 objPtr);
extern u32 ObjHits_EnableObject();
extern int objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int getTrickyObject(void);
extern int Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int* obj);
extern f32 timeDelta;
extern f32 lbl_803E2E54;
extern f32 lbl_803E2E58;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E2E50;


#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_8015FBEC(int obj)
{


    s16 mode = ((GameObject*)obj)->anim.seqId;
    int i;

    if (mode == 0x2cb)
    {
        for (i = 0; i < 25; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 834, NULL, 1, -1, NULL);
        }
    }
    else if (mode == 100 || mode == 0x30a)
    {
        for (i = 0; i < 25; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 836, NULL, 1, -1, NULL);
        }
    }

    Sfx_PlayFromObject(obj, SFXkr_impact3);
    Camera_EnableViewYOffset();
    CameraShake_SetAllMagnitudes(lbl_803E2E50);
}
#pragma dont_inline reset

static inline u8 scarab_isObjectInList(void* o)
{
    extern void* ObjList_GetObjects(int* outA, int* outB);
    int i;
    int count;
    int* objs = ObjList_GetObjects(&i, &count);
    while (i < count)
    {
        if (o == (void*)objs[i++])
        {
            return 1;
        }
    }
    return 0;
}

void fn_8015FCCC(int obj)
{


    s16 type;
    int n;

    Camera_EnableViewYOffset();
    CameraShake_SetAllMagnitudes(lbl_803E2E50);
    Sfx_PlayFromObject(obj, SFXkr_impact3);
    type = ((GameObject*)obj)->anim.seqId;
    if (type == 0x2cb)
    {
        if (((GameObject*)obj)->ownerObj != NULL)
        {
            if (scarab_isObjectInList(((GameObject*)obj)->ownerObj))
            {
                (*(void (**)(void*, int))(**(int**)(*(int*)&((GameObject*)obj)->ownerObj + 0x68) + 0x20))(
                    ((GameObject*)obj)->ownerObj, 0x80);
            }
        }
        for (n = 0; n < 25; n++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 832, NULL, 1, -1, NULL);
        }
    }
    else if (type == 100)
    {
        if (((GameObject*)obj)->ownerObj != NULL)
        {
            if (scarab_isObjectInList(((GameObject*)obj)->ownerObj))
            {
                (*(void (**)(void*, int))(**(int**)(*(int*)&((GameObject*)obj)->ownerObj + 0x68) + 0x24))(
                    ((GameObject*)obj)->ownerObj, 0x80);
            }
        }
        for (n = 0; n < 25; n++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 835, NULL, 1, -1, NULL);
        }
    }
    else if (type == 0x30a)
    {
        if (((GameObject*)obj)->ownerObj != NULL)
        {
            if (scarab_isObjectInList(((GameObject*)obj)->ownerObj))
            {
                (*(void (**)(void*, int, int))(**(int**)(*(int*)&((GameObject*)obj)->ownerObj + 0x68) + 0x24))(
                    ((GameObject*)obj)->ownerObj, 0x80, 0);
            }
        }
        for (n = 0; n < 25; n++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 835, NULL, 1, -1, NULL);
        }
    }
}

void iceball_update(u16* obj, int unused)
{
    int p;

    p = (int)obj;
    ((GameObject*)p)->unkF4 = (s32)((f32)((GameObject*)p)->unkF4 - timeDelta);
    if (((GameObject*)p)->unkF4 < 0)
    {
        Obj_FreeObject((int*)p);
        return;
    }
    if (((GameObject*)p)->anim.alpha == 0)
    {
        return;
    }
    /* raw offsets (rotX/rotZ/rotY +0/4/2, velocity +0x24/0x28/0x2c): the
       named-field form is fuzzy-100 but perturbs the .o; raw is byte-exact */
    ((GameObject*)p)->anim.velocityY = ((GameObject*)p)->anim.velocityY - lbl_803E2E54 * timeDelta;
    ((GameObject*)p)->anim.velocityY = ((GameObject*)p)->anim.velocityY * lbl_803E2E58;
    ((GameObject*)p)->anim.rotX += 910;
    ((GameObject*)p)->anim.rotZ += 910;
    ((GameObject*)p)->anim.rotY += 910;
    objMove(p, ((GameObject*)p)->anim.velocityX * timeDelta, ((GameObject*)p)->anim.velocityY * timeDelta,
            ((GameObject*)p)->anim.velocityZ * timeDelta);
    ObjHits_SetHitVolumeSlot(p, 10, 1, 0);
    ObjHitbox_SetSphereRadius(p, 5);
    ObjHits_EnableObject(p);
    if ((*(ObjHitsPriorityState**)&((GameObject*)p)->anim.hitReactState)->lastHitObject != 0 &&
        ((*(ObjHitsPriorityState**)&((GameObject*)p)->anim.hitReactState)->lastHitObject == Obj_GetPlayerObject() ||
            (*(ObjHitsPriorityState**)&((GameObject*)p)->anim.hitReactState)->lastHitObject == getTrickyObject()))
    {
        fn_8015FCCC(p);
        ((GameObject*)p)->anim.alpha = 0;
        ((GameObject*)p)->unkF4 = 120;
        (*(ObjHitsPriorityState**)&((GameObject*)p)->anim.hitReactState)->flags &= ~1;
    }
    else if ((*(ObjHitsPriorityState**)&((GameObject*)p)->anim.hitReactState)->contactFlags != 0)
    {
        fn_8015FBEC(p);
        ((GameObject*)p)->anim.alpha = 0;
        ((GameObject*)p)->unkF4 = 120;
        (*(ObjHitsPriorityState**)&((GameObject*)p)->anim.hitReactState)->flags &= ~1;
    }
}

#pragma scheduling on
#pragma peephole on

/* ChukChuk ice-spitter: defined in the sibling TU; this DLL only owns the
   descriptor below (its extra state is 0x18 bytes, getObjectTypeId 0). */
void chukchuk_free(void);
void chukchuk_hitDetect(void);
void chukchuk_release(void);
void chukchuk_initialise(void);
void chukchuk_init(u8* obj, u8* params);

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

void iceball_hitDetect(void)
{
}

void iceball_release(void)
{
}

void iceball_initialise(void)
{
}

int chukchuk_getExtraSize(void);
int chukchuk_getObjectTypeId(void);
int iceball_getExtraSize(void) { return 0x2; }
int iceball_getObjectTypeId(void) { return 0x0; }

void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#pragma scheduling off
#pragma peephole off
void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E2E50);
}
void iceball_free(void) { Camera_DisableViewYOffset(); }

void chukchuk_update(short* obj);

void chukchuk_setScale(int obj, int v);

void iceball_init(GameObject* obj)
{
    obj->unkF4 = 0xb4;
    ObjHits_DisableObject((int)obj);
    obj->anim.alpha = 0xff;
}

ObjectDescriptor11WithPadding gChukChukObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)chukchuk_initialise,
        (ObjectDescriptorCallback)chukchuk_release,
        0,
        (ObjectDescriptorCallback)chukchuk_init,
        (ObjectDescriptorCallback)chukchuk_update,
        (ObjectDescriptorCallback)chukchuk_hitDetect,
        (ObjectDescriptorCallback)chukchuk_render,
        (ObjectDescriptorCallback)chukchuk_free,
        (ObjectDescriptorCallback)chukchuk_getObjectTypeId,
        chukchuk_getExtraSize,
        (ObjectDescriptorCallback)chukchuk_setScale,
    },
    0,
};

ObjectDescriptor gIceBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)iceball_initialise,
    (ObjectDescriptorCallback)iceball_release,
    0,
    (ObjectDescriptorCallback)iceball_init,
    (ObjectDescriptorCallback)iceball_update,
    (ObjectDescriptorCallback)iceball_hitDetect,
    (ObjectDescriptorCallback)iceball_render,
    (ObjectDescriptorCallback)iceball_free,
    (ObjectDescriptorCallback)iceball_getObjectTypeId,
    iceball_getExtraSize,
};

/*__DATA_EXTERNS__*/
extern void dll_CB_func0B_nop();
extern void dll_CB_setScale();
extern void dll_CB_getExtraSize_ret_1040();
extern void dll_CB_getObjectTypeId();
extern void dll_CB_free();
extern void dll_CB_render();
extern void dll_CB_hitDetect();
extern void dll_CB_update();
extern void dll_CB_init();
extern void dll_CB_release_nop();
extern void dll_CB_initialise();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
u8 lbl_80320008[120] = { 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2 };
u8 lbl_80320080[32] = { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0 };
void* dll_CB[16] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x000B0000, dll_CB_initialise, dll_CB_release_nop, (void*)0x00000000, dll_CB_init, dll_CB_update, dll_CB_hitDetect, dll_CB_render, dll_CB_free, dll_CB_getObjectTypeId, dll_CB_getExtraSize_ret_1040, dll_CB_setScale, dll_CB_func0B_nop };
u8 lbl_803200E0[120] = { 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7, 0, 0, 0, 7 };
u8 lbl_80320158[32] = { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0 };
