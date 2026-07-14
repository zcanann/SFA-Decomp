/* DLL 0x0193 (gpshobjcreator) — GPSH shrine object creator and ecsh_shrine update [0x801C8084-0x801C82C8). */
#include "main/dll/gpshshrineflags_struct.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#define OBJFX_HIT_DETECT_SCALE_SECOND_INTPTR_LEGACY
#include "main/objfx.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/frame_timing.h"
#include "main/object_render_legacy.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"

typedef struct GpshObjcreatorState
{
    u8 pad0[0x4 - 0x0];
    u8 objTypeIndex;
    u8 pad5[0x8 - 0x5];
} GpshObjcreatorState;

typedef struct GpshObjcreatorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 objTypeIndex;
    u8 pad1C[0x1E - 0x1C];
    s8 rotX;
    u8 pad1F[0x20 - 0x1F];
} GpshObjcreatorObjectDef;

/* 0x24-byte spawn descriptor handed to Obj_SetupObject for the created
 * shrine object. ObjPlacement-style head (type id / color / position)
 * plus class-specific tail. */
typedef struct GpshObjcreatorSpawnSetup
{
    ObjPlacement base; /* 0x00..0x17 */
    u8 rotByte;      /* 0x18 */
    u8 pad19;        /* 0x19 */
    s16 unk1A;       /* 0x1a */
    u8 pad1C[8];     /* 0x1c */
} GpshObjcreatorSpawnSetup;

STATIC_ASSERT(offsetof(GpshObjcreatorSpawnSetup, base.posX) == 0x8);
STATIC_ASSERT(offsetof(GpshObjcreatorSpawnSetup, rotByte) == 0x18);
STATIC_ASSERT(offsetof(GpshObjcreatorSpawnSetup, unk1A) == 0x1a);
STATIC_ASSERT(sizeof(GpshObjcreatorSpawnSetup) == 0x24);


extern s16 lbl_803263B8[];

int gpsh_objcreator_getExtraSize(void) { return 0x8; }
int gpsh_objcreator_getObjectTypeId(void) { return 0x0; }

void gpsh_objcreator_free(void)
{
}

void gpsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void gpsh_objcreator_hitDetect(void)
{
}

void gpsh_objcreator_update(int* obj)
{
    u8* sub;
    GpshObjcreatorSpawnSetup* setup;

    sub = ((GameObject*)obj)->extra;
    if (mainGetBit(0x5af) != 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
        ((GpshShrineFlags*)(sub + 5))->b80 = 0;
        *(u8*)((char*)obj + 0x37) = 0xff;
        ((GameObject*)obj)->anim.alpha = 0xff;
    }
    if (((GpshShrineFlags*)(sub + 5))->b80) return;
    if (((GameObject*)obj)->unkF8 == 0)
    {
        if (mainGetBit(0x148) != 0)
        {
            *(f32*)sub = 100.0f;
            ((GameObject*)obj)->unkF8 = 1;
        }
    }
    if ((u8)Obj_IsLoadingLocked() == 0) return;
    if (!*(f32*)sub) return;
    *(f32*)sub = *(f32*)sub - timeDelta;
    hitDetectFn_80097070(obj, 0.6f, 2, 1, 1, 0);
    if (*(f32*)sub <= 0.0f)
    {
        Sfx_PlayFromObjectLimited(0, SFXTRIG_wp_hitpos_6_167, 1);
        setup = (GpshObjcreatorSpawnSetup*)Obj_AllocObjectSetup(0x24, sub[4] + 0x1f4);
        ((GpshShrineFlags*)(sub + 5))->b80 = 1;
        setup->base.color[3] = 0xff;
        setup->base.color[0] = 0x20;
        setup->base.color[1] = 2;
        setup->base.posX = ((GameObject*)obj)->anim.localPosX;
        setup->base.posY = ((GameObject*)obj)->anim.localPosY;
        setup->base.posZ = ((GameObject*)obj)->anim.localPosZ;
        setup->base.objectId = (s16)(sub[4] + 0x1f4);
        setup->rotByte = (u8)((s32) * (s16*)obj >> 8);
        setup->unk1A = lbl_803263B8[sub[4]];
        Obj_SetupObject(&setup->base, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                        ((GameObject*)obj)->anim.parent);
    }
}

void gpsh_objcreator_init(int* obj, int* def)
{
    register u32 zero;
    register int* state;
    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)((GpshObjcreatorObjectDef*)def)->rotX << 8);
    zero = 0;
    ((GameObject*)obj)->unkF8 = zero;
    ((GpshObjcreatorState*)state)->objTypeIndex = (u8)((GpshObjcreatorObjectDef*)def)->objTypeIndex;
    ((GpshShrineFlags*)((char*)state + 5))->b80 = 0;
    *(u8*)((char*)obj + 0x37) = 0xff;
    ((GameObject*)obj)->anim.alpha = 0xff;
}

void gpsh_objcreator_release(void)
{
}

void gpsh_objcreator_initialise(void)
{
}
