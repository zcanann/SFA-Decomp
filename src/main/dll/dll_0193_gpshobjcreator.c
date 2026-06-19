/* DLL 0x0193 (gpshobjcreator) — GPSH shrine object creator and ecsh_shrine update [0x801C8084-0x801C82C8). */
#include "main/dll/gpshshrineflags_struct.h"
extern f32 timeDelta;
extern int Obj_IsLoadingLocked(void);
#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/VF/vf_shared.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"

typedef struct GpshObjcreatorState
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 pad5[0x8 - 0x5];
} GpshObjcreatorState;

typedef struct GpshObjcreatorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s8 unk1E;
    u8 pad1F[0x20 - 0x1F];
} GpshObjcreatorObjectDef;

extern void hitDetectFn_80097070(int* obj, f32 e, int a, int b, int c, int d);

extern void* Obj_AllocObjectSetup(int size, int b);
extern f32 lbl_803E504C;
extern f32 lbl_803E5050;
extern f32 lbl_803E5054;
extern s16 lbl_803263B8[];
extern f32 lbl_803E5048;

void gpsh_objcreator_free(void)
{
}

void gpsh_objcreator_hitDetect(void)
{
}

void gpsh_objcreator_release(void)
{
}

void gpsh_objcreator_initialise(void)
{
}

void gpsh_objcreator_update(int* obj)
{
    extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d); /* #57 */
    u8* sub;
    void* setup;

    sub = ((GameObject*)obj)->extra;
    if (GameBit_Get(0x5af) != 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
        ((GpshShrineFlags*)(sub + 5))->b80 = 0;
        *(u8*)((char*)obj + 0x37) = 0xff;
        ((GameObject*)obj)->anim.alpha = 0xff;
    }
    if (((GpshShrineFlags*)(sub + 5))->b80) return;
    if (((GameObject*)obj)->unkF8 == 0)
    {
        if (GameBit_Get(0x148) != 0)
        {
            *(f32*)sub = lbl_803E504C;
            ((GameObject*)obj)->unkF8 = 1;
        }
    }
    if ((u8)Obj_IsLoadingLocked() == 0) return;
    if (*(f32*)sub == lbl_803E5050) return;
    *(f32*)sub = *(f32*)sub - timeDelta;
    hitDetectFn_80097070(obj, lbl_803E5054, 2, 1, 1, 0);
    if (*(f32*)sub <= lbl_803E5050)
    {
        Sfx_PlayFromObjectLimited(0, SFXwp_swtst1_c, 1);
        setup = Obj_AllocObjectSetup(0x24, sub[4] + 0x1f4);
        ((GpshShrineFlags*)(sub + 5))->b80 = 1;
        *(u8*)((char*)setup + 7) = 0xff;
        *(u8*)((char*)setup + 4) = 0x20;
        *(u8*)((char*)setup + 5) = 2;
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s16*)setup = (s16)(sub[4] + 0x1f4);
        *(u8*)((char*)setup + 0x18) = (u8)((s32) * (s16*)obj >> 8);
        *(s16*)((char*)setup + 0x1a) = lbl_803263B8[sub[4]];
        Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, *(void**)&((GameObject*)obj)->anim.parent);
    }
}

void gpsh_scene_free(void);

int gpsh_objcreator_getExtraSize(void) { return 0x8; }
int gpsh_objcreator_getObjectTypeId(void) { return 0x0; }
int gpsh_scene_getExtraSize(void);

void gpsh_objcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5048);
}

void gpsh_scene_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void gpsh_objcreator_init(int* obj, int* def)
{
    register u32 zero;
    register int* state;
    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)((GpshObjcreatorObjectDef*)def)->unk1E << 8);
    zero = 0;
    ((GameObject*)obj)->unkF8 = zero;
    ((GpshObjcreatorState*)state)->unk4 = (u8)((GpshObjcreatorObjectDef*)def)->unk1A;
    ((GpshShrineFlags*)((char*)state + 5))->b80 = 0;
    *(u8*)((char*)obj + 0x37) = 0xff;
    ((GameObject*)obj)->anim.alpha = 0xff;
}
