#include "main/dll/DF/DFbarrelanim.h"
#include "main/game_object.h"
#include "main/dll/DF/dll_196.h"
#include "main/dll/DF/dll_198.h"

typedef struct DFSHDoor2SpeciPlacement
{
    u8 pad0[0x1B - 0x0];
    u8 unk1B;
    u8 pad1C[0x22 - 0x1C];
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} DFSHDoor2SpeciPlacement;


typedef struct DFDoorSpeciExtra
{
    u16 phase;
    u8 pad02;
    u8 state;
    u8 pad04[2];
} DFDoorSpeciExtra;

extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern void ObjGroup_AddObject(int obj, int group);
extern u32 GameBit_Get(int eventId);
extern int* objFindTexture(int obj, int a, int b);
extern void textureFree(void* resource);
extern void* textureLoadAsset(int assetId);
extern f32 sqrtf(f32 x);
extern f32 mathCosf(f32 x);
extern u8 framesThisStep;
extern int lbl_803DBF40;
extern void* lbl_803DBF48;
extern f32 lbl_803DBF50;
extern u8 lbl_803DBF58;
extern f32 lbl_803E4DFC;
extern f32 lbl_803E4E24;
extern f32 lbl_803E4E28;
extern f32 lbl_803E4E30;
extern f32 lbl_803E4E34;
extern f32 lbl_803E4E38;
extern f32 lbl_803E4E3C;
extern f32 lbl_803E4E40;
extern f64 lbl_803E4E48;

/*
 * --INFO--
 *
 * Function: dfropenode_update
 * EN v1.0 Address: 0x801C2278
 * EN v1.0 Size: 824b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfropenode_update(DFropenodeObject* obj);

/*
 * --INFO--
 *
 * Function: dfropenode_init
 * EN v1.0 Address: 0x801C25B0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfropenode_init(DFropenodeObject* obj, u8* objDef);

/*
 * --INFO--
 *
 * Function: dfropenode_release
 * EN v1.0 Address: 0x801C2634
 * EN v1.0 Size: 76b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfropenode_release(void);

/*
 * --INFO--
 *
 * Function: dfropenode_initialise
 * EN v1.0 Address: 0x801C2680
 * EN v1.0 Size: 96b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfropenode_initialise(void);

/*
 * --INFO--
 *
 * Function: DFSH_Door2Speci_SeqFn
 * EN v1.0 Address: 0x801C26E0
 * EN v1.0 Size: 316b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int DFSH_Door2Speci_SeqFn(int obj)
{
    int* texture;
    DFDoorSpeciExtra* extra;
    int objDef;
    int alpha;
    u32 phaseStep;
    f32 phase;

    extra = ((GameObject*)obj)->extra;
    objDef = *(int*)&((GameObject*)obj)->anim.placementData;
    switch (extra->state)
    {
    case 0:
        if (GameBit_Get(((DFSHDoor2SpeciPlacement*)objDef)->unk22) != 0)
        {
            extra->state = 1;
        }
        break;
    case 1:
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL)
        {
            alpha = *texture + framesThisStep * 0x10;
            if (alpha > 0x100)
            {
                alpha = 0x100;
                extra->state = 2;
            }
            *texture = alpha;
        }
        break;
    case 2:
    default:
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL)
        {
            phaseStep = (extra->phase + framesThisStep * 800) & 0xffff;
            extra->phase = phaseStep;
            phase = (lbl_803E4E3C * (f32)(u32)extra->phase) / lbl_803E4E40;
            *texture = (s32) - (lbl_803E4E34 * (lbl_803E4E38 - mathCosf(phase)) - lbl_803E4E30);
        }
        break;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_getExtraSize
 * EN v1.0 Address: 0x801C281C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801C29EC
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfsh_door2speci_getExtraSize(void)
{
    return sizeof(DFDoorSpeciExtra);
}

/* === merged from main/dll/DF/dll_199.c [801C2824-801C282C) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/dll/DF/dll_199.h"

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_getObjectTypeId
 * EN v1.0 Address: 0x801C2824
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801C2824
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfsh_door2speci_getObjectTypeId(void)
{
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

/* === moved from main/dll/DF/DFlantern.c [801C282C-801C2914) (TU re-split, docs/boundary_audit.md) === */
#include "main/mapEvent.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/DF/DFlantern.h"
#include "main/dll/DF/dll_198.h"
#include "main/objanim.h"

extern uint GameBit_Get(int eventId);
extern int* objFindTexture(int obj, int textureIndex, int materialIndex);
extern void objRenderFn_8003b8f4(f32);
extern void ModelLightStruct_free(void* light);
extern void gameTimerStop(void);
extern int mapGetDirIdx(int mapId);
extern void unlockLevel(int mapDir, int mode, int flags);
extern void Music_Trigger(int trackId, int mode);
extern void GameBit_Set(int bit, int value);
extern u8* Obj_GetPlayerObject(void);
extern void fn_80296518(void* obj, int arg, int enable);
extern f32 Vec_xzDistance(void* a, void* b);
extern f32 mathSinf(f32 angle);
extern MapEventInterface** gMapEventInterface;
extern void modelLightStruct_setEnabled(int light, int mode, f32 value);

extern f32 lbl_803E4E38;
extern f32 timeDelta;
extern f32 lbl_803E4E50;
extern f32 lbl_803E4E54;
extern f32 lbl_803E4E58;
extern f32 lbl_803E4E5C;
extern f32 lbl_803E4E60;
extern f32 lbl_803E4E64;
extern f32 lbl_803E4E68;
extern f32 lbl_803E4E6C;
extern f32 lbl_803E4E70;
extern f32 lbl_803E4E74;
extern f32 lbl_803E4E78;
extern f32 lbl_803E4E88;

typedef struct DFlanternShrineState
{
    void* light;
    u8 pad04[0x14 - 0x04];
    s16 orbitA;
    s16 orbitB;
    s16 orbitC;
    u8 pad1a[0x1c - 0x1a];
    u8 flags;
} DFlanternShrineState;

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_free
 * EN v1.0 Address: 0x801C282C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_door2speci_free(void)
{
}

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_render
 * EN v1.0 Address: 0x801C2830
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_door2speci_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v;

    v = visible;
    if (v != 0)
    {
        objRenderFn_8003b8f4(lbl_803E4E38);
    }
}

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_hitDetect
 * EN v1.0 Address: 0x801C2860
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_door2speci_hitDetect(void)
{
}

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_update
 * EN v1.0 Address: 0x801C2864
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_door2speci_update(void)
{
}

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_init
 * EN v1.0 Address: 0x801C2868
 * EN v1.0 Size: 164b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_door2speci_init(int obj, int def)
{
    int state;
    int* texture;

    state = *(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)DFSH_Door2Speci_SeqFn;
    if (GameBit_Get((int)*(short*)(def + 0x22)) != 0)
    {
        *(unsigned char*)(state + 3) = 2;
    }
    else
    {
        *(unsigned char*)(state + 3) = 0;
    }
    texture = objFindTexture(obj, 0, 0);
    if (texture != (int*)0x0)
    {
        if (*(unsigned char*)(state + 3) == 2)
        {
            *texture = 1;
        }
        else
        {
            *texture = 0;
        }
    }
    *(short*)state = 0;
}

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_release
 * EN v1.0 Address: 0x801C290C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_door2speci_release(void)
{
}

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_initialise
 * EN v1.0 Address: 0x801C2910
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_door2speci_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: fn_801C2914
 * EN v1.0 Address: 0x801C2914
 * EN v1.0 Size: 852b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801C2914(int obj);

/*
 * --INFO--
 *
 * Function: dfsh_shrine_SeqFn
 * EN v1.0 Address: 0x801C2C68
 * EN v1.0 Size: 348b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct LanternFlagBits
{
    u8 on : 1;
    u8 rest : 7;
} LanternFlagBits;

int dfsh_shrine_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

/*
 * --INFO--
 *
 * Function: dfsh_shrine_getExtraSize
 * EN v1.0 Address: 0x801C2DC4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfsh_shrine_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: dfsh_shrine_getObjectTypeId
 * EN v1.0 Address: 0x801C2DCC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfsh_shrine_getObjectTypeId(void);

/*
 * --INFO--
 *
 * Function: dfsh_shrine_free
 * EN v1.0 Address: 0x801C2DD4
 * EN v1.0 Size: 148b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfsh_shrine_free(int obj);
