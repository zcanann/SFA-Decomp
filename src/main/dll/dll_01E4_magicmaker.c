#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/DF/rope.h"
#include "main/dll/mmsh_waterspike.h"

typedef struct DimbosscrackparPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
} DimbosscrackparPlacement;


typedef struct MagicmakerPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
} MagicmakerPlacement;


typedef struct DIMbossspitUpdateBurstState
{
    u8 pad0[0x4 - 0x0];
    s32 light;
    u8 pad8[0x3DC - 0x8];
    s32 unk3DC;
    u8 pad3E0[0x400 - 0x3E0];
    u16 unk400;
    u8 pad402[0x40C - 0x402];
    s32 unk40C;
} DIMbossspitUpdateBurstState;


typedef struct Dimbossgut2State
{
    u8 pad0[0x4 - 0x0];
    s32 unk4;
    u8 pad8[0x3DC - 0x8];
    s32 unk3DC;
    u8 pad3E0[0x400 - 0x3E0];
    u16 unk400;
    u8 pad402[0x40C - 0x402];
    s32 unk40C;
    u8 pad410[0x42C - 0x410];
} Dimbossgut2State;


typedef struct DIMbossspitState
{
    s16 unk0;
    s16 unk2;
    s32 light;
    u8 pad8[0x3DC - 0x8];
    s32 unk3DC;
    u8 pad3E0[0x400 - 0x3E0];
    u16 unk400;
    u8 pad402[0x40C - 0x402];
    s32 unk40C;
} DIMbossspitState;


extern void ModelLightStruct_free(void* light);
extern int randomGetRange(int min, int max);
extern void Obj_FreeObject(int obj);
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjMsg_Pop();
extern void objRenderFn_8003b8f4(f32 scale);
extern void queueGlowRender(void* light);

extern undefined4* gBaddieControlInterface;
extern f32 lbl_803E4CF0;
extern f32 lbl_803E4D44;

extern u8 framesThisStep;
extern f32 timeDelta;
extern EffectInterface** gPartfxInterface;
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern void Sfx_PlayFromObject(int obj, int id);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern void doRumble(f32 v);
extern void modelLightStruct_setEnabled(int light, int v, f32 f);
extern f32 lbl_803E4D38;
extern f32 lbl_803E4D3C;
extern f32 lbl_803E4D40;
extern f32 lbl_803E4D48;
extern f32 lbl_803E4D4C;
extern f32 lbl_803E4D50;
extern f32 lbl_803E4D60;
extern f32 lbl_803E4D64;
extern f32 lbl_803E4D68;
extern const f32 lbl_803E4D6C;
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern f32 lbl_803E4CD0;
extern f32 lbl_803E4CD4;
extern f32 lbl_803E4CD8;
extern f32 lbl_803E4CDC;
extern f32 lbl_803E4CE0;
extern f32 lbl_803E4CE4;
extern f32 lbl_803E4CE8;
extern f32 lbl_803E4CEC;
extern f32 lbl_803E4D20;
extern int Curve_AdvanceAlongPath(int a, f32 f);
extern int getAngle(f32 dx, f32 dy);
extern int Obj_GetPlayerObject(void);
extern f32 lbl_803E4D10;
extern f32 lbl_803E4D14;
extern f32 lbl_803E4D18;
extern f32 lbl_803E4D1C;

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
void dimbossgut2_updateTracking(int obj, int state);

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
void dimbossgut2_free(int arg9);

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
void dimbossgut2_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible);

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
void dimbossgut2_update(int obj);

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
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int** out, int a, int b);
extern void lightSetFieldBC_8001db14(int light, int v);
extern void* objCreateLight(int obj, int n);
extern void modelLightStruct_setLightKind(int light, int v);
extern void modelLightStruct_setDiffuseColor(int light, int a, int b, int c, int d);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
extern void modelLightStruct_setupGlow(int light, int a, int b, int c, int d, int e, f32 f);
extern void modelLightStruct_setGlowProjectionRadius(int light, f32 f);
extern f32 lbl_803E4D24;
extern f32 lbl_803E4D28;
extern f32 lbl_803E4D2C;
extern f32 lbl_803E4D30;
extern f32 lbl_803E4D04;

void dimbossgut2_init(int obj, int def, int p3);

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
void DIMbossspit_updateBurst(int obj);

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
void DIMbossspit_free(int param_1);

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
void DIMbossspit_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible);

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
void DIMbossspit_update(int obj);

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
extern void modelLightStruct_setSpecularColor(int light, int a, int b, int c, int d);
extern void lightSetField4D(int light, int v);
extern void modelLightStruct_setAffectsAabbLightSelection(int light, int v);
extern int Obj_GetActiveModel(int obj);
extern void ObjModel_SetPostRenderCallback(int model, void* cb);
extern void postRenderSetAlphaBlendState(void);
extern f32 lbl_803E4D70;
extern f32 lbl_803E4D74;
extern f32 lbl_803E4D78;
extern f32 lbl_803E4D7C;
extern f32 lbl_803E4D80;

void DIMbossspit_init(int obj);


/* Trivial 4b 0-arg blr leaves. */
void dimbossgut2_func11(void);

void dimbossgut2_hitDetect(void);

void dimbossgut2_release(void);

void dimbossgut2_initialise(void);

void DIMbossspit_hitDetect(void);

void DIMbossspit_release(void);

void DIMbossspit_initialise(void);

void magicmaker_free(void)
{
}

void magicmaker_hitDetect(void)
{
}

void magicmaker_init(void)
{
}

void magicmaker_release(void)
{
}

void magicmaker_initialise(void)
{
}

void dimbosscrackpar_hitDetect(void);

void dimbosscrackpar_release(void);

void dimbosscrackpar_initialise(void);

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
extern u8 Obj_IsLoadingLocked(void);
extern void GameBit_Set(int eventId, int value);
extern int* ObjGroup_GetObjects(int group, int* countOut);
extern char* Obj_AllocObjectSetup(int size, int typeId);
extern char* Obj_SetupObject(char* setup, int a, int b, int c, int d);
extern void hitDetectFn_80097070(char* obj, f32 f, int a, int b, int c, int d);
extern u16 lbl_80325CE8[];
extern f32 lbl_803E4D8C;
extern f32 lbl_803E4D88;

void magicmaker_update(int obj)
{
    int def;
    char* newobj;
    int n;
    int count;
    int* objs;
    int i;
    int j;
    char* setup;
    int o;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (Obj_IsLoadingLocked() != 0)
    {
        if ((u32)GameBit_Get(0x26b) != 0u)
        {
            GameBit_Set(0x26b, 0);
            objs = ObjGroup_GetObjects(4, &count);
            n = 0;
            for (i = 0; i < count; i++)
            {
                o = *objs;
                for (j = 0; j < 6; j++)
                {
                    if (*(s16*)(o + 0x46) == lbl_80325CE8[j])
                    {
                        n++;
                    }
                }
                objs++;
            }
            if (n < 10)
            {
                setup = Obj_AllocObjectSetup(0x30, lbl_80325CE8[randomGetRange(0, 5)]);
                if (setup != NULL)
                {
                    *(u8*)(setup + 0x1a) = 0x14;
                    *(s16*)(setup + 0x2c) = -1;
                    *(s16*)(setup + 0x1c) = -1;
                    ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX + (f32)(int)
                    randomGetRange(-0x15e, 0x15e);
                    ((ObjPlacement*)setup)->posY = lbl_803E4D8C + ((GameObject*)obj)->anim.localPosY;
                    ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ + (f32)(int)
                    randomGetRange(-0x15e, 0x15e);
                    *(s16*)(setup + 0x24) = -1;
                    *(u8*)(setup + 0x4) = ((MagicmakerPlacement*)def)->unk4;
                    *(u8*)(setup + 0x6) = ((MagicmakerPlacement*)def)->unk6;
                    *(u8*)(setup + 0x5) = ((MagicmakerPlacement*)def)->unk5;
                    *(u8*)(setup + 0x7) = ((MagicmakerPlacement*)def)->unk7;
                    *(s16*)(setup + 0x2e) = 3;
                    newobj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                             *(int*)&((GameObject*)obj)->anim.parent);
                    if (newobj != NULL)
                    {
                        i = 3;
                        do
                        {
                            hitDetectFn_80097070(newobj, lbl_803E4D88, 2, 2, 0x64, 0);
                            i--;
                        }
                        while (i != 0);
                    }
                }
            }
        }
    }
}

extern f32 lbl_803E4D98;

int dimbosscrackpar_SeqFn(int* obj);

void dimbosscrackpar_update(int* obj);

void dimbosscrackpar_free(int* obj);

void dimbosscrackpar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dimbosscrackpar_init(s16* obj, s8* def);

void dimbossfire_hitDetect(void);

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


/* 8b "li r3, N; blr" returners. */
int dimbossgut2_setScale(void);
int dimbossgut2_getExtraSize(void);
int dimbossgut2_getObjectTypeId(void);
int DIMbossspit_getExtraSize(void);
int DIMbossspit_getObjectTypeId(void);
int magicmaker_getExtraSize(void) { return 0x0; }
int magicmaker_getObjectTypeId(void) { return 0x0; }
int dimbosscrackpar_getExtraSize(void);
int dimbosscrackpar_getObjectTypeId(void);
int dimbossfire_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
void magicmaker_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4D88);
}
