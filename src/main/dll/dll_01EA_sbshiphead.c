#include "main/obj_placement.h"
#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/dll/DB/DBstealerworm.h"
#include "main/dll/DB/sbgalleon_state.h"

STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(sizeof(SBShipHeadState) == 0x10);

extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 FUN_8003b818();

extern undefined4 DAT_803dc070;
extern EffectInterface** gPartfxInterface;
extern f32 lbl_803DC074;
extern f32 lbl_803E64C8;
extern f32 lbl_803E64CC;
extern f32 lbl_803E64D0;
extern f32 lbl_803E64D4;

extern int ObjList_GetObjects(int* start, int* end);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 timeDelta;

extern int DBprotection_getCameraState(u32 g);
extern void Obj_SetModelColorFadeRecursive(int obj, int a, int b, int c, int d, int e);
extern int Obj_GetPlayerObject(void);
extern u8 framesThisStep;
extern int ObjPath_GetPointWorldPosition(int obj, int idx, f32* x, f32* y, f32* z, int p);

extern u32 getSbGalleon(void);
extern f32 Vec_distance(void* a, void* b);
extern void Sfx_StopObjectChannel(int obj, int ch);
extern u8 Obj_IsLoadingLocked(void);
extern void Obj_GetWorldPosition(int obj, f32* x, f32* y, f32* z);
extern u8* Obj_AllocObjectSetup(int size, int objId);
extern int Obj_SetupObject(u8* setup, int a, int b, int c, int d);
extern u8 lbl_803DC090;
extern int lbl_803DDC48;
extern f32 lbl_803E5834;
extern f32 lbl_803E5840;
extern f32 lbl_803E5844;
extern f32 lbl_803E5848;
extern f32 lbl_803E584C;
extern f32 lbl_803E5850;
extern f32 lbl_803E5854;
extern f32 lbl_803E5858;
extern f32 lbl_803E585C;
extern f32 sqrtf(f32);
extern void ObjMsg_AllocQueue(int obj, int n);
extern f32 lbl_803E5830;
extern f32 lbl_803E5838;
extern f32 lbl_803E5888;

void SB_ShipHead_render(int obj, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    int ref;
    int state;
    byte i;
    u8 fxArgs[6];
    undefined2 sfxId;
    float volume;
    float dx;
    float dy;
    float dz[3];

    if (visible != 0)
    {
        state = *(int*)&((GameObject*)obj)->extra;
        FUN_8003b818(obj);
        ref = *(int*)&((GameObject*)obj)->anim.parent;
        if ((((ref != 0) && (((GameObject*)ref)->anim.seqId == 0x8e)) &&
            (ref = (**(code**)(**(int**)&((GameObject*)ref)->anim.dll + 0x2c))(), ref != 0)) && (ref != 2))
        {
            ((SBShipHeadState*)state)->swayA = ((SBShipHeadState*)state)->swayA - lbl_803DC074;
            if (((SBShipHeadState*)state)->swayA <= lbl_803E64CC)
            {
                ((SBShipHeadState*)state)->swayA = ((SBShipHeadState*)state)->swayA + lbl_803E64D0;
            }
            ((SBShipHeadState*)state)->swayB = ((SBShipHeadState*)state)->swayB - lbl_803DC074;
            if (((SBShipHeadState*)state)->swayB <= lbl_803E64CC)
            {
                ((SBShipHeadState*)state)->swayB = ((SBShipHeadState*)state)->swayB + lbl_803E64C8;
            }
            volume = lbl_803E64D4;
            sfxId = 0xc0a;
            ObjPath_GetPointWorldPosition(obj, 0xd, &dx, &dy, dz, 0);
            dx = dx - ((GameObject*)obj)->anim.worldPosX;
            dy = dy - ((GameObject*)obj)->anim.worldPosY;
            dz[0] = dz[0] - ((GameObject*)obj)->anim.worldPosZ;
            for (i = 0; i < DAT_803dc070; i = i + 1)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7aa, fxArgs, 2, -1, NULL);
            }
        }
    }
    return;
}

void SB_ShipHead_update(int obj)
{
    f32 ddx;
    f32 ddy;
    f32 ddz;
    f32 s;
    int player;
    u8* galleon;
    int state;
    int i;
    int mode;
    SBShipHeadState* hs;
    int proj;
    u8* setup;
    int msg;
    int start;
    int end;
    int hit;
    f32 px;
    f32 py;
    f32 pz;
    int tmp2[2];
    int tmp3;

    mode = 0;
    player = Obj_GetPlayerObject();
    galleon = *(u8**)&((GameObject*)obj)->anim.parent;
    if (galleon != 0)
    {
        state = DBprotection_getCameraState(getSbGalleon());
        if (state == 2)
        {
            if (Vec_distance((void*)(player + 0x18), (void*)&((GameObject*)obj)->anim.worldPosX) < lbl_803E5840)
            {
                Sfx_PlayFromObject(obj, 0x312);
            }
            else
            {
                Sfx_StopObjectChannel(obj, 0x40);
            }
        }
        state = ((GameObject*)galleon)->unkF4;
        hs = ((GameObject*)obj)->extra;
        if (*(void**)&hs->target == 0)
        {
            int* arr = (int*)ObjList_GetObjects(&start, &end);
            for (i = start; i < end; i++)
            {
                int o = arr[i];
                if (*(s16*)(o + 0x46) == 0x8c)
                {
                    hs->target = o;
                    i = end;
                }
            }
        }
        if (ObjMsg_Pop(obj, &msg, tmp2, &tmp3) != 0)
        {
            switch (msg)
            {
            case 0x130002:
                mode = 1;
                break;
            case 0x130003:
                mode = 2;
                break;
            }
        }
        if (((**(int (**)(u8*))(**(int**)&((GameObject*)galleon)->anim.dll + 0x28))(galleon) >= 2)
            && (((GameObject*)obj)->unkF8 <= 0) && (((uint)(state - 3) <= 1 || (state == 5)))
            && (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0)
            && (*(s16*)(hit + 0x46) != 0x114))
        {
            Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
            Sfx_PlayFromObject(obj, 0x37);
            hs->health -= 1;
            if (hs->health <= 0)
            {
                (**(void (**)(u8*))(**(int**)&((GameObject*)galleon)->anim.dll + 0x20))(galleon);
                ((GameObject*)obj)->unkF8 = 300;
                ObjHits_DisableObject(obj);
            }
        }
        if (0 < ((GameObject*)obj)->unkF8)
        {
            ((GameObject*)obj)->unkF8 = ((GameObject*)obj)->unkF8 - framesThisStep;
        }
        if (state == 8)
        {
            ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 + 1;
            if (10 < ((GameObject*)obj)->unkF4)
            {
                ((GameObject*)obj)->unkF4 = 0;
            }
        }
        if ((state == 5) && (lbl_803DDC48 != 5))
        {
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E5834, 0);
            lbl_803DC090 = 0;
        }
        if ((((((GameObject*)obj)->anim.currentMove == 1) && (lbl_803E5844 <= ((GameObject*)obj)->anim.
                currentMoveProgress))
            && (lbl_803DC090 == 0)) && (Obj_IsLoadingLocked() != 0))
        {
            lbl_803DC090 = 1;
            ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 + framesThisStep;
            Sfx_PlayFromObject(obj, 0x38);
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E5848;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ - lbl_803E584C;
            Obj_GetWorldPosition(obj, &px, &py, &pz);
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - lbl_803E5848;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + lbl_803E584C;
            setup = Obj_AllocObjectSetup(0x18, 0x114);
            setup[6] = 0xff;
            setup[7] = 0xff;
            setup[4] = 2;
            setup[5] = 1;
            ((ObjPlacement*)setup)->posX = px;
            ((ObjPlacement*)setup)->posY = py;
            ((ObjPlacement*)setup)->posZ = pz;
            proj = Obj_SetupObject(setup, 5, -1, -1, 0);
            ddx = *(f32*)(player + 0x18) - *(f32*)(proj + 0xc);
            ddy = (*(f32*)(player + 0x1c) - lbl_803E5850) - *(f32*)(proj + 0x10);
            ddz = *(f32*)(player + 0x20) - *(f32*)(proj + 0x14);
            s = lbl_803E5850 / sqrtf(ddz * ddz + (ddx * ddx + ddy * ddy));
            *(f32*)(proj + 0x24) = ddx * s;
            *(f32*)(proj + 0x28) = ddy * s;
            *(f32*)(proj + 0x2c) = ddz * s;
            *(int*)(proj + 0xf4) = 0x78;
            *(int*)(proj + 0xf8) = hs->target;
        }
        if ((mode == 1) && (Obj_IsLoadingLocked() != 0))
        {
            Sfx_PlayFromObject(obj, 0x38);
            player = Obj_GetPlayerObject();
            setup = Obj_AllocObjectSetup(0x18, 0x138);
            ((ObjPlacement*)setup)->posX = lbl_803E5854 + *(f32*)(player + 0x18);
            ((ObjPlacement*)setup)->posY = lbl_803E5848 + (*(f32*)(player + 0x1c) + (f32)(int)
            randomGetRange(-6, 6)
            )
            ;
            ((ObjPlacement*)setup)->posZ = lbl_803E5858 + (*(f32*)(player + 0x20) + (f32)(int)
            randomGetRange(-6, 6)
            )
            ;
            setup[4] = 2;
            setup[5] = 1;
            setup[6] = 0xff;
            setup[7] = 0xff;
            Obj_SetupObject(setup, 5, -1, -1, 0);
        }
        proj = ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E585C, timeDelta, NULL);
        if ((((GameObject*)obj)->anim.currentMove == 1) && (proj != 0))
        {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E5834, 0);
        }
    }
    lbl_803DDC48 = state;
}

void SB_Galleon_release(void);

int SB_ShipHead_getExtraSize(void) { return 0x10; }
int SB_ShipHead_getObjectTypeId(void) { return 0x1; }
int SB_ShipMast_getExtraSize(void);

u32 getSbGalleon(void);

void SB_ShipHead_free(int x) { ObjGroup_RemoveObject(x, 0x3); }

void SB_Propeller_hitDetect(int obj);

void SB_ShipHead_init(int obj)
{
    f32* p = (f32*)((int**)obj)[0xb8 / 4];
    ObjGroup_AddObject(obj, 3);
    ObjMsg_AllocQueue(obj, 10);
    ((SBShipHeadState*)p)->health = 4;
    ((SBShipHeadState*)p)->swayB = ((SBShipHeadState*)p)->swayB + lbl_803E5830;
    ((SBShipHeadState*)p)->swayA = ((SBShipHeadState*)p)->swayA + lbl_803E5838;
}

void SB_ShipGun_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
