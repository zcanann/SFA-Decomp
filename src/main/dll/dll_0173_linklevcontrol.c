/*
 * linklevcontrol (DLL 0x0173) - per-area level-control object for the
 * LinkLevel maps. One instance lives in each map-event area cell; the
 * object's anim.mapEventSlot identifies which cell (0x45..0x49).
 *
 * link_levcontrol_update tracks the player's current map cell (via
 * coordsToMapCell on the player world XZ): on first entry to this
 * object's cell it runs the one-shot enter effects (sky / env-fx /
 * music cues), and while the player stays in the cell it drives the
 * looping area music. The cell's music selection branches on sky sun
 * position and a couple of story game bits, edge-latched through the
 * object's musicTrack field and a SCGameBitLatch record.
 *
 * The object descriptor exported here is gIMIcePillarObjDescriptor; its
 * callbacks (imicepillar_*) live in sibling TUs. The two leading
 * FUN_801ae* functions are drift stubs from neighbouring objects that
 * the linker still resolves by their v1.0 names - left untouched.
 */
#include "main/dll/linklevcontrolstate_struct.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/sky_interface.h"

/* Area cells handled by this controller (GameObject::anim.mapEventSlot). */
enum
{
    AREA_CELL_45 = 0x45,
    AREA_CELL_46 = 0x46,
    AREA_CELL_47 = 0x47,
    AREA_CELL_48 = 0x48,
    AREA_CELL_49 = 0x49
};

extern uint GameBit_Get(int eventId);
extern void Music_Trigger(int track, int flag);
extern void SCGameBitLatch_Update(void* state, int mask, int a, int b, int c, int d);
extern int getSaveGameLoadStatus(void);
extern void* Obj_GetPlayerObject(void);
extern int coordsToMapCell(f32 x, f32 z);
extern void fn_80088870(u8* a, u8* b, u8* c, u8* d);
extern void envFxActFn_800887f8(int id);
extern void getEnvfxAct(int a, int b, int c, int d);
extern u8 lbl_803239F0[];

/* Drift stubs resolved by v1.0 name; bodies recovered from target asm. */
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80057690();
extern undefined8 FUN_80286830();
extern undefined4 FUN_8028687c();

void imicepillar_render(void);
void imicepillar_hitDetect(void);
void imicepillar_update(void);
void imicepillar_init(void);
void imicepillar_release(void);
void imicepillar_initialise(void);
void imicepillar_free(void);
int imicepillar_getExtraSize(void);
int imicepillar_getObjectTypeId(void);

void link_levcontrol_updateAreaMusic(int* obj);
void link_levcontrol_applyEnterAreaEffects(int* obj);

#pragma scheduling on
#pragma peephole on
void FUN_801ae0_dropped_old_imicepillar_render(undefined8 param_1, undefined8 param_2, undefined8 param_3,
                                               undefined8 param_4,
                                               undefined8 param_5, undefined8 param_6, undefined8 param_7,
                                               undefined8 param_8,
                                               int param_9)
{
    if (*(int*)&((GameObject*)param_9)->childObjs[0] != 0)
    {
        FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     *(int*)&((GameObject*)param_9)->childObjs[0]);
    }
}

void FUN_801ae184(undefined4 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4,
                  undefined4 param_5, char param_6)
{
    extern undefined4 FUN_801adca0();
    extern undefined4 ObjPath_GetPointWorldPosition();
    u8 savedByte;
    int active;
    undefined2* obj;
    uint bit;
    int status;
    undefined4 flag;
    undefined2* subObj;
    undefined4* data;
    undefined8 ret;

    ret = FUN_80286830();
    obj = (undefined2*)((ulonglong)ret >> 0x20);
    if (obj[0x23] == 0x373)
    {
        FUN_8003b818((int)obj);
    }
    else
    {
        bit = GameBit_Get(0x6e);
        if ((bit == 0) || (bit = GameBit_Get(0x382), bit != 0))
        {
            data = *(undefined4**)(obj + 0x5c);
            subObj = (undefined2*)*data;
            active = 0;
            if ((subObj != (undefined2*)0x0) &&
                (status = (**(code**)(**(int**)(subObj + 0x34) + 0x38))(subObj), status == 2))
            {
                active = 1;
            }
            if (active)
            {
                obj[3] = obj[3] | 8;
                flag = FUN_80057690((int)subObj);
                param_6 = (char)flag;
                FUN_801adca0(obj, subObj, (int)ret, param_3, param_4, param_5, param_6,
                             (uint) * (byte*)(data + 8), 1);
            }
            else
            {
                obj[3] = obj[3] & ~0x8;
            }
            if ((param_6 != '\0') && (*(char*)(data + 8) != '\0'))
            {
                savedByte = *(u8*)((int)obj + 0x37);
                if (active)
                {
                    *(char*)((int)obj + 0x37) = *(char*)(data + 8);
                }
                FUN_8003b818((int)obj);
                ObjPath_GetPointWorldPosition(obj, 1, (float*)(data + 5), data + 6, (float*)(data + 7), 0);
                *(u8*)((int)obj + 0x37) = savedByte;
            }
        }
    }
    FUN_8028687c();
}

ObjectDescriptor gIMIcePillarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imicepillar_initialise,
    (ObjectDescriptorCallback)imicepillar_release,
    0,
    (ObjectDescriptorCallback)imicepillar_init,
    (ObjectDescriptorCallback)imicepillar_update,
    (ObjectDescriptorCallback)imicepillar_hitDetect,
    (ObjectDescriptorCallback)imicepillar_render,
    (ObjectDescriptorCallback)imicepillar_free,
    (ObjectDescriptorCallback)imicepillar_getObjectTypeId,
    imicepillar_getExtraSize,
};

int link_levcontrol_getExtraSize(void) { return sizeof(LinkLevControlState); }

#pragma scheduling off
#pragma peephole off
void link_levcontrol_free(int obj)
{
    switch ((s32)((GameObject*)obj)->anim.mapEventSlot)
    {
    case AREA_CELL_45: Music_Trigger(0xda, 0);
        break;
    case AREA_CELL_48:
    case AREA_CELL_49: Music_Trigger(0x36, 0);
        break;
    }
}

void link_levcontrol_update(int* obj)
{
    LinkLevControlState* inner = ((GameObject*)obj)->extra;
    f32* player = (f32*)Obj_GetPlayerObject();
    if (player == NULL) return;

    if ((s32)inner->areaCell != (s32)((GameObject*)obj)->anim.mapEventSlot)
    {
        if ((s32)((GameObject*)obj)->anim.mapEventSlot == coordsToMapCell(player[3], player[5]))
        {
            link_levcontrol_applyEnterAreaEffects(obj);
        }
        else
        {
            return;
        }
    }
    if ((s32)((GameObject*)obj)->anim.mapEventSlot == coordsToMapCell(player[3], player[5]))
    {
        link_levcontrol_updateAreaMusic(obj);
    }
    inner->areaCell = (s8)coordsToMapCell(player[3], player[5]);
}

void link_levcontrol_updateAreaMusic(int* obj)
{
    LinkLevControlState* inner = ((GameObject*)obj)->extra;
    switch (((GameObject*)obj)->anim.mapEventSlot)
    {
    case AREA_CELL_47:
        if ((*gSkyInterface)->getSunPosition(0) != 0)
        {
            if (inner->musicTrack != 0x2d)
            {
                inner->musicTrack = 0x2d;
                Music_Trigger(0x2d, 1);
            }
        }
        else
        {
            if (inner->musicTrack != 0x33)
            {
                inner->musicTrack = 0x33;
                Music_Trigger(0x33, 1);
            }
        }
        break;
    case AREA_CELL_48:
        if (GameBit_Get(0xe1e) == 0)
        {
            if (GameBit_Get(0xb72) != 0)
            {
                if (inner->musicTrack != 0x95)
                {
                    inner->musicTrack = 0x95;
                    Music_Trigger(0x95, 1);
                }
            }
            else if ((*gSkyInterface)->getSunPosition(0) != 0)
            {
                if (inner->musicTrack != 0x2d)
                {
                    inner->musicTrack = 0x2d;
                    Music_Trigger(0x2d, 1);
                }
            }
            else
            {
                if (inner->musicTrack != 0x33)
                {
                    inner->musicTrack = 0x33;
                    Music_Trigger(0x33, 1);
                }
            }
        }
        SCGameBitLatch_Update(&inner->latch, 1, -1, -1, 0xe1e, 0x36);
        break;
    }
}

void link_levcontrol_applyEnterAreaEffects(int* obj)
{
    u8* tbl = lbl_803239F0;
    switch (((GameObject*)obj)->anim.mapEventSlot)
    {
    case AREA_CELL_47:
        fn_80088870(tbl + 0x38, tbl, tbl + 0x70, tbl + 0xa8);
        if (((GameObject*)obj)->unkF4 == 2)
        {
            envFxActFn_800887f8(0x3f);
        }
        else
        {
            envFxActFn_800887f8(0x1f);
        }
        Music_Trigger(0xc2, 0);
        Music_Trigger(0xce, 0);
        Music_Trigger(0xcc, 0);
        Music_Trigger(0xdb, 0);
        Music_Trigger(0xf2, 0);
        break;
    case AREA_CELL_45:
        skyFn_80088c94(7, 0);
        envFxActFn_800887f8(0);
        getEnvfxAct(0, 0, 0x13e, 0);
        getEnvfxAct(0, 0, 0x140, 0);
        getEnvfxAct(0, 0, 0x13f, 0);
        Music_Trigger(0xda, 1);
        break;
    case AREA_CELL_49:
        Music_Trigger(0x36, 1);
        break;
    case AREA_CELL_48:
        Music_Trigger(0xc8, 0);
        break;
    case AREA_CELL_46:
        Music_Trigger(0xe1, 0);
        Music_Trigger(0x96, 1);
        break;
    }
}

void link_levcontrol_init(int* obj)
{
    LinkLevControlState* inner = ((GameObject*)obj)->extra;
    inner->areaCell = -1;
    inner->unk04 = -1;
    inner->musicTrack = -1;
    ((GameObject*)obj)->objectFlags |= 0x4000;
    if (getSaveGameLoadStatus() != 0)
    {
        ((GameObject*)obj)->unkF4 = 2;
    }
    else
    {
        ((GameObject*)obj)->unkF4 = 1;
    }
}
