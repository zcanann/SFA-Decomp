/*
 * dimsnowball1c2 (DLL 0x1C2) — timed snowball spawner for Dinosaur Island
 * Mission.  On each timer expiry, if loading is not locked and the player
 * is clear, allocates a rolling-snowball object (kind 36, id 406) seeded
 * from the placement params and resets the spawn countdown.
 */
#include "main/dll/dimicewallstate_struct.h"
#include "main/frame_timing.h"
#include "main/dll/player_api.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#define OBJECT_RENDER_LEGACY_DIRECT_CALL
#include "main/object_render_legacy.h"
#undef OBJECT_RENDER_LEGACY_DIRECT_CALL
#include "main/object.h"
#include "main/object_api.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#define DIMSNOWBALL1C2_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DIMSNOWBALL1C2_OBJFLAG_HIDDEN 0x4000

/* child object id periodically spawned in dimsnowball1c2_update (role un-pinnable per gate) */
#define DIMSNOWBALL1C2_CHILD_OBJ 406

typedef struct Dimsnowball1c2State
{
    s8 countdown;
    u8 pad1[0x2 - 0x1];
    s16 spawnPeriod;
    u8 pad4[0x8 - 0x4];
} Dimsnowball1c2State;

typedef struct Dimsnowball1c2Placement
{
    u8 pad0[0x4 - 0x0];
    u8 colorR; /* 0x4 -> spawn setup head.unk04[0] */
    u8 colorG; /* 0x5 -> spawn setup head.unk04[1] */
    u8 colorB; /* 0x6 -> spawn setup head.unk04[2] */
    u8 colorA; /* 0x7 -> spawn setup head.unk04[3] */
    u8 pad8[0x14 - 0x8];
    s32 mapId;
    s16 initialCountdown; /* init: copied to extra (DimicewallState.unk2 + word 0) */
    u8 childRot; /* copied to spawned child placement 0x1A (rotation) */
    u8 childZOffset; /* base for spawned child placement 0x1C (+random) */
    s8 rotByte; /* 0x1C rotation byte; also -> child placement 0x18 */
    u8 pad1D[0x1E - 0x1D];
    s16 unk1E;
} Dimsnowball1c2Placement;

/* Spawn-setup buffer for the DIMSNOWBALL1C2 child (Obj_AllocObjectSetup(0x24)):
 * ObjPlacement head (color/pos/mapId) + class-specific rotation fields at
 * 0x18/0x1A/0x1C, sourced from the parent placement's rotByte/childRot/childZOffset. */
typedef struct Dimsnowball1c2Setup
{
    ObjPlacement head; /* 0x00 */
    s8 rotByte;        /* 0x18 <- def->rotByte */
    u8 pad19[0x1A - 0x19];
    s16 childRot;      /* 0x1A <- def->childRot */
    s16 childZOffset;  /* 0x1C <- def->childZOffset + random */
} Dimsnowball1c2Setup;


int dimsnowball1c2_getExtraSize(void)
{
    return 4;
}

int dimsnowball1c2_getObjectTypeId(void) { return 0x0; }

void dimsnowball1c2_free(void)
{
}

void dimsnowball1c2_render(GameObject *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, 1.0f);
}

void dimsnowball1c2_hitDetect(void)
{
}

void dimsnowball1c2_update(int* obj)
{
    if (Obj_IsLoadingLocked())
    {
        int* extra = ((GameObject*)obj)->extra;
        if ((*(s16*)extra -= framesThisStep) <= 0)
        {
    if (playerGetFocusObject(Obj_GetPlayerObject()) == NULL)
            {
                ObjPlacement* np;
                Dimsnowball1c2Placement* def;
                def = *(Dimsnowball1c2Placement**)&((GameObject*)obj)->anim.placementData;
                np = (ObjPlacement*)Obj_AllocObjectSetup(36, DIMSNOWBALL1C2_CHILD_OBJ);
                np->color[0] = def->colorR;
                np->color[2] = def->colorB;
                np->color[1] = def->colorG;
                np->color[3] = def->colorA;
                np->posX = ((GameObject*)obj)->anim.localPosX;
                np->posY = ((GameObject*)obj)->anim.localPosY;
                np->posZ = ((GameObject*)obj)->anim.localPosZ;
                np->mapId = def->mapId;
                {
                    int t1c = def->rotByte;
                    ((Dimsnowball1c2Setup*)np)->rotByte = t1c;
                }
                ((Dimsnowball1c2Setup*)np)->childRot = def->childRot;
                ((Dimsnowball1c2Setup*)np)->childZOffset =
                    (f32)(u32)def->childZOffset +
                    (f32)(int)randomGetRange(0, 100) / 100.0f;
                Obj_SetupObject(np, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
                *(s16*)extra = ((Dimsnowball1c2State*)extra)->spawnPeriod;
            }
        }
    }
}

void dimsnowball1c2_init(GameObject *obj, u8* p)
{
    Dimsnowball1c2Placement* def = (Dimsnowball1c2Placement*)p;
    char* inner;
    (obj)->anim.rotX = (s16)((u32)p[0x1c] << 8);
    inner = (obj)->extra;
    ((DimicewallState*)inner)->unk2 = def->initialCountdown;
    *(s16*)inner = def->initialCountdown;
    (obj)->objectFlags |= (DIMSNOWBALL1C2_OBJFLAG_HIDDEN | DIMSNOWBALL1C2_OBJFLAG_HITDETECT_DISABLED);
}

void dimsnowball1c2_release(void)
{
}

void dimsnowball1c2_initialise(void)
{
}

ObjectDescriptor gDIMSnowBall1C2ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dimsnowball1c2_initialise,
    (ObjectDescriptorCallback)dimsnowball1c2_release,
    0,
    (ObjectDescriptorCallback)dimsnowball1c2_init,
    (ObjectDescriptorCallback)dimsnowball1c2_update,
    (ObjectDescriptorCallback)dimsnowball1c2_hitDetect,
    (ObjectDescriptorCallback)dimsnowball1c2_render,
    (ObjectDescriptorCallback)dimsnowball1c2_free,
    (ObjectDescriptorCallback)dimsnowball1c2_getObjectTypeId,
    dimsnowball1c2_getExtraSize,
};

#pragma force_active on
/* .sdata2 constant pool */
const f32 lbl_803E4878[2] = {1.0f, 0.0f};
const f32 lbl_803E4880 = 5e+01f;
const f32 lbl_803E4884 = 0.0f;
const f32 lbl_803E4888 = 0.1f;
const f32 lbl_803E488C = 0.0f;
const f32 lbl_803E4890 = 176.0f;
const f32 lbl_803E4894 = -0.0f;
const f32 lbl_803E4898 = 1.0f;
const f32 lbl_803E489C = 0.0f;
const f32 lbl_803E48A0 = 5e+01f;
const f32 lbl_803E48A4 = 0.01f;
const f32 lbl_803E48A8 = 0.5f;
const f32 lbl_803E48AC = 2.0f;
const f32 gDimWoodDoorPi = 3.1415927f;
const f32 gDimWoodDoorAngleHalfCircle = 32768.0f;
const f32 lbl_803E48B8 = 0.0f;
const f32 lbl_803E48BC = 0.0f;
const f32 lbl_803E48C0 = 176.0f;
const f32 lbl_803E48C4 = -0.0f;
const f32 lbl_803E48C8 = 1e+01f;
const f32 lbl_803E48CC = 8.0f;
const f32 lbl_803E48D0 = 4.0f;
const f32 lbl_803E48D4 = -1.0f;
const f32 lbl_803E48D8 = 8e+01f;
const f32 lbl_803E48DC = 0.0f;
const f32 lbl_803E48E0 = 176.0f;
const f32 lbl_803E48E4 = 0.0f;
const f32 lbl_803E48E8 = 1.0f;
const f32 lbl_803E48EC = 1e+02f;
const f32 gDimCannonAnimAdvanceSpeed = 0.025f;
const f32 lbl_803E48F4 = 0.0f;
const f32 lbl_803E48F8 = 1.0f;
const f32 lbl_803E48FC = 0.0f;
const f32 lbl_803E4900 = 1.0f;
const f32 lbl_803E4904 = 0.0f;
const f32 lbl_803E4908 = 0.0f;
const f32 lbl_803E490C = 1.0f;
const f32 lbl_803E4910 = 5e+02f;
const f32 lbl_803E4914 = 3.1415927f;
const f32 lbl_803E4918 = 32768.0f;
const f32 lbl_803E491C = 0.0f;
const f32 lbl_803E4920 = 176.0f;
const f32 lbl_803E4924 = -0.0f;
const u32 lbl_803E4928 = 0xFFFFFFFF;
const f32 lbl_803E492C = 1.0f;
const f32 lbl_803E4930 = 15.0f;
const f32 lbl_803E4934 = 1e+01f;
const f32 lbl_803E4938 = 255.0f;
const f32 lbl_803E493C = 25.0f;
const f32 lbl_803E4940 = 8.0f;
const f32 lbl_803E4944 = 0.0f;
const f32 lbl_803E4948 = 176.0f;
const f32 lbl_803E494C = -0.0f;
const f32 lbl_803E4950 = 7.5f;
const f32 lbl_803E4954 = 2.5f;
const f32 lbl_803E4958 = 3.0f;
const f32 lbl_803E495C = 0.09f;
const f32 lbl_803E4960 = 0.0f;
const f32 lbl_803E4964 = 0.0f;
const f32 lbl_803E4968 = 2.1427498f;
const f32 lbl_803E496C = -6.6188688e+22f;
const f32 lbl_803E4970 = 32768.0f;
const f32 lbl_803E4974 = 0.00390625f;
const f32 lbl_803E4978 = 2.3927f;
const f32 lbl_803E497C = 4.5681372e-11f;
const f32 lbl_803E4980 = 7.5f;
const f32 lbl_803E4984 = 0.0f;
const f32 lbl_803E4988 = -1.0f;
const f32 lbl_803E498C = 0.0f;
const f64 lbl_803E4990 = 4503599627370496.0;
const f32 lbl_803E4998 = 0.2f;
const f32 lbl_803E499C = 0.5f;
const f32 lbl_803E49A0 = 0.95f;
const f32 lbl_803E49A4 = 0.1f;
const f32 lbl_803E49A8 = 1e+02f;
const f32 lbl_803E49AC = 0.4f;
const f32 lbl_803E49B0 = 5.0f;
const f32 lbl_803E49B4 = 2e+01f;
const f32 lbl_803E49B8 = 6.0f;
const f32 lbl_803E49BC = 2.0f;
const f32 lbl_803E49C0 = 0.01f;
const f32 lbl_803E49C4 = 65535.0f;
const f32 lbl_803E49C8 = 16384.0f;
const f32 lbl_803E49CC = 1.5f;
const f32 lbl_803E49D0 = 1.0f;
const f32 lbl_803E49D4 = 0.0f;
const f32 lbl_803E49D8 = 0.95f;
const f32 lbl_803E49DC = 0.9f;
const f32 lbl_803E49E0 = 0.025f;
const f32 lbl_803E49E4 = -4.0f;
const f32 lbl_803E49E8 = 1.0f;
const f32 lbl_803E49EC = 82.0f;
const f32 lbl_803E49F0 = -0.1f;
const f32 lbl_803E49F4 = -5.0f;
const f32 lbl_803E49F8 = 0.1f;
const f32 lbl_803E49FC = 8.0f;
