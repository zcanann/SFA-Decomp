/*
 * cfmaincrystal (DLL 0x14B) - the CloudRunner Fortress main crystal.
 * Collects pylon beam reports (0x110001..3 messages) and the crystal
 * position (0x110004), draws up to ten beams between charged pylons
 * and the crystal, charges up once all three pylons are lit and fires
 * the convergence beam. Carved from the sandwormBoss container.
 */

#include "main/dll/partfx_interface.h"
#include "main/render_envfx_api.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/object_render_legacy.h"
#include "main/obj_message.h"
#include "main/camera.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebits.h"
#include "main/dll/CF/dll_014B_cfmaincrystal.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/audio/sfx.h"
#include "main/object_descriptor.h"

#define CFMAINCRYSTAL_PYLON_FRAMES 0x78 /* beam hold time once reported */
#define CFMAINCRYSTAL_CHARGE_START 0x5A /* charge frames granted by 0x57 */
#define CFMAINCRYSTAL_CHARGE_FIRE  0x3C /* charge at which the bolt fires */

/* Spark fx emitted (1-in-3) while the pylons are still partially charged
   (sum of pylonTimer[0..2] < 0x12c). */
#define CFMAINCRYSTAL_PARTFX_CHARGE_SPARK 0x81
/* beam particle spawned along each crystal<->pylon link as the beams[] slot is activated */
#define CFMAINCRYSTAL_PARTFX_BEAM 0x7f4
/* env effect activated once when all three pylons chime and the main charge begins */
#define CFMAINCRYSTAL_ENVFX 0x7f

/* beam-report protocol shared with cfpowerbase (dll_014A): probe each
   pylon group (class 0xDA) with its message; the crystal itself answers
   position probes (class 0xDC) with CFMAINCRYSTAL_MSG_CRYSTAL. */
enum
{
    CFMAINCRYSTAL_MSG_PYLON_1 = 0x110001,
    CFMAINCRYSTAL_MSG_PYLON_2 = 0x110002,
    CFMAINCRYSTAL_MSG_PYLON_3 = 0x110003,
    CFMAINCRYSTAL_MSG_CRYSTAL = 0x110004
};

/* game bits: the three base bits (see cfpowerbase) + 0x57 = the
   convergence cutscene bit that pins everything fully charged - and
   the "power restored" bit that starts the city's wind lifts
   (see cfwindlift) */
enum
{
    GAMEBIT_CFBASE_1 = 0x54,
    GAMEBIT_CFBASE_2 = 0x55,
    GAMEBIT_CFBASE_3 = 0x56,
    GAMEBIT_CF_CONVERGENCE = 0x57
};

typedef struct
{
    s16 a, b, c, d; /* per-effect s16 params; c/d carry the beam index */
    u8 pad[4];
    f32 x, y, z;
} PartPayload;

STATIC_ASSERT(sizeof(CfMainCrystalState) == 0x160);


extern f32 lbl_803E4210;

int* gCfMainCrystalObj;

/* fn_8019D9F0: main crystal beam update -
 * collect the three pylon positions from messages, re-request missing ones,
 * emit the beam particles toward the crystal (and down from each pylon),
 * ramp the convergence charge, hum volume and per-beam chime timers. */
void fn_8019D9F0(int* obj)
{
    int i;
    CfMainCrystalState* sub = ((GameObject*)obj)->extra;
    int idx;
    int count;
    PartPayload pay;
    f32 dir[3];
    int msgSrc;
    int msgType;
    int payload = 0;
    Obj_GetPlayerObject();
    Camera_EnableViewYOffset();
    while (ObjMsg_Pop(obj, (u32*)&msgType, (u32*)&msgSrc, (u32*)&payload) != 0)
    {
        switch (msgType)
        {
        case CFMAINCRYSTAL_MSG_PYLON_1:
            sub->pylonX[0] = ((GameObject*)msgSrc)->anim.localPosX;
            sub->pylonY[0] = 1945.0f;
            sub->pylonZ[0] = ((GameObject*)msgSrc)->anim.localPosZ;
            sub->pylonTimer[0] = 1;
            break;
        case CFMAINCRYSTAL_MSG_PYLON_2:
            sub->pylonX[1] = ((GameObject*)msgSrc)->anim.localPosX;
            sub->pylonY[1] = 1945.0f;
            sub->pylonZ[1] = ((GameObject*)msgSrc)->anim.localPosZ;
            sub->pylonTimer[1] = 1;
            break;
        case CFMAINCRYSTAL_MSG_PYLON_3:
            sub->pylonX[2] = ((GameObject*)msgSrc)->anim.localPosX;
            sub->pylonY[2] = 1945.0f;
            sub->pylonZ[2] = ((GameObject*)msgSrc)->anim.localPosZ;
            sub->pylonTimer[2] = 1;
            break;
        case CFMAINCRYSTAL_MSG_CRYSTAL:
            sub->crystalX = ((GameObject*)msgSrc)->anim.localPosX;
            sub->crystalY = ((GameObject*)msgSrc)->anim.localPosY;
            sub->crystalZ = ((GameObject*)msgSrc)->anim.localPosZ;
            sub->crystalKnown = 1;
            break;
        }
    }
    if (sub->crystalKnown == 0)
    {
        ObjMsg_SendToObjects(0xdc, 5, obj, CFMAINCRYSTAL_MSG_CRYSTAL, 0);
    }
    if (mainGetBit(GAMEBIT_CFBASE_1) != 0 && sub->pylonTimer[0] == 0)
    {
        ObjMsg_SendToObjects(0xda, 4, obj, CFMAINCRYSTAL_MSG_PYLON_1, 0);
    }
    if (mainGetBit(GAMEBIT_CFBASE_2) != 0 && sub->pylonTimer[1] == 0)
    {
        ObjMsg_SendToObjects(0xda, 4, obj, CFMAINCRYSTAL_MSG_PYLON_2, 0);
    }
    if (mainGetBit(GAMEBIT_CFBASE_3) != 0 && sub->pylonTimer[2] == 0)
    {
        ObjMsg_SendToObjects(0xda, 4, obj, CFMAINCRYSTAL_MSG_PYLON_3, 0);
    }
    sub->beams[0].active = 0;
    sub->beams[1].active = 0;
    sub->beams[2].active = 0;
    sub->beams[3].active = 0;
    sub->beams[4].active = 0;
    sub->beams[5].active = 0;
    sub->beams[6].active = 0;
    sub->beams[7].active = 0;
    sub->beams[8].active = 0;
    sub->beams[9].active = 0;
    count = 0;
    idx = 0;
    if (sub->crystalKnown != 0)
    {
        if (mainGetBit(GAMEBIT_CF_CONVERGENCE) != 0)
        {
            if (sub->pylonTimer[0] != 0)
            {
                sub->pylonTimer[0] = CFMAINCRYSTAL_PYLON_FRAMES;
            }
            if (sub->pylonTimer[1] != 0)
            {
                sub->pylonTimer[1] = CFMAINCRYSTAL_PYLON_FRAMES;
            }
            if (sub->pylonTimer[2] != 0)
            {
                sub->pylonTimer[2] = CFMAINCRYSTAL_PYLON_FRAMES;
            }
            sub->charge = CFMAINCRYSTAL_CHARGE_START;
        }
        i = 0;
        do
        {
            if (i <= 2 && sub->pylonTimer[i] != 0)
            {
                CrystalBeam* sl = &sub->beams[idx++];
                sl->active = 1;
                sl->colorR = 0x7f;
                sl->colorG = 0x7f;
                sl->colorB = 0xff;
                sl->startX = sub->crystalX;
                sl->startY = 20.0f + sub->crystalY;
                sl->startZ = sub->crystalZ;
                dir[0] = sub->pylonX[i] - sl->startX;
                dir[1] = (55.0f + sub->pylonY[i]) - sl->startY;
                dir[2] = sub->pylonZ[i] - sl->startZ;
                PSVECNormalize(dir, dir);
                pay.x = sub->pylonX[i] - sub->crystalX;
                pay.y = (55.0f + sub->pylonY[i]) - sub->crystalY;
                pay.z = sub->pylonZ[i] - sub->crystalZ;
                dir[0] = -dir[0];
                dir[1] = -dir[1];
                dir[2] = -dir[2];
                pay.d = i;
                (*gPartfxInterface)->spawnObject(obj, CFMAINCRYSTAL_PARTFX_BEAM, &pay, 2, -1, dir);
                dir[0] = sub->pylonX[i] - ((GameObject*)gCfMainCrystalObj)->anim.localPosX;
                dir[1] = -80.0f;
                dir[2] = sub->pylonZ[i] - ((GameObject*)gCfMainCrystalObj)->anim.localPosZ;
                PSVECNormalize(dir, dir);
                pay.x = 0.0f;
                pay.y = 20.0f;
                pay.z = 0.0f;
                pay.d = i + 3;
                (*gPartfxInterface)->spawnObject(gCfMainCrystalObj, CFMAINCRYSTAL_PARTFX_BEAM, &pay, 2, -1, dir);
                pay.x = sub->pylonX[i];
                pay.y = sub->pylonY[i];
                pay.z = sub->pylonZ[i];
                if (sub->chime[3] > 0x14)
                {
                    pay.x = sub->pylonX[i];
                    pay.y = sub->pylonY[i];
                    pay.z = sub->pylonZ[i];
                    pay.c = i;
                }
                pay.x = sub->pylonX[i];
                pay.y = sub->pylonY[i];
                pay.z = sub->pylonZ[i];
                pay.c = i;
                sl = &sub->beams[idx++];
                sl->active = 1;
                count++;
            }
            i++;
        } while (i < 3);
        if (sub->pylonTimer[0] + sub->pylonTimer[1] + sub->pylonTimer[2] < 0x12c && (int)randomGetRange(0, 3) == 0)
        {
            (*gPartfxInterface)->spawnObject(obj, CFMAINCRYSTAL_PARTFX_CHARGE_SPARK, NULL, 0, -1, NULL);
        }
        if (sub->pylonTimer[0] != 0 || sub->pylonTimer[1] != 0 || sub->pylonTimer[2] != 0)
        {
            if (sub->chime[0] > 0x64)
            {
                sub->chime[0] = 0;
            }
            if (sub->chime[1] > 0x64)
            {
                sub->chime[1] = 0;
            }
            if (sub->chime[2] > 0x64)
            {
                sub->chime[2] = 0;
            }
            if (sub->chime[3] > 0x14)
            {
                sub->chime[3] = 0;
            }
            sub->chime[0] += framesThisStep;
            sub->chime[1] += framesThisStep;
            sub->chime[2] += framesThisStep;
            sub->chime[3] += framesThisStep;
        }
        if (count == 3)
        {
            if (sub->charge == 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
                getEnvfxActInt(0, 0, CFMAINCRYSTAL_ENVFX, 0);
            }
            sub->charge += framesThisStep;
        }
        if (sub->charge >= CFMAINCRYSTAL_CHARGE_FIRE)
        {
            f32 fr = (f32)(sub->charge - CFMAINCRYSTAL_CHARGE_FIRE);
            CrystalBeam* sl;
            fr = fr / 30.0f;
            sl = &sub->beams[idx];
            sl->active = 1;
            sl->colorR = 0;
            sl->colorG = 0;
            sl->colorB = 0;
            sl->startX = ((GameObject*)obj)->anim.localPosX;
            sl->startY = 15.0f + ((GameObject*)obj)->anim.localPosY;
            sl->startZ = ((GameObject*)obj)->anim.localPosZ;
            sl->endX = sl->startX;
            sl->endY = -(250.0f * fr - sl->startY);
            sl->endZ = sl->startZ;
        }
        ((GameObject*)obj)->anim.rotX += framesThisStep * (count * 0x7e);
    }
    if (count != 0)
    {
        if (Sfx_IsPlayingFromObjectChannel((int)obj, 0x40) == 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_d5);
            sub->humVolume = 0.66f;
        }
        else
        {
            f32 vol = 0.33f + count / 3.0f;
            {
                f32 d = vol - sub->humVolume;
                f32 approachRate = 0.0625f;
                sub->humVolume = d * approachRate + sub->humVolume;
            }
            if (sub->charge >= CFMAINCRYSTAL_CHARGE_FIRE)
            {
                sub->humVolume = vol;
            }
            Sfx_SetObjectChannelVolume((int)obj, 0x40, 0x64, sub->humVolume);
        }
    }
    i = 0;
    do
    {
        idx = sub->pylonTimer[i];
        if (idx != 0 && idx < 0x80)
        {
            sub->pylonTimer[i] += framesThisStep;
            if (idx == 1 && sub->pylonTimer[i] > 1)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_en_icecrk16_d6);
            }
            if (idx < 0x1e && sub->pylonTimer[i] >= 0x1e)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_en_lflsh1_c);
            }
        }
        i++;
    } while (i < 3);
    ((GameObject*)obj)->anim.rotX += framesThisStep * 0x2a;
}

int CFMainCrystal_getExtraSize(void)
{
    return 0x160;
}

int CFMainCrystal_getObjectTypeId(void)
{
    return 0x1;
}

void CFMainCrystal_free(int* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void CFMainCrystal_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4210);
}

void CFMainCrystal_hitDetect(void)
{
}

void CFMainCrystal_update(int* obj)
{
    u32 payload;
    u32 msgType;
    u32 srcObjId;
    s8 mode;
    mode = ((s8*)((GameObject*)obj)->anim.placement)[0x19];
    switch (mode)
    {
    case 0:
        fn_8019D9F0(obj);
        break;
    case 1:
        payload = 0;
        while (ObjMsg_Pop(obj, (u32*)&msgType, (u32*)&srcObjId, (u32*)&payload) != 0)
        {
            switch (msgType)
            {
            case CFMAINCRYSTAL_MSG_CRYSTAL:
                ObjMsg_SendToObject((void*)srcObjId, CFMAINCRYSTAL_MSG_CRYSTAL, obj, 0);
                break;
            }
        }
        gCfMainCrystalObj = obj;
        ((GameObject*)obj)->anim.rotX = (s16)(((GameObject*)obj)->anim.rotX + framesThisStep * 0xb6);
        break;
    }
}

void CFMainCrystal_init(int* obj, u8* def)
{
    CfMainCrystalState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32) * (s8*)((char*)def + 0x18) << 8);
    if (*(s8*)((char*)def + 0x19) == 0)
    {
        state->chime[0] = 0x28;
        state->chime[1] = 0;
        state->chime[2] = 0;
        state->chime[3] = 0x46;
        ((ObjAnimComponent*)obj)->bankIndex = 1;
        state->unk158 = 0;
    }
    ObjMsg_AllocQueue(obj, 2);
}

void CFMainCrystal_release(void)
{
}

void CFMainCrystal_initialise(void)
{
}

ObjectDescriptor gCFMainCrystalObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)CFMainCrystal_initialise, (ObjectDescriptorCallback)CFMainCrystal_release, 0,
    (ObjectDescriptorCallback)CFMainCrystal_init, (ObjectDescriptorCallback)CFMainCrystal_update,
    (ObjectDescriptorCallback)CFMainCrystal_hitDetect, (ObjectDescriptorCallback)CFMainCrystal_render,
    (ObjectDescriptorCallback)CFMainCrystal_free, (ObjectDescriptorCallback)CFMainCrystal_getObjectTypeId,
    CFMainCrystal_getExtraSize,
};
