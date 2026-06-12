/* DLL 0x014B - cfmaincrystal. TU: 0x8019D9F0-0x8019E3F4. */
#include "main/dll/cfmaincrystalstate_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/objseq.h"

extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_EnableObject();
extern int ObjMsg_Pop();
extern undefined8 ObjMsg_SendToObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern void objRenderFn_8003b8f4(f32);

extern EffectInterface** gPartfxInterface;

extern uint GameBit_Get(int eventId);
extern void* Obj_GetPlayerObject(void);
extern void fn_8003ADC4(int* a, int* b, void* c, int d, int e, int f);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern u8 framesThisStep;
extern f32 lbl_803E4210;
extern void fn_8019D9F0(int* obj);
extern int* lbl_803DDB10;
extern void getEnvfxAct(int a, int b, int c, int d);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int ch);
extern void Sfx_SetObjectChannelVolume(int obj, int ch, int max, f32 vol);
extern void PSVECNormalize(f32 * out, f32 * in);
extern f32 lbl_803E41D8;
extern f32 lbl_803E41DC;
extern f32 lbl_803E41E0;
extern f32 lbl_803E41E4;
extern f32 lbl_803E41E8;
extern f32 lbl_803E41EC;
extern f32 lbl_803E41F0;
extern f32 lbl_803E41F4;
extern f32 lbl_803E41F8;
extern f32 lbl_803E41FC;
extern f32 lbl_803E4200;
extern f32 lbl_803E4204;
extern void Camera_EnableViewYOffset(void);


void babycloudrunner_init_OLD_v1_1(int obj)
{
    undefined4* state;

    state = ((GameObject*)obj)->extra;
    *state = 0;
    state[1] = 0;
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0x80;
    return;
}


void cfguardian_release(void);

/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */

/* Per-object extra state for the CloudRunner main crystal
 * (cfmaincrystal_getExtraSize == 0x160). */

STATIC_ASSERT(sizeof(CfMainCrystalState) == 0x160);

/* Per-object extra state for the CloudRunner power base
 * (cfpowerbase_getExtraSize == 0x6). */


/* Per-object extra state for the CloudRunner prison guard
 * (cfprisonguard_getExtraSize == 0x3c). */


/* Per-object extra state for the CloudRunner prison uncle
 * (cfprisonuncle_getExtraSize == 0xa8). */


/* Per-object extra state for the robot light beacon
 * (gcrobotlightbea_getExtraSize == 0xc). */


void cfmaincrystal_hitDetect(void)
{
}

void cfmaincrystal_release(void)
{
}

void cfmaincrystal_initialise(void)
{
}

void babycloudrunner_hitDetect(void);

int cfmaincrystal_getExtraSize(void) { return 0x160; }
int cfmaincrystal_getObjectTypeId(void) { return 0x1; }
int babycloudrunner_getExtraSize(void);

#pragma peephole off
void cfmaincrystal_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4210);
}

void cfprisoncage_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#pragma scheduling off
void cfmaincrystal_free(int* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void cfperch_free(int* obj);

void cfmaincrystal_update(int* obj)
{
    uint payload;
    uint msgType;
    uint srcObjId;
    s8 t;
    t = ((s8*)*(int*)&((GameObject*)obj)->anim.placementData)[0x19];
    switch (t)
    {
    case 0:
        fn_8019D9F0(obj);
        break;
    case 1:
        payload = 0;
        while (ObjMsg_Pop(obj, &msgType, &srcObjId, &payload) != 0)
        {
            switch (msgType)
            {
            case 0x110004:
                ObjMsg_SendToObject((void*)srcObjId, 0x110004, obj, 0);
                break;
            }
        }
        lbl_803DDB10 = obj;
        *(s16*)obj = (s16)(*(s16*)obj + (s32)framesThisStep * 0xb6);
        break;
    }
}

void cfmaincrystal_init(int* obj, u8* def)
{
    CfMainCrystalState* state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32) * (s8*)((char*)def + 0x18) << 8);
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

typedef struct
{
    s16 a, b, c, d;
    u8 pad[4];
    f32 x, y, z;
} PartPayload;

/* EN v1.0 0x8019D9F0  size: 2112b  fn_8019D9F0: main crystal beam update -
 * collect the three pylon positions from messages, re-request missing ones,
 * emit the beam particles toward the crystal (and down from each pylon),
 * ramp the convergence charge, hum volume and per-beam chime timers. */
void fn_8019D9F0(int* obj)
{
    char* p16;
    char* p32;
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
    while (ObjMsg_Pop(obj, &msgType, &msgSrc, &payload) != 0)
    {
        switch (msgType)
        {
        case 0x110001:
            sub->pylonX[0] = *(f32*)((char*)msgSrc + 0xc);
            sub->pylonY[0] = lbl_803E41D8;
            sub->pylonZ[0] = *(f32*)((char*)msgSrc + 0x14);
            sub->pylonTimer[0] = 1;
            break;
        case 0x110002:
            sub->pylonX[1] = *(f32*)((char*)msgSrc + 0xc);
            sub->pylonY[1] = lbl_803E41D8;
            sub->pylonZ[1] = *(f32*)((char*)msgSrc + 0x14);
            sub->pylonTimer[1] = 1;
            break;
        case 0x110003:
            sub->pylonX[2] = *(f32*)((char*)msgSrc + 0xc);
            sub->pylonY[2] = lbl_803E41D8;
            sub->pylonZ[2] = *(f32*)((char*)msgSrc + 0x14);
            sub->pylonTimer[2] = 1;
            break;
        case 0x110004:
            sub->crystalX = *(f32*)((char*)msgSrc + 0xc);
            sub->crystalY = *(f32*)((char*)msgSrc + 0x10);
            sub->crystalZ = *(f32*)((char*)msgSrc + 0x14);
            sub->crystalKnown = 1;
            break;
        }
    }
    if (sub->crystalKnown == 0)
    {
        ObjMsg_SendToObjects(0xdc, 5, obj, 0x110004, 0);
    }
    if (GameBit_Get(0x54) != 0 && sub->pylonTimer[0] == 0)
    {
        ObjMsg_SendToObjects(0xda, 4, obj, 0x110001, 0);
    }
    if (GameBit_Get(0x55) != 0 && sub->pylonTimer[1] == 0)
    {
        ObjMsg_SendToObjects(0xda, 4, obj, 0x110002, 0);
    }
    if (GameBit_Get(0x56) != 0 && sub->pylonTimer[2] == 0)
    {
        ObjMsg_SendToObjects(0xda, 4, obj, 0x110003, 0);
    }
    sub->beams[0].b1b = 0;
    sub->beams[1].b1b = 0;
    sub->beams[2].b1b = 0;
    sub->beams[3].b1b = 0;
    sub->beams[4].b1b = 0;
    sub->beams[5].b1b = 0;
    sub->beams[6].b1b = 0;
    sub->beams[7].b1b = 0;
    sub->beams[8].b1b = 0;
    sub->beams[9].b1b = 0;
    count = 0;
    idx = 0;
    if (sub->crystalKnown != 0)
    {
        if (GameBit_Get(0x57) != 0)
        {
            if (sub->pylonTimer[0] != 0)
            {
                sub->pylonTimer[0] = 0x78;
            }
            if (sub->pylonTimer[1] != 0)
            {
                sub->pylonTimer[1] = 0x78;
            }
            if (sub->pylonTimer[2] != 0)
            {
                sub->pylonTimer[2] = 0x78;
            }
            sub->charge = 0x5a;
        }
        i = 0;
        p16 = (char*)sub;
        p32 = (char*)sub;
        do
        {
            if (i <= 2 && *(s16*)(p16 + 0x30) != 0)
            {
                CrystalBeam* sl = &sub->beams[idx++];
                sl->b1b = 1;
                sl->b18 = 0x7f;
                sl->b19 = 0x7f;
                sl->b1a = 0xff;
                sl->f0 = sub->crystalX;
                sl->f8 = lbl_803E41DC + sub->crystalY;
                sl->f10 = sub->crystalZ;
                dir[0] = *(f32*)p32 - sl->f0;
                dir[1] = (lbl_803E41E0 + *(f32*)(p32 + 0x10)) - sl->f8;
                dir[2] = *(f32*)(p32 + 0x20) - sl->f10;
                PSVECNormalize(dir, dir);
                pay.x = *(f32*)p32 - sub->crystalX;
                pay.y = (lbl_803E41E0 + *(f32*)(p32 + 0x10)) - sub->crystalY;
                pay.z = *(f32*)(p32 + 0x20) - sub->crystalZ;
                dir[0] = -dir[0];
                dir[1] = -dir[1];
                dir[2] = -dir[2];
                pay.d = i;
                (*gPartfxInterface)->spawnObject(obj, 0x7f4, &pay, 2, -1, dir);
                dir[0] = *(f32*)p32 - ((GameObject*)lbl_803DDB10)->anim.localPosX;
                dir[1] = lbl_803E41E4;
                dir[2] = *(f32*)(p32 + 0x20) - ((GameObject*)lbl_803DDB10)->anim.localPosZ;
                PSVECNormalize(dir, dir);
                pay.x = lbl_803E41E8;
                pay.y = lbl_803E41DC;
                pay.z = lbl_803E41E8;
                pay.d = i + 3;
                (*gPartfxInterface)->spawnObject(lbl_803DDB10, 0x7f4, &pay, 2, -1, dir);
                pay.x = *(f32*)p32;
                pay.y = *(f32*)(p32 + 0x10);
                pay.z = *(f32*)(p32 + 0x20);
                if (sub->chime[3] > 0x14)
                {
                    pay.x = *(f32*)p32;
                    pay.y = *(f32*)(p32 + 0x10);
                    pay.z = *(f32*)(p32 + 0x20);
                    pay.c = i;
                }
                pay.x = *(f32*)p32;
                pay.y = *(f32*)(p32 + 0x10);
                pay.z = *(f32*)(p32 + 0x20);
                pay.c = i;
                sl = &sub->beams[idx++];
                sl->b1b = 1;
                count++;
            }
            p16 += 2;
            p32 += 4;
            i++;
        }
        while (i < 3);
        if (sub->pylonTimer[0] + sub->pylonTimer[1] + sub->pylonTimer[2] < 0x12c
            && (int)randomGetRange(0, 3) == 0)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x81, NULL, 0, -1, NULL);
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
                Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
                getEnvfxAct(0, 0, 0x7f, 0);
            }
            sub->charge += framesThisStep;
        }
        if (sub->charge >= 0x3c)
        {
            f32 fr = (f32)(sub->charge - 0x3c);
            CrystalBeam* sl;
            fr = fr / lbl_803E41EC;
            sl = &sub->beams[idx];
            sl->b1b = 1;
            sl->b18 = 0;
            sl->b19 = 0;
            sl->b1a = 0;
            sl->f0 = ((GameObject*)obj)->anim.localPosX;
            sl->f8 = lbl_803E41F0 + ((GameObject*)obj)->anim.localPosY;
            sl->f10 = ((GameObject*)obj)->anim.localPosZ;
            sl->f4 = sl->f0;
            sl->fc = -(lbl_803E41F4 * fr - sl->f8);
            sl->f14 = sl->f10;
        }
        *(s16*)obj += framesThisStep * (count * 0x7e);
    }
    if (count != 0)
    {
        if (Sfx_IsPlayingFromObjectChannel((int)obj, 0x40) == 0)
        {
            Sfx_PlayFromObject((int)obj, SFXsk_planteater11);
            sub->humVolume = lbl_803E41F8;
        }
        else
        {
            f32 vol = lbl_803E41FC + (f32)count / lbl_803E4200;
            {
                f32 d = vol - sub->humVolume;
                sub->humVolume = d * lbl_803E4204 + sub->humVolume;
            }
            if (sub->charge >= 0x3c)
            {
                sub->humVolume = vol;
            }
            Sfx_SetObjectChannelVolume((int)obj, 0x40, 0x64, sub->humVolume);
        }
    }
    i = 0;
    do
    {
        s16 v = sub->pylonTimer[i];
        if (v != 0 && v < 0x80)
        {
            sub->pylonTimer[i] += framesThisStep;
            if (v == 1 && sub->pylonTimer[i] > 1)
            {
                Sfx_PlayFromObject((int)obj, SFXsk_toysq2_c);
            }
            if (v < 0x1e && sub->pylonTimer[i] >= 0x1e)
            {
                Sfx_PlayFromObject((int)obj, SFXsk_trbark1);
            }
        }
        i++;
    }
    while (i < 3);
    *(s16*)obj += framesThisStep * 0x2a;
}
