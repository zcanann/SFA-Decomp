/*
 * Tricky companion behaviour states (part of the tricky DLL, 0x00C4).
 *
 * Each function here is one entry of Tricky's per-frame substate machine,
 * dispatched off state[0xa] (the substate index) either directly or through
 * the function-pointer table walked in trickyFn_80142524
 * (((TrickyFnRow*)(base + state[0xa]*4))->fn). They drive Tricky along ROM
 * curve paths (rom_curve_interface), follow/feed the player, run the dig
 * and flame-breath sequences, pick random idle moves and emit the matching
 * object sounds (audio/sfx). trickyFoodFn_8014460c handles the shared
 * feeding/Y-button-item interaction and is called as a guard at the top of
 * most states. Water-vs-land animation selection (the repeated
 * waterLevel/unk2B0/unk2B4 ladder) chooses swim vs walk anims throughout.
 */
#include "main/dll/tricky_substates.h"
#include "main/audio/sfx.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/sky_interface.h"
#include "main/gameplay_runtime.h"
#include "sfa_light_decls.h"
extern int ObjGroup_FindNearestObject();
extern void ObjLink_AttachChild();
extern void objAudioFn_800393f8(int obj, void* audio, int soundId, int volume, int param5, int param6);
extern int trickyFn_8013b368();
extern void objAnimFn_8013a3f0(int param_1, int param_2, f32 param_3, int param_4);

typedef struct
{
    u8 bit7 : 1;
    u8 bit6 : 1;
    u8 bit5 : 1;
    u8 rest : 5;
} TrickyByteFlags;

extern f32 timeDelta;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23EC;
extern f32 lbl_803E2408;
extern f32 lbl_803E2438;
extern f32 lbl_803E2440;
extern f32 lbl_803E2444;
extern f32 lbl_803E2478;
extern f32 lbl_803E2518;
extern f32 lbl_803E251C;
extern f32 lbl_803E2524;
extern u16 getYButtonItem(s16* out);
extern void buttonDisable(int port, u32 mask);
extern char sInWaterMessage[];
extern char lbl_8031D478[];
extern u8 lbl_8031D2E8[];
extern f32 lbl_803E2488;
extern f32 lbl_803E2510;
extern f32 lbl_803E2424;
extern f32 lbl_803E2410;
extern f32 lbl_803E2414;
extern f32 lbl_803E243C;
extern void* Objfsa_FindNearestCurveType24(void* pos, int a, int b);
extern int Objfsa_GetWalkGroupIndexAtPoint(void* pos, int a);
extern void trickyUpdateApproachSpeed(u8* obj, f32 vel, u8* state, u8* pos, int flag);
extern int trickyMove(u8 * obj, u8 * pos);
extern int getAngle(float y, float x);
extern void trickyTurnTowardYaw(u8* obj, s16 yaw);
extern f32 Vec_xzDistance(void* a, void* b);
extern u32 gTrickySubstateSfxIdPairB;
extern void* Objfsa_FindNearestEnabledCurveType24(void* pos, int a, int b);
extern f32 getXZDistance(f32* a, f32* b);
extern float sqrtf(float x);
extern u32 gTrickySubstateSfxIdPairA;
extern f32 lbl_803E2418;
extern f32 lbl_803E2514;
extern f32 lbl_803E24F8;
void fn_80144B50(u8* obj, u8* state);
extern void objPosFn_80039510(int obj, int flags, float* out);
extern f32 lbl_803E24C8;
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern u8* Obj_SetupObject(u8* e, int a, int b, int c, void* d);
extern void objSetAnimSpeedTo1(u8 * e);
extern f32 lbl_803E24AC;
extern f32 lbl_803E23E4;
extern u32 lbl_802C21DC[];
extern f32 lbl_803E23F0;
extern f32 lbl_803E249C;
extern f32 lbl_803E2520;
extern f32 lbl_803E23F8;

extern float mathSinf(float x);
extern float mathCosf(float x);
extern f64 lbl_803E2528;
extern f32 lbl_803E2454;
extern f32 lbl_803E2458;
extern f32 lbl_803E2484;
extern f32 lbl_803E2530;
extern f32 lbl_803E2534;
extern f32 lbl_803E24A8;
extern f32 lbl_803E24EC;

void trickyDigTunnel(u8* obj, u8* state)
{
    u32 sfxTable;
    u8* base;
    u8* pc;
    u8* pos;
    u8* ptr;
    int gidx;
    int k;
    int off;
    int idx;
    int v;
    int inWater;
    u16 id;
    f32 vz, vx, spd, z;

    base = lbl_8031D2E8;
    sfxTable = gTrickySubstateSfxIdPairB;
    switch (state[0xa])
    {
    case 0:
        pc = Objfsa_FindNearestCurveType24(((TrickyState*)state)->unk28, -1, 2);
        ((TrickyState*)state)->unk708 = (u8*)(*gRomCurveInterface)->getById(*(int*)(pc + 0x1c));
        ((TrickyState*)state)->unk700 = pc;
        ((TrickyState*)state)->unk704 = (u8*)(*gRomCurveInterface)->getById(*(int*)(pc + 0x20));
        if (*(u8*)(((TrickyState*)state)->unk704 + 3) != 0)
        {
            *(u32*)&((TrickyState*)state)->unk704 = *(u32*)&((TrickyState*)state)->unk704 ^ *(u32*)&((TrickyState*)
                state)->unk708;
            *(u32*)&((TrickyState*)state)->unk708 = *(u32*)&((TrickyState*)state)->unk708 ^ *(u32*)&((TrickyState*)
                state)->unk704;
            *(u32*)&((TrickyState*)state)->unk704 = *(u32*)&((TrickyState*)state)->unk704 ^ *(u32*)&((TrickyState*)
                state)->unk708;
        }
        ptr = ((TrickyState*)state)->unk708 + 8;
        if (((TrickyState*)state)->unk28 != ptr)
        {
            ((TrickyState*)state)->unk28 = ptr;
            ((TrickyState*)state)->stateFlags &= ~0x400LL;
            ((TrickyState*)state)->unkD2 = 0;
        }
        state[0xa] = 1;
    case 1:
        trickyDebugPrint((char*)(base + 0x7b8));
        trickyFn_8013b368((int)obj, lbl_803E2488, state);
        gidx = Objfsa_GetWalkGroupIndexAtPoint(obj + 0x18, 0);
        if (*(u8*)(((TrickyState*)state)->unk708 + 3) == gidx)
        {
            state[0x9] = 1;
            state[0xa] = 2;
        }
        break;
    case 2:
        trickyDebugPrint((char*)(base + 0x7cc));
        pos = ((TrickyState*)state)->unk700 + 8;
        trickyUpdateApproachSpeed(obj, lbl_803E2488, state, pos, 1);
        if (trickyMove(obj, pos) == 0)
        {
            ((TrickyState*)state)->stateFlags |= 0x2010;
            state[0xa] = 3;
        }
        else
        {
            if (Objfsa_GetWalkGroupIndexAtPoint(obj + 0x18, 0) == 0)
            {
                ((TrickyState*)state)->stateFlags |= 0x2010;
            }
        }
        break;
    case 3:
        objAnimFn_8013a3f0((int)obj, 0xe, lbl_803E2510, 0x4000000);
        ((TrickyState*)state)->dirX = *(f32*)(((TrickyState*)state)->unk704 + 8) - *(f32*)(((TrickyState*)state)->unk700
            + 8);
        ((TrickyState*)state)->dirZ = *(f32*)(((TrickyState*)state)->unk704 + 0x10) - *(f32*)(((TrickyState*)state)->
            unk700 + 0x10);
        Sfx_AddLoopedObjectSound((u32)obj, 0x13d);
        *(f32*)&((TrickyState*)state)->unk70C = (f32)(int)
        randomGetRange(0x14, 0xb4);
        state[0xa] = 4;
    case 4:
        trickyDebugPrint((char*)(base + 0x7e4));
        *(f32*)&((TrickyState*)state)->unk70C -= timeDelta;
        if (*(f32*)&((TrickyState*)state)->unk70C <= lbl_803E23DC)
        {
            *(f32*)&((TrickyState*)state)->unk70C = (f32)(int)
            randomGetRange(0x14, 0xb4);
            *(f32*)&((TrickyState*)state)->unk70C *= lbl_803E2424;
            ptr = ((GameObject*)obj)->extra;
            if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
                && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)
                && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
            {
                objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x360, 0x500, -1, 0);
            }
        }
        spd = ((f32 (**)(u8*, u8*))(**(u8***)(((TrickyState*)state)->followObj + 0x68)))[8](
            ((TrickyState*)state)->followObj, obj);
        ((GameObject*)obj)->anim.localPosX = ((TrickyState*)state)->dirX * spd + *(f32*)(((TrickyState*)state)->unk700 +
            8);
        ((GameObject*)obj)->anim.localPosZ = ((TrickyState*)state)->dirZ * spd + *(f32*)(((TrickyState*)state)->unk700 +
            0x10);
        vx = *(f32*)(*(u8**)&((GameObject*)obj)->extra + 0x2c);
        vz = *(f32*)(*(u8**)&((GameObject*)obj)->extra + 0x30);
        spd = vz * vz;
        if (vx * vx + spd > lbl_803E23EC)
        {
            trickyTurnTowardYaw(obj, getAngle(-vx, -vz));
        }
        if (((u8 (**)(u8*))(**(u8***)(((TrickyState*)state)->followObj + 0x68)))[9](((TrickyState*)state)->followObj) !=
            0)
        {
            idx = 0;
            off = 0;
            for (k = 4; k != 0; k--)
            {
                v = *(int*)(((TrickyState*)state)->unk704 + off + 0x1c);
                if (v > -1 && v != *(u32*)(((TrickyState*)state)->unk700 + 0x14))
                {
                    ((TrickyState*)state)->unk700 = ((TrickyState*)state)->unk704;
                    ((TrickyState*)state)->unk704 =
                        (u8*)(*gRomCurveInterface)->getById(
                            ((int*)((char*)((TrickyState*)state)->unk704 + 0x1c))[idx]);
                    break;
                }
                off += 4;
                idx++;
            }
            **(u8**)state -= 4;
            Sfx_RemoveLoopedObjectSound((u32)obj, 0x13d);
            state[0xa] = 5;
            id = *(u16*)((char*)&sfxTable + randomGetRange(0, 1) * 2);
            ptr = ((GameObject*)obj)->extra;
            if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
                && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)
                && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
            {
                objAudioFn_800393f8((int)obj, ptr + 0x3a8, id, 0x500, -1, 0);
            }
        }
        break;
    case 5:
        trickyDebugPrint((char*)(base + 0x7f8), Vec_xzDistance(obj + 0x18, ((TrickyState*)state)->unk704 + 8));
        pos = ((TrickyState*)state)->unk704 + 8;
        trickyUpdateApproachSpeed(obj, lbl_803E2488, state, pos, 1);
        if (trickyMove(obj, pos) == 0)
        {
            idx = 0;
            off = idx;
            for (k = 4; k != 0; k--)
            {
                v = *(int*)(((TrickyState*)state)->unk704 + off + 0x1c);
                if (v > -1 && v != *(u32*)(((TrickyState*)state)->unk700 + 0x14))
                {
                    ((TrickyState*)state)->unk700 = ((TrickyState*)state)->unk704;
                    ((TrickyState*)state)->unk704 =
                        (u8*)(*gRomCurveInterface)->getById(
                            ((int*)((char*)((TrickyState*)state)->unk704 + 0x1c))[idx]);
                    break;
                }
                off += 4;
                idx++;
            }
            state[0xa] = 6;
        }
        break;
    case 6:
        trickyDebugPrint((char*)(base + 0x810));
        pos = ((TrickyState*)state)->unk704 + 8;
        trickyUpdateApproachSpeed(obj, lbl_803E2488, state, pos, 1);
        if (trickyMove(obj, pos) == 0)
        {
            if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
            {
                inWater = 0;
            }
            else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
            {
                inWater = 1;
            }
            else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
            {
                inWater = 1;
            }
            else
            {
                inWater = 0;
            }
            if (inWater != 0)
            {
                objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                ((TrickyState*)state)->unk79C = lbl_803E2440;
                ((TrickyState*)state)->unk838 = lbl_803E23DC;
                trickyDebugPrint((char*)(base + 0x184));
            }
            else
            {
                objAnimFn_8013a3f0((int)obj, 0, lbl_803E2444, 0);
                trickyDebugPrint((char*)(base + 0x190));
            }
            ((TrickyState*)state)->stateFlags &= ~0x2010;
            state[0xa] = 7;
        }
        break;
    case 7:
        trickyDebugPrint((char*)(base + 0x824));
        gidx = Objfsa_GetWalkGroupIndexAtPoint(*(u8**)&((TrickyState*)state)->playerObj + 0x18, 0);
        if (Objfsa_GetWalkGroupIndexAtPoint(obj + 0x18, 0) == gidx)
        {
            state[0x8] = 1;
            state[0xa] = 0;
            z = lbl_803E23DC;
            ((TrickyState*)state)->unk71C = z;
            ((TrickyState*)state)->unk720 = z;
            ((TrickyState*)state)->stateFlags &= ~0x10LL;
            ((TrickyState*)state)->stateFlags &= ~0x10000LL;
            ((TrickyState*)state)->stateFlags &= ~0x20000LL;
            ((TrickyState*)state)->stateFlags &= ~0x40000LL;
            ((TrickyState*)state)->unkD = -1;
        }
        break;
    }
}

void trickyFn_80141fec(u8* obj, u8* state)
{
    u32 sfxTable;
    u8* ptr;
    u8* pc;
    int ret;
    f32 spd;
    f32 d;
    f32 z;
    u16 id;

    sfxTable = gTrickySubstateSfxIdPairA;
    pc = ((TrickyState*)state)->followObj;
    switch (state[0xa])
    {
    case 0:
        ((TrickyState*)state)->unk70C = Objfsa_FindNearestEnabledCurveType24(
            ((TrickyState*)state)->followObj + 0x18, -1, 2);
        if (((TrickyState*)state)->unk70C != NULL
            && getXZDistance((float*)(((TrickyState*)state)->followObj + 0x18),
                             (float*)(((TrickyState*)state)->unk70C + 8)) > lbl_803E2514)
        {
            ((TrickyState*)state)->unk70C = NULL;
        }
        state[0xa] = 1;
    case 1:
        ret = trickyFn_8013b368((int)obj, lbl_803E2488, state);
        if (ret == 0)
        {
            if (((TrickyState*)state)->unk70C != NULL)
            {
                state[0xa] = 2;
                ptr = ((TrickyState*)state)->unk70C + 8;
                if (((TrickyState*)state)->unk28 != ptr)
                {
                    ((TrickyState*)state)->unk28 = ptr;
                    *(s32*)&((TrickyState*)state)->stateFlags &= ~(u64)0x400;
                    ((TrickyState*)state)->unkD2 = 0;
                }
            }
            else
            {
                ((TrickyState*)state)->stateFlags |= 0x10;
                state[0xa] = 3;
                *(f32*)&((TrickyState*)state)->unk700 = lbl_803E23DC;
                ((TrickyState*)state)->unk710 = (f32)(int)
                randomGetRange(0x28, 0x50);
                Sfx_AddLoopedObjectSound((u32)obj, 0x13d);
                objAnimFn_8013a3f0((int)obj, 0xe, lbl_803E2510, 0x4000000);
            }
        }
        else if (ret == 2)
        {
            state[0x8] = 1;
            state[0xa] = 0;
            z = lbl_803E23DC;
            ((TrickyState*)state)->unk71C = z;
            ((TrickyState*)state)->unk720 = z;
            ((TrickyState*)state)->stateFlags &= ~0x10LL;
            ((TrickyState*)state)->stateFlags &= ~0x10000LL;
            ((TrickyState*)state)->stateFlags &= ~0x20000LL;
            ((TrickyState*)state)->stateFlags &= ~0x40000LL;
            ((TrickyState*)state)->unkD = -1;
        }
        break;
    case 2:
        if (trickyFn_8013b368((int)obj, lbl_803E2418, state) == 0)
        {
            ((TrickyState*)state)->stateFlags |= 0x10;
            state[0xa] = 3;
            *(f32*)&((TrickyState*)state)->unk700 = lbl_803E23DC;
            Sfx_AddLoopedObjectSound((u32)obj, 0x13d);
            objAnimFn_8013a3f0((int)obj, 0xe, lbl_803E2510, 0x4000000);
        }
        break;
    case 3:
        *(f32*)&((TrickyState*)state)->unk700 += timeDelta;
        ((TrickyState*)state)->unk710 -= timeDelta;
        if (*(f32*)&((TrickyState*)state)->unk700 >= lbl_803E24F8)
        {
            state[0xa] = 4;
            *(f32*)&((TrickyState*)state)->unk704 = ((GameObject*)obj)->anim.worldPosX;
            *(f32*)&((TrickyState*)state)->unk708 = ((GameObject*)obj)->anim.worldPosZ;
            ptr = ((TrickyState*)state)->unk70C;
            if (ptr != NULL)
            {
                pc = ((TrickyState*)state)->followObj;
                ((TrickyState*)state)->dirX = *(f32*)(ptr + 8) - *(f32*)(pc + 0x18);
                ((TrickyState*)state)->dirZ = ((TrickyState*)ptr)->prevSpeed - *(f32*)(pc + 0x20);
                d = sqrtf(
                    ((TrickyState*)state)->dirX * ((TrickyState*)state)->dirX + ((TrickyState*)state)->dirZ * ((
                        TrickyState*)state)->dirZ);
                if (lbl_803E23DC != d)
                {
                    ((TrickyState*)state)->dirX = ((TrickyState*)state)->dirX / d;
                    ((TrickyState*)state)->dirZ = ((TrickyState*)state)->dirZ / d;
                }
            }
        }
        break;
    case 4:
        ((TrickyState*)state)->unk710 -= timeDelta;
        if (((TrickyState*)state)->unk710 <= lbl_803E23DC)
        {
            ((TrickyState*)state)->unk710 = (f32)(int)
            randomGetRange(0x28, 0x50);
            ((TrickyState*)state)->unk710 *= lbl_803E2424;
            ptr = ((GameObject*)obj)->extra;
            if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
                && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)
                && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
            {
                objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x360, 0x500, -1, 0);
            }
        }
        spd = ((f32 (**)(u8*, u8*))(**(u8***)(pc + 0x68)))[8](pc, obj);
        ((GameObject*)obj)->anim.localPosX = *(f32*)&((TrickyState*)state)->unk704 - ((TrickyState*)state)->dirX * spd;
        ((GameObject*)obj)->anim.localPosZ = *(f32*)&((TrickyState*)state)->unk708 - ((TrickyState*)state)->dirZ * spd;
        if (((u8 (**)(u8*))(**(u8***)(pc + 0x68)))[9](pc) != 0)
        {
            Sfx_RemoveLoopedObjectSound((u32)obj, 0x13d);
            **(u8**)state -= 4;
            state[0x8] = 1;
            state[0xa] = 0;
            z = lbl_803E23DC;
            ((TrickyState*)state)->unk71C = z;
            ((TrickyState*)state)->unk720 = z;
            ((TrickyState*)state)->stateFlags &= ~0x10LL;
            ((TrickyState*)state)->stateFlags &= ~0x10000LL;
            ((TrickyState*)state)->stateFlags &= ~0x20000LL;
            ((TrickyState*)state)->stateFlags &= ~0x40000LL;
            ((TrickyState*)state)->unkD = -1;
            id = *(u16*)((char*)&sfxTable + randomGetRange(0, 1) * 2);
            ptr = ((GameObject*)obj)->extra;
            if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
                && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)
                && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
            {
                objAudioFn_800393f8((int)obj, ptr + 0x3a8, id, 0x500, -1, 0);
            }
        }
        break;
    }
}

typedef struct TrickyFnRow
{
    u8 pad[0x6c];
    int (*fn)(u8*, u8*);
} TrickyFnRow;

typedef struct
{
    u8 bf7 : 1;
    u8 bf6 : 1;
    u8 bf5 : 1;
    u8 rest : 5;
} FlagByte728;

void trickyFn_80142524(u8* obj, u8* state)
{
    u8* base;
    u8* found;
    u8* other;
    u8* target;
    u8* ptr;
    int inWater;
    f32 z;

    base = lbl_8031D2E8;
    found = NULL;
    if ((((TrickyState*)state)->stateFlags & 0x10) == 0)
    {
        if (state[0x7d0] != 0)
        {
            switch ((int)state[0x7d0])
            {
            case 1:
            {
                target = ((TrickyState*)state)->unk7D4;
                other = ((GameObject*)obj)->extra;
                if ((((GameObject*)obj)->objectFlags & 0x1000) == 0)
                {
                    if ((((TrickyState*)other)->stateFlags & 0x10) == 0)
                    {
                        ((TrickyState*)other)->followObj = target;
                        if (((TrickyState*)other)->unk28 != target + 0x18)
                        {
                            ((TrickyState*)other)->unk28 = target + 0x18;
                            *(s32*)&((TrickyState*)other)->stateFlags &= ~0x400LL;
                            ((TrickyState*)other)->unkD2 = 0;
                        }
                        other[0xa] = 0;
                        other[0x8] = 10;
                    }
                    else
                    {
                        other[0x7d0] = 1;
                        ((TrickyState*)other)->unk7D4 = target;
                        ((TrickyState*)other)->stateFlags |= 0x10000LL;
                    }
                }
                if (trickyFoodFn_8014460c((int)obj, (int*)state) == 0
                    && trickyFn_8013b368((int)obj, lbl_803E2488, state) == 0)
                {
                    ((TrickyState*)state)->unk740 -= timeDelta;
                    if (((TrickyState*)state)->unk740 <= lbl_803E23DC)
                    {
                        ((TrickyState*)state)->unk740 = (f32)(int)
                        randomGetRange(500, 0x2ee);
                        ptr = ((GameObject*)obj)->extra;
                        if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
                            && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove <
                                0x29)
                            && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
                        {
                            objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x360, 0x500, -1, 0);
                        }
                    }
                    if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                    {
                        inWater = 0;
                    }
                    else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
                    {
                        inWater = 1;
                    }
                    else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
                    {
                        inWater = 1;
                    }
                    else
                    {
                        inWater = 0;
                    }
                    if (inWater != 0)
                    {
                        objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                        ((TrickyState*)state)->unk79C = lbl_803E2440;
                        ((TrickyState*)state)->unk838 = lbl_803E23DC;
                        trickyDebugPrint((char*)(base + 0x184));
                    }
                    else
                    {
                        switch (((GameObject*)obj)->anim.currentMove)
                        {
                        case 0xd:
                            if (((TrickyState*)state)->stateFlags & 0x8000000)
                            {
                                objAnimFn_8013a3f0((int)obj, 0x31, lbl_803E243C, 0);
                            }
                            break;
                        default:
                            objAnimFn_8013a3f0((int)obj, 0xd, lbl_803E2444, 0);
                        case 0x31:
                            break;
                        }
                        trickyDebugPrint((char*)(base + 0x190));
                    }
                }
            }
                break;
            default:
                break;
            }
            state[0x7d0] = 0;
            return;
        }
        found = Tricky_findNearestGroup4BObject(obj, (TrickyState*)state);
    }
    if (found != NULL)
    {
        state[0x374] = 2;
        (*gPathControlInterface)->attachObject(obj, &((TrickyState*)state)->pathControlFlags);
        state[8] = 1;
        state[0xa] = 0;
        z = lbl_803E23DC;
        ((TrickyState*)state)->unk71C = z;
        ((TrickyState*)state)->unk720 = z;
        ((TrickyState*)state)->stateFlags &= ~0x10LL;
        ((TrickyState*)state)->stateFlags &= ~0x10000LL;
        ((TrickyState*)state)->stateFlags &= ~0x20000LL;
        ((TrickyState*)state)->stateFlags &= ~0x40000LL;
        ((TrickyState*)state)->unkD = -1;
        ((GameObject*)obj)->anim.localPosX = *(f32*)(found + 0xc);
        ((GameObject*)obj)->anim.localPosY = *(f32*)(found + 0x10);
        ((GameObject*)obj)->anim.localPosZ = *(f32*)(found + 0x14);
        ((GameObject*)obj)->anim.worldPosX = *(f32*)(found + 0x18);
        ((GameObject*)obj)->anim.worldPosY = *(f32*)(found + 0x1c);
        ((GameObject*)obj)->anim.worldPosZ = *(f32*)(found + 0x20);
        ObjHits_SyncObjectPosition((int)obj);
        ((GameObject*)obj)->anim.rotX = *(s16*)found;
        state[9] = 0;
        z = lbl_803E23DC;
        ((TrickyState*)state)->prevSpeed = z;
        ((TrickyState*)state)->speed = z;
        ((TrickyState*)state)->homePosX = *(f32*)(found + 0x18);
        ((TrickyState*)state)->homePosY = *(f32*)(found + 0x1c);
        ((TrickyState*)state)->homePosZ = *(f32*)(found + 0x20);
        ((TrickyState*)state)->stateFlags |= 0x80000LL;
        ((TrickyState*)state)->stateFlags &= ~0x2000LL;
    }
    else
    {
        ((TrickyState*)state)->unk71C -= timeDelta;
        if (((TrickyState*)state)->unk71C < *(f32*)&lbl_803E23DC)
        {
            ((TrickyState*)state)->unk71C = lbl_803E23DC;
        }
        fn_80144B50(obj, state);
        ptr = base + 0x6c;
        if ((*(int (**)(u8*, u8*))(ptr + state[0xa] * 4))(obj, state) == 0)
        {
            if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
            {
                inWater = 0;
            }
            else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
            {
                inWater = 1;
            }
            else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
            {
                inWater = 1;
            }
            else
            {
                inWater = 0;
            }
            if (inWater != 0)
            {
                objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                ((TrickyState*)state)->unk79C = lbl_803E2440;
                ((TrickyState*)state)->unk838 = lbl_803E23DC;
            }
            else
            {
                objAnimFn_8013a3f0((int)obj, 0x25, lbl_803E2518, 0);
            }
        }
    }
}

int trickyFn_80142a14(int obj, int state)
{
    int tex;
    short move;
    u16 sfxId;
    float pos[3];

    objPosFn_80039510(*(int*)&((TrickyState*)state)->followObj, 0, pos);
    if (getXZDistance(pos, (float*)(state + 0x72c)) > lbl_803E2424)
    {
        ((TrickyState*)state)->unk72C = pos[0];
        *(float*)&((TrickyState*)state)->unk730 = pos[1];
        ((TrickyState*)state)->unk734 = pos[2];
    }
    if ((((u32)((TrickyState*)state)->unk728 >> 5) & 1) != 0)
    {
        if (Sfx_IsPlayingFromObjectChannel(obj, 16) != 0)
        {
            return 0;
        }
        tricky_startRandomIdleMove(obj, state);
    }
    else if ((u8)trickyFn_8013b368((int)obj, lbl_803E24C8, state) != 1)
    {
        ((FlagByte728*)(state + 0x728))->bf5 = 1;
        sfxId = randomGetRange(862, 863);
        tex = *(int*)&((GameObject*)obj)->extra;
        if ((((u32)*(u8*)(tex + 0x58) >> 6) & 1) == 0)
        {
            move = ((GameObject*)obj)->anim.currentMove;
            if (move >= 48 || move < 41)
            {
                if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0)
                {
                    objAudioFn_800393f8(obj, (void*)(tex + 0x3a8), sfxId, 1280, -1, 0);
                }
            }
        }
        return 0;
    }
    return 1;
}

int trickyFlameFn_80142b6c(u8* obj, u8* state)
{
    int i;
    int j;
    u8* ptr;
    u8* p;
    u8* q;
    u8* e;

    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0x1a:
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E24AC && (((TrickyState*)state)->stateFlags & 0x800)
            == 0)
        {
            if (Obj_IsLoadingLocked() != 0)
            {
                ((TrickyState*)state)->stateFlags |= 0x800;
                for (i = 0, p = state; i < 7; p += 4, i++)
                {
                    e = Obj_AllocObjectSetup(0x24, 0x4f0);
                    e[4] = 2;
                    e[5] = 1;
                    *(s16*)(e + 0x1a) = i;
                    *(u8**)(p + 0x700) = Obj_SetupObject(e, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                                         ((GameObject*)obj)->anim.parent);
                }
                Sfx_PlayFromObject((int)obj, 0x3db);
                Sfx_AddLoopedObjectSound((u32)obj, 0x3dc);
            }
        }
        else
        {
            if (((TrickyState*)state)->stateFlags & 0x8000000)
            {
                ((TrickyState*)state)->stateFlags &= ~0x800LL;
                ((TrickyState*)state)->stateFlags |= 0x1000;
                for (j = 0, q = state; j < 7; q += 4, j++)
                {
                    objSetAnimSpeedTo1(*(u8**)(q + 0x700));
                }
                Sfx_RemoveLoopedObjectSound((u32)obj, 0x3dc);
                ptr = ((GameObject*)obj)->extra;
                if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
                    && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)
                    && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
                {
                    objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x29d, 0, -1, 0);
                }
                state[0xa] = 10;
            }
        }
        break;
    default:
        objAnimFn_8013a3f0((int)obj, 0x1a, lbl_803E23E4, 0);
    }
    return 1;
}

int trickyFoodFn_80142d2c(int obj, int state)
{
    int tex;
    int result;
    short move;
    struct Buf5
    {
        u32 a[5];
    } buf;

    buf = *(struct Buf5*)lbl_802C21DC;
    if (trickyFoodFn_8014460c(obj, (int*)state) != 0)
    {
        ((TrickyState*)state)->unk720 = lbl_803E23DC;
        result = *(u32*)&((TrickyState*)state)->stateFlags;
        *(u32*)&((TrickyState*)state)->stateFlags = result & ~0x10LL;
        ((TrickyState*)state)->substate = 0;
        return 1;
    }
    result = (*gGameUIInterface)->isOneOfItemsBeingUsed((s32*)&buf, 5);
    if (result != 2)
    {
        if (result < 2)
        {
            if (result >= 0) goto dobody;
            goto skip;
        }
        else if (result >= 6)
        {
            goto skip;
        }
    dobody:;
        tex = *(int*)&((GameObject*)obj)->extra;
        if (((*(u8*)(tex + 0x58) >> 6) & 1) == 0u)
        {
            move = ((GameObject*)obj)->anim.currentMove;
            if (move >= 48 || move < 41)
            {
                if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0)
                {
                    objAudioFn_800393f8(obj, (void*)(tex + 0x3a8), 861, 1280, -1, 0);
                }
            }
        }
    }
skip:
    if (lbl_803E23DC == ((TrickyState*)state)->unk720)
    {
        result = *(u32*)&((TrickyState*)state)->stateFlags;
        *(u32*)&((TrickyState*)state)->stateFlags = result & ~0x10LL;
        ((TrickyState*)state)->substate = 0;
    }
    if ((u8)trickyFn_8013b368(obj, lbl_803E2408, state) == 1)
    {
        return 1;
    }
    return 0;
}

int trickyFn_80142eb0(int obj, int state)
{
    short move;
    int b;
    struct
    {
        u8 head[8];
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } spawnBuf;

    if (trickyFoodFn_8014460c(obj, (int*)state) != 0)
    {
        return 1;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_PROMPT_SUPPRESSED;
    move = ((GameObject*)obj)->anim.currentMove;
    switch (move)
    {
    case 44:
    case 45:
        if ((*(u32*)&((TrickyState*)state)->stateFlags & 0x8000000) != 0)
        {
            objAnimFn_8013a3f0(obj, 46, lbl_803E249C, 0);
        }
        break;
    case 46:
    {
        if (((*(u32*)&((TrickyState*)state)->stateFlags & 0x8000000) != 0) &&
            (((*(u32*)&((TrickyState*)state)->stateFlags & 0x10000) != 0 || randomGetRange(0, 2) == 0) ||
                ((TrickyState*)state)->unk720 > lbl_803E23DC))
        {
            objAnimFn_8013a3f0(obj, 47, lbl_803E23EC, 0);
        }
        spawnBuf.x = ((GameObject*)obj)->anim.worldPosX;
        spawnBuf.y = ((GameObject*)obj)->anim.worldPosY;
        spawnBuf.z = ((GameObject*)obj)->anim.worldPosZ;
        spawnBuf.scale = lbl_803E23F0;
        (*gPartfxInterface)->spawnObject((void*)obj, 2022, &spawnBuf, 0x200001, -1, NULL);
        break;
    }
    case 47:
        if ((*(u32*)&((TrickyState*)state)->stateFlags & 0x8000000) != 0)
        {
            if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
            {
                b = 0;
            }
            else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
            {
                b = 1;
            }
            else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
            {
                b = 1;
            }
            else
            {
                b = 0;
            }
            if (b != 0)
            {
                objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                ((TrickyState*)state)->unk79C = lbl_803E2440;
                ((TrickyState*)state)->unk838 = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            }
            else
            {
                objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                trickyDebugPrint(lbl_8031D478);
            }
            *(int*)&((TrickyState*)state)->stateFlags = *(int*)&((TrickyState*)state)->stateFlags & ~0x10LL;
            ((TrickyState*)state)->substate = 0;
        }
        break;
    }
    return 1;
}

int trickyFn_801430e0(u8* obj, u8* state)
{
    u8* ptr;
    int ret;

    if (trickyFoodFn_8014460c((int)obj, (int*)state) != 0)
    {
        return 1;
    }
    if ((u8)trickyFn_8013b368((int)obj, lbl_803E2418, state) != 1)
    {
        if (((TrickyState*)state)->unk7B0 != NULL)
        {
            ptr = ((GameObject*)obj)->extra;
            if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
                && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)
                && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
            {
                objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x357, 0, -1, 0);
            }
            objAnimFn_8013a3f0((int)obj, 0x26, lbl_803E251C, 0);
            state[0xa] = 5;
        }
        else
        {
            ret = randomGetRange(0, 6);
            if (ret >= 5 || ret < 0)
            {
                objAnimFn_801441c0(obj, state);
            }
            else
            {
                tricky_startRandomIdleMove((int)obj, (int)state);
            }
        }
    }
    return 1;
}

u32 trickyFn_80143210(int obj, int* trickyState)
{
    short move;
    int foodResult;

    foodResult = trickyFoodFn_8014460c(obj, trickyState);
    if (foodResult != 0)
    {
        return 1;
    }
    move = ((GameObject*)obj)->anim.currentMove;
    switch (move)
    {
    case 0x23:
        if ((trickyState[0x15] & 0x8000000U) != 0)
        {
            objAnimFn_8013a3f0(obj, 0x24, lbl_803E2478, 0);
        }
        break;
    case 0x24:
        if (((trickyState[0x15] & 0x8000000U) != 0) && ((int)randomGetRange(0, 3) == 0))
        {
            *(u8*)((int)trickyState + 10) = 0;
        }
        break;
    }
    return 1;
}

u32 trickyFn_801432cc(int obj, int* trickyState)
{
    short move;
    int foodResult;

    foodResult = trickyFoodFn_8014460c(obj, trickyState);
    if (foodResult != 0)
    {
        return 1;
    }
    move = ((GameObject*)obj)->anim.currentMove;
    switch (move)
    {
    case 0x21:
        if ((trickyState[0x15] & 0x8000000U) != 0)
        {
            objAnimFn_8013a3f0(obj, 0x22, lbl_803E2478, 0);
        }
        break;
    case 0x22:
        if (((trickyState[0x15] & 0x8000000U) != 0) && ((int)randomGetRange(0, 3) == 0))
        {
            *(u8*)((int)trickyState + 10) = 0;
        }
        break;
    }
    return 1;
}

#pragma optimization_level 2
u32 trickyFn_80143388(int obj, int* trickyState)
{
    int ref;
    int val;

    val = trickyFoodFn_8014460c(obj, trickyState);
    if (val != 0)
    {
        return 1;
    }
    for (val = 0; val < *(char*)((int)trickyState + 0x827); val++)
    {
        if (*(char*)((int)trickyState + val + 0x81f) != '\0') continue;
        ref = *(int*)&((GameObject*)obj)->extra;
        if (((u32)(*(u8*)(ref + 0x58) >> 6 & 1)) != 0U) continue;
        if ((int)((GameObject*)obj)->anim.currentMove >= 0x30 || (int)((GameObject*)obj)->anim.currentMove < 0x29)
        {
            if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0)
            {
                objAudioFn_800393f8(obj, (void*)(ref + 0x3a8), 0x357, 0, 0xffffffff, 0);
            }
        }
    }
    val = trickyFoodFn_8014460c(obj, trickyState);
    if (val != 0)
    {
        return 1;
    }
    if ((trickyState[0x15] & 0x8000000U) != 0)
    {
        if (trickyState[8] == (int)((GameObject*)obj)->anim.currentMove)
        {
            *(u8*)((int)trickyState + 10) = 0;
        }
    }
    return 1;
}
#pragma optimization_level reset

int trickyFn_801434b0(int obj, int* trickyState)
{
    char bval;
    short move;
    float fval;
    int b;
    int val;
    u8 fxBuf[24];
    int ia;
    float fa;
    int ib;

    if (trickyFoodFn_8014460c(obj, trickyState) != 0)
    {
        return 1;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_PROMPT_SUPPRESSED;
    move = ((GameObject*)obj)->anim.currentMove;
    switch (move)
    {
    case 0x29:
        if ((*(u32*)&trickyState[0x15] & 0x8000000) != 0)
        {
            objAnimFn_8013a3f0(obj, 0x2a, lbl_803E2520, 0);
        }
        break;
    case 0x2a:
        *(float*)(trickyState + 0x1cf) = *(float*)(trickyState + 0x1cf) - timeDelta;
        if (*(float*)(trickyState + 0x1cf) <= lbl_803E23DC)
        {
            if (((*(u32*)&trickyState[0x15] & 0x10000) != 0) || (*(float*)(trickyState + 0x1c8) > lbl_803E23DC))
            {
                objAnimFn_8013a3f0(obj, 0x2b, lbl_803E23EC, 0);
            }
            else
            {
                val = (*gSkyInterface)->getSunPosition(0);
                if (val == 0)
                {
                    objAnimFn_8013a3f0(obj, 0x2c, lbl_803E251C, 0);
                    *(u8*)((int)trickyState + 10) = 9;
                }
            }
        }
        for (val = 0; val < *(char*)((int)trickyState + 0x827); val++)
        {
            bval = *(char*)((int)trickyState + (b = val + 0x81f));
            if (bval == '\0')
            {
                objAudioFn_800393f8(obj, (void*)(trickyState + 0xea), 0x390, 0x500, -1, 0);
            }
            else if (bval == '\a')
            {
                objAudioFn_800393f8(obj, (void*)(trickyState + 0xea), 0x391, 0x100, -1, 0);
            }
        }
        fval = *(float*)(trickyState + 0x1d1) - timeDelta;
        *(float*)(trickyState + 0x1d1) = fval;
        if (fval <= lbl_803E23DC)
        {
            if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
            {
                *(f32*)&fxBuf[12] = *(f32*)(trickyState + 0x102);
                *(f32*)&fxBuf[16] = lbl_803E23F8 + *(float*)(trickyState + 0x103);
                *(f32*)&fxBuf[20] = *(f32*)(trickyState + 0x104);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7f0, fxBuf, 0x200001, -1,
                                                 NULL);
            }
            *(float*)(trickyState + 0x1d1) = lbl_803E24C8;
        }
        break;
    case 0x2b:
        if ((*(u32*)&trickyState[0x15] & 0x8000000) != 0)
        {
            if (lbl_803E23DC == *(float*)(trickyState + 0xab))
            {
                b = 0;
            }
            else if (lbl_803E2410 == *(float*)(trickyState + 0xac))
            {
                b = 1;
            }
            else if (*(float*)(trickyState + 0xad) - *(float*)(trickyState + 0xac) > lbl_803E2414)
            {
                b = 1;
            }
            else
            {
                b = 0;
            }
            if (b != 0)
            {
                objAnimFn_8013a3f0(obj, 8, lbl_803E243C, 0);
                *(float*)(trickyState + 0x1e7) = lbl_803E2440;
                *(float*)(trickyState + 0x20e) = lbl_803E23DC;
                trickyDebugPrint(sInWaterMessage);
            }
            else
            {
                objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
                trickyDebugPrint(lbl_8031D478);
            }
            trickyState[0x15] = trickyState[0x15] & ~0x10LL;
            *(u8*)((int)trickyState + 10) = 0;
        }
        break;
    }
    return 1;
}

typedef struct TrickyPackedSlots
{
    u8 a : 2;
    u8 b : 2;
    u8 c : 2;
    u8 d : 2;
} TrickyPackedSlots;

int trickyFoodFn_801437d4(u8* obj, u8* state)
{
    s8 slots[4];
    u8* ptr;
    u8* e;
    int idx;
    f32 z;

    if (trickyFoodFn_8014460c((int)obj, (int*)state) != 0)
    {
        state[0xa] = 0;
        return 1;
    }
    if (cMenuGetSelectedItem() == 0xc1)
    {
        state[0xa] = 0;
        return 1;
    }
    ((TrickyState*)state)->unk738 -= timeDelta;
    if (((TrickyState*)state)->unk738 < lbl_803E23DC)
    {
        ptr = ((GameObject*)obj)->extra;
        if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
            && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)
            && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
        {
            objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x29a, 0x100, -1, 0);
        }
        ((TrickyState*)state)->unk738 = lbl_803E2440;
    }
    if (((TrickyState*)state)->child == NULL && Obj_IsLoadingLocked() != 0)
    {
        e = Obj_AllocObjectSetup(0x20, 0x17b);
        slots[0] = -1;
        slots[1] = -1;
        slots[2] = -1;
        if (((TrickyState*)state)->unk7A8 != NULL)
        {
            slots[((TrickyPackedSlots*)(state + 0x7bc))->a] = 1;
        }
        if (((TrickyState*)state)->unk7B0 != NULL)
        {
            slots[((TrickyPackedSlots*)(state + 0x7bc))->b] = 1;
        }
        if (((TrickyState*)state)->child != NULL)
        {
            slots[((TrickyPackedSlots*)(state + 0x7bc))->c] = 1;
        }
        if (slots[0] == -1)
        {
            idx = 0;
        }
        else if (slots[1] == -1)
        {
            idx = 1;
        }
        else if (slots[2] == -1)
        {
            idx = 2;
        }
        else if (slots[3] == -1)
        {
            idx = 3;
        }
        else
        {
            idx = -1;
        }
        ((TrickyPackedSlots*)(state + 0x7bc))->c = idx;
        ((TrickyState*)state)->child = Obj_SetupObject(e, 4, -1, -1, ((GameObject*)obj)->anim.parent);
        ObjLink_AttachChild(obj, ((TrickyState*)state)->child, ((TrickyPackedSlots*)(state + 0x7bc))->c);
        z = lbl_803E23DC;
        ((TrickyState*)state)->unk7C0 = z;
        ((TrickyState*)state)->unk7C4 = z;
        ((TrickyState*)state)->unk7C8 = z;
    }
    if ((*gSkyInterface)->getSunPosition(0) != 0
        && ((TrickyState*)state)->unk71C <= lbl_803E23DC
        && GameBit_Get(0xdd) != 0)
    {
        objAnimFn_8013a3f0((int)obj, 0x29, lbl_803E2444, 0);
        ptr = ((GameObject*)obj)->extra;
        if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
            && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)
            && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
        {
            objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x354, 0x1000, -1, 0);
        }
        ((TrickyState*)state)->stateFlags |= 0x10;
        state[0xa] = 4;
        ((TrickyState*)state)->unk73C = (f32)(int)
        randomGetRange(0x78, 0xf0);
    }
    return 1;
}

u32 trickyFn_80143b04(int obj, int* trickyState)
{
    int val;

    val = trickyFoodFn_8014460c(obj, trickyState);
    if (val != 0)
    {
        return 1;
    }
    if ((trickyState[0x15] & 0x8000000U) != 0)
    {
        if (trickyState[8] == (int)((GameObject*)obj)->anim.currentMove)
        {
            *(u8*)((int)trickyState + 10) = 0;
        }
    }
    return 1;
}

u32 trickyFn_80143b78(int obj, int* trickyState)
{
    int val;

    val = trickyFoodFn_8014460c(obj, trickyState);
    if (val != 0)
    {
        return 1;
    }
    val = trickyFn_8013b368(obj, lbl_803E2408, trickyState);
    if (val == 1)
    {
        if (lbl_803E23DC == *(f32*)((int)trickyState + 0x71c))
        {
            *(u8*)((int)trickyState + 10) = 0;
        }
        return 1;
    }
    *(u8*)((int)trickyState + 10) = 0;
    return 0;
}

int trickyFn_80143c04(int obj, int state)
{
    int tex;
    short move;
    u8 result;
    int followBase;
    int inWater;
    float threshold;

    *(int*)&((TrickyState*)state)->followObj = ((TrickyState*)state)->playerObj;
    followBase = *(u32*)&((TrickyState*)state)->followObj + 0x18;
    if (*(u32*)&((TrickyState*)state)->unk28 != followBase)
    {
        *(int*)&((TrickyState*)state)->unk28 = followBase;
        *(s32*)&((TrickyState*)state)->stateFlags &= ~0x400LL;
        *(short*)&((TrickyState*)state)->unkD2 = 0;
    }
    if (lbl_803E23DC == ((TrickyState*)state)->unk71C)
    {
        ((TrickyState*)state)->unkD = -1;
        threshold = lbl_803E24C8;
    }
    else
    {
        if ((*(u32*)&((TrickyState*)state)->stateFlags & 0x20000) != 0)
        {
            ((TrickyState*)state)->unkD = 0;
            *(u32*)&((TrickyState*)state)->stateFlags = *(u32*)&((TrickyState*)state)->stateFlags & ~0x20000LL;
        }
        threshold = lbl_803E2408;
    }
    result = trickyFn_8013b368((int)obj, threshold, state);
    if (result != 1)
    {
        if (result == 2)
        {
            if ((*(u32*)&((TrickyState*)state)->stateFlags & 2) != 0)
            {
                tex = *(int*)&((GameObject*)obj)->extra;
                if (((*(u8*)(tex + 0x58) >> 6) & 1) == 0u)
                {
                    move = ((GameObject*)obj)->anim.currentMove;
                    if (move >= 48 || move < 41)
                    {
                        if (Sfx_IsPlayingFromObjectChannel(obj, 16) == 0)
                        {
                            objAudioFn_800393f8(obj, (void*)(tex + 0x3a8), 861, 1280, -1, 0);
                        }
                    }
                }
            }
        }
        if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
        {
            inWater = 0;
        }
        else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
        {
            inWater = 1;
        }
        else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
        {
            inWater = 1;
        }
        else
        {
            inWater = 0;
        }
        if (inWater != 0)
        {
            return 0;
        }
        return fn_80143DD4(obj, (int*)state);
    }
    ((FlagByte728*)(state + 0x728))->bf7 = 1;
    return 1;
}

u32 fn_80143DD4(int obj, int* trickyState)
{
    int done;
    int extra;
    u32 bitVal;

    done = trickyFoodFn_8014460c(obj, trickyState);
    if (done != 0)
    {
        return 1;
    }
    if (*(f32*)((int)trickyState + 0x79c) > lbl_803E23DC)
    {
        objAnimFn_8013a3f0(obj, 0x1b, lbl_803E23EC, 0);
        *(u8*)((int)trickyState + 10) = 2;
        *(f32*)((int)trickyState + 0x79c) = lbl_803E23DC;
        return 1;
    }
    if ((*(u8*)(trickyState + 0x1ca) >> 7 & 1) != 0U)
    {
        *(f32*)((int)trickyState + 0x724) = lbl_803E2524;
        ((FlagByte728*)((int)trickyState + 0x728))->bf7 = 0;
        ((FlagByte728*)((int)trickyState + 0x728))->bf6 = 1;
    }
    if ((*(u8*)(trickyState + 0x1ca) >> 6 & 1) != 0U)
    {
        *(f32*)((int)trickyState + 0x724) = *(f32*)((int)trickyState + 0x724) - timeDelta;
        if (*(f32*)((int)trickyState + 0x724) <= lbl_803E23DC)
        {
            *(f32*)((int)trickyState + 0x71c) = lbl_803E2438;
            bitVal = randomGetRange(200, 500);
            *(f32*)((int)trickyState + 0x724) =
                (f32)(s32)(bitVal);
            ((FlagByte728*)((int)trickyState + 0x728))->bf6 = 0;
            *(u8*)((int)trickyState + 10) = 1;
        }
        return 0;
    }
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x10))
    {
        return 1;
    }
    done = (*gSkyInterface)->getSunPosition(0);
    if (done == 0)
    {
        *(u32*)&trickyState[0x15] = *(u32*)&trickyState[0x15] & ~0x20000000LL;
    }
    done = (*gSkyInterface)->getSunPosition(0);
    if ((done != 0) && ((trickyState[0x15] & 0x20000000U) == 0))
    {
        *(u32*)&trickyState[0x15] = *(u32*)&trickyState[0x15] | 0x20000000LL;
        done = *(int*)&((GameObject*)obj)->extra;
        if (((*(u8*)(done + 0x58) >> 6 & 1) == 0U) &&
            ((((GameObject*)obj)->anim.currentMove >= 0x30 || (((GameObject*)obj)->anim.currentMove < 0x29)) &&
                !Sfx_IsPlayingFromObjectChannel(obj, 0x10)))
        {
            objAudioFn_800393f8(obj, (void*)(done + 0x3a8), 0x353, 0x500, 0xffffffff, 0);
        }
        return 0;
    }
    if (*(u8*)*trickyState <= 3)
    {
        objAnimFn_8013a3f0(obj, 0x14, lbl_803E2444, 0);
        *(u8*)((int)trickyState + 10) = 3;
        *(f32*)((int)trickyState + 0x738) = lbl_803E2440;
        return 1;
    }
    *(f32*)((int)trickyState + 0x724) = *(f32*)((int)trickyState + 0x724) - timeDelta;
    if (*(f32*)((int)trickyState + 0x724) <= lbl_803E23DC)
    {
        bitVal = randomGetRange(200, 500);
        *(f32*)((int)trickyState + 0x724) =
            (f32)(s32)(bitVal);
        if (*(u8*)*trickyState <= 7)
        {
            objAnimFn_8013a3f0(obj, 0x14, lbl_803E2444, 0);
            *(u8*)((int)trickyState + 10) = 3;
            *(f32*)((int)trickyState + 0x738) = lbl_803E2440;
            return 1;
        }
        if (*(f32*)((int)trickyState + 0x71c) > lbl_803E23DC)
        {
            tricky_startRandomIdleMove(obj, (int)trickyState);
        }
        else
        {
            if ((u32)trickyState[0x1ec] != 0)
            {
                extra = *(int*)&((GameObject*)obj)->extra;
                if ((((*(u8*)(extra + 0x58) >> 6 & 1) == 0U) &&
                    (((GameObject*)obj)->anim.currentMove >= 0x30 || (((GameObject*)obj)->anim.currentMove < 0x29)
                    ) && !Sfx_IsPlayingFromObjectChannel(obj, 0x10)))
                {
                    objAudioFn_800393f8(obj, (void*)(extra + 0x3a8), 0x357, 0, 0xffffffff, 0);
                }
                objAnimFn_8013a3f0(obj, 0x26, lbl_803E251C, 0);
                *(u8*)((int)trickyState + 10) = 5;
            }
            else
            {
                bitVal = randomGetRange(0, 6);
                if (((int)bitVal < 5) && ((int)bitVal >= 0))
                {
                    tricky_startRandomIdleMove(obj, (int)trickyState);
                }
                else
                {
                    objAnimFn_801441c0((u8*)obj, (u8*)trickyState);
                }
            }
        }
        return 1;
    }
    return 0;
}

void objAnimFn_801441c0(u8* obj, u8* state)
{
    f32 arr[2];
    u8* ptr;
    u8 lo;
    u8 hi;
    u8* found;
    int sv;
    f32 ang;

    lo = 1;
    hi = 3;
    arr[0] = lbl_803E2524;
    found = (u8*)ObjGroup_FindNearestObject(0x4d, obj, arr);
    if (found != NULL && (*(u16*)(found + 0xb0) & 0x800) != 0)
    {
        lo = 0;
    }
    if ((*gSkyInterface)->getSunPosition(0) == 0 || GameBit_Get(0xdd) == 0)
    {
        hi = 2;
    }
    switch (randomGetRange(lo, hi))
    {
    case 0:
        ((TrickyState*)state)->followObj = found;
        objPosFn_80039510((int)found, 0, (float*)(state + 0x72c));
        if (((TrickyState*)state)->unk28 != state + 0x72c)
        {
            ((TrickyState*)state)->unk28 = state + 0x72c;
            sv = ((TrickyState*)state)->stateFlags;
            ((TrickyState*)state)->stateFlags = sv & ~0x400LL;
            ((TrickyState*)state)->unkD2 = 0;
        }
        ((FlagByte728*)(state + 0x728))->bf5 = 0;
        state[0xa] = 0xc;
        break;
    case 1:
        sv = randomGetRange(0x20, 0xff);
        sv = (s16)((((GameObject*)obj)->anim.rotX + sv) * 0x100);
        ang = lbl_803E2454 * (f32)sv / lbl_803E2458;
        ((TrickyState*)state)->unk72C = (f32)(lbl_803E2528 * -mathSinf(ang) + ((GameObject*)obj)->anim.localPosX);
        *(f32*)&((TrickyState*)state)->unk730 = ((GameObject*)obj)->anim.localPosY;
        ((TrickyState*)state)->unk734 = (f32)(lbl_803E2484 * -mathCosf(ang) + ((GameObject*)obj)->anim.localPosZ);
        if (((TrickyState*)state)->unk28 != state + 0x72c)
        {
            ((TrickyState*)state)->unk28 = state + 0x72c;
            sv = ((TrickyState*)state)->stateFlags;
            ((TrickyState*)state)->stateFlags = sv & ~0x400LL;
            ((TrickyState*)state)->unkD2 = 0;
        }
        state[0xa] = 8;
        break;
    case 2:
        objAnimFn_8013a3f0((int)obj, 0x2d, lbl_803E2530, 0);
        ((TrickyState*)state)->stateFlags |= 0x10;
        state[0xa] = 9;
        break;
    case 3:
        objAnimFn_8013a3f0((int)obj, 0x29, lbl_803E2444, 0);
        ptr = ((GameObject*)obj)->extra;
        if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
            && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)
            && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
        {
            objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x354, 0x1000, -1, 0);
        }
        ((TrickyState*)state)->stateFlags |= 0x10;
        state[0xa] = 4;
        ((TrickyState*)state)->unk73C = (f32)(int)
        randomGetRange(0x78, 0xf0);
        break;
    }
}

void tricky_startRandomIdleMove(int obj, int trickyState)
{
    int val;
    int state;

    val = randomGetRange(0, 4);
    switch (val)
    {
    case 0:
        objAnimFn_8013a3f0(obj, 0, lbl_803E2444, 0);
        ((TrickyState*)trickyState)->substate = 2;
        break;
    case 1:
        state = *(int*)&((GameObject*)obj)->extra;
        if (((u32)(*(u8*)(state + 0x58) >> 6 & 1)) == 0U)
        {
            if (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)
            {
                if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0)
                {
                    objAudioFn_800393f8(obj, (void*)(state + 0x3a8), 0x357, 0, 0xffffffff, 0);
                }
            }
        }
        objAnimFn_8013a3f0(obj, 0x26, lbl_803E251C, 0);
        ((TrickyState*)trickyState)->substate = 5;
        break;
    case 2:
        objAnimFn_8013a3f0(obj, 0x21, lbl_803E2478, 0);
        ((TrickyState*)trickyState)->substate = 6;
        break;
    case 3:
        objAnimFn_8013a3f0(obj, 0x23, lbl_803E2478, 0);
        ((TrickyState*)trickyState)->substate = 7;
        break;
    case 4:
        objAnimFn_8013a3f0(obj, 0x25, lbl_803E2518, 0);
        ((TrickyState*)trickyState)->substate = 2;
        break;
    }
}

int trickyFoodFn_8014460c(int objArg, int* trickyState)
{
    u8* obj = (u8*)objArg;
    u8* state = (u8*)trickyState;
    u8* b;
    u8 flag;
    u8 a;
    u8 c;
    u8 d;
    u32 n;
    u8 cnt;
    u8 g;
    int inWater;
    s16 item[4];

    flag = 0;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    n = GameBit_Get(0xc1);
    if (n != 0)
    {
        getYButtonItem(item);
        if (item[0] == 0xc1)
        {
            flag = 1;
        }
        if (cMenuGetSelectedItem() == 0xc1)
        {
            flag = 1;
        }
    }
    if (flag != 0)
    {
        if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1)
        {
            if ((*gGameUIInterface)->isEventReady(0xc1) != 0)
            {
                a = **(u8**)state;
                c = *(*(u8**)state + 1);
                if (a == c)
                {
                    b = ((GameObject*)obj)->extra;
                    ((TrickyState*)b)->stateFlags |= 0x4000;
                    ((TrickyState*)b)->stateFlags |= 1;
                    if (lbl_803E23DC == ((TrickyState*)b)->waterLevel)
                    {
                        inWater = 0;
                    }
                    else if (lbl_803E2410 == ((TrickyState*)b)->unk2B0)
                    {
                        inWater = 1;
                    }
                    else if (((TrickyState*)b)->unk2B4 - ((TrickyState*)b)->unk2B0 > lbl_803E2414)
                    {
                        inWater = 1;
                    }
                    else
                    {
                        inWater = 0;
                    }
                    if (inWater != 0)
                    {
                        objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                        ((TrickyState*)b)->unk79C = lbl_803E2440;
                        ((TrickyState*)b)->unk838 = lbl_803E23DC;
                        trickyDebugPrint(sInWaterMessage);
                    }
                    else
                    {
                        objAnimFn_8013a3f0((int)obj, 0, lbl_803E2444, 0);
                        trickyDebugPrint(lbl_8031D478);
                    }
                    (*gObjectTriggerInterface)->runSequence(3, obj, -1);
                    ((TrickyByteFlags*)&((TrickyState*)b)->unk82E)->bit5 = 1;
                }
                else
                {
                    d = c - a;
                    cnt = (u32)d >> 2;
                    if (d % 4)
                    {
                        cnt += 1;
                    }
                    if (cnt > n)
                    {
                        ((TrickyState*)state)->unk82D = a + (n << 2);
                        GameBit_Set(0xc1, 0);
                    }
                    else
                    {
                        ((TrickyState*)state)->unk82D = a + (cnt << 2);
                        GameBit_Set(0xc1, n - cnt);
                    }
                    if (((TrickyState*)state)->unk82D > *(*(u8**)state + 1))
                    {
                        ((TrickyState*)state)->unk82D = *(*(u8**)state + 1);
                    }
                    b = ((GameObject*)obj)->extra;
                    ((TrickyState*)b)->stateFlags |= 0x4000;
                    if (lbl_803E23DC == ((TrickyState*)b)->waterLevel)
                    {
                        inWater = 0;
                    }
                    else if (lbl_803E2410 == ((TrickyState*)b)->unk2B0)
                    {
                        inWater = 1;
                    }
                    else if (((TrickyState*)b)->unk2B4 - ((TrickyState*)b)->unk2B0 > lbl_803E2414)
                    {
                        inWater = 1;
                    }
                    else
                    {
                        inWater = 0;
                    }
                    if (inWater != 0)
                    {
                        objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                        ((TrickyState*)b)->unk79C = lbl_803E2440;
                        ((TrickyState*)b)->unk838 = lbl_803E23DC;
                        trickyDebugPrint(sInWaterMessage);
                    }
                    else
                    {
                        objAnimFn_8013a3f0((int)obj, 0, lbl_803E2444, 0);
                        trickyDebugPrint(lbl_8031D478);
                    }
                    (*gObjectTriggerInterface)->runSequence(2, obj, -1);
                    ((TrickyByteFlags*)&((TrickyState*)b)->unk82E)->bit5 = 1;
                    ((TrickyState*)state)->stateFlags |= 0x40000000LL;
                }
                buttonDisable(0, 0x100);
                return 1;
            }
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 4);
        }
    }
    else
    {
        g = GameBit_Get(0x4e3);
        if (g != 0xff && cMenuGetSelectedItem() == -1)
        {
            if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1)
            {
                GameBit_Set(0x4e3, 0xff);
                b = ((GameObject*)obj)->extra;
                ((TrickyState*)b)->stateFlags |= 0x4000;
                if (g != 2)
                {
                    ((TrickyState*)b)->stateFlags |= 1;
                }
                if (lbl_803E23DC == ((TrickyState*)b)->waterLevel)
                {
                    inWater = 0;
                }
                else if (lbl_803E2410 == ((TrickyState*)b)->unk2B0)
                {
                    inWater = 1;
                }
                else if (((TrickyState*)b)->unk2B4 - ((TrickyState*)b)->unk2B0 > lbl_803E2414)
                {
                    inWater = 1;
                }
                else
                {
                    inWater = 0;
                }
                if (inWater != 0)
                {
                    objAnimFn_8013a3f0((int)obj, 8, lbl_803E243C, 0);
                    ((TrickyState*)b)->unk79C = lbl_803E2440;
                    ((TrickyState*)b)->unk838 = lbl_803E23DC;
                    trickyDebugPrint(sInWaterMessage);
                }
                else
                {
                    objAnimFn_8013a3f0((int)obj, 0, lbl_803E2444, 0);
                    trickyDebugPrint(lbl_8031D478);
                }
                (*gObjectTriggerInterface)->runSequence(g, obj, -1);
                ((TrickyByteFlags*)&((TrickyState*)b)->unk82E)->bit5 = 1;
                buttonDisable(0, 0x100);
                return 1;
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            Obj_SetActiveHitVolumeBounds((GameObject*)obj, 0, 0, 0, 0, 2);
        }
    }
    return 0;
}

void fn_80144B50(u8* obj, u8* state)
{
    int hit[1];
    u8* ptr;
    f32 fv;
    int inWater;

    ((TrickyState*)state)->unk720 -= timeDelta;
    if (((TrickyState*)state)->unk720 < *(f32*)&lbl_803E23DC)
    {
        ((TrickyState*)state)->unk720 = lbl_803E23DC;
    }
    if (ObjHits_GetPriorityHit((int)obj, hit, 0, 0) != 0
        && *(u8**)(hit[0] + 0xc4) != NULL
        && *(s16*)(*(u8**)(hit[0] + 0xc4) + 0x44) == 1)
    {
        fv = ((TrickyState*)state)->unk720;
        if (fv <= lbl_803E23DC)
        {
            ((TrickyState*)state)->unk720 = fv + lbl_803E24EC;
            ptr = ((GameObject*)obj)->extra;
            if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
                && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)
                && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
            {
                objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x34f, 0x500, -1, 0);
            }
        }
        else
        {
            ((TrickyState*)state)->unk720 = fv + lbl_803E2440;
            if (state[0xa] != 0xb)
            {
                if (((TrickyState*)state)->stateFlags & 0x10)
                {
                    if (((TrickyState*)state)->unk720 > lbl_803E2534)
                    {
                        ((TrickyState*)state)->unk720 *= lbl_803E24A8;
                        if (GameBit_Get(0x245) != 0)
                        {
                            if (lbl_803E23DC == ((TrickyState*)state)->waterLevel)
                            {
                                inWater = 0;
                            }
                            else if (lbl_803E2410 == ((TrickyState*)state)->unk2B0)
                            {
                                inWater = 1;
                            }
                            else if (((TrickyState*)state)->unk2B4 - ((TrickyState*)state)->unk2B0 > lbl_803E2414)
                            {
                                inWater = 1;
                            }
                            else
                            {
                                inWater = 0;
                            }
                            if (inWater == 0)
                            {
                                state[0xa] = 0xb;
                                return;
                            }
                        }
                        ptr = ((GameObject*)obj)->extra;
                        if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
                            && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove <
                                0x29)
                            && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
                        {
                            objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x350, 0x500, -1, 0);
                        }
                    }
                    else
                    {
                        ptr = ((GameObject*)obj)->extra;
                        if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
                            && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove <
                                0x29)
                            && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
                        {
                            objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x350, 0x500, -1, 0);
                        }
                    }
                }
                else
                {
                    ptr = ((GameObject*)obj)->extra;
                    if (((u32)((TrickyState*)ptr)->statusFlags >> 6 & 1) == 0
                        && (((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29)
                        && Sfx_IsPlayingFromObjectChannel((int)obj, 0x10) == 0)
                    {
                        objAudioFn_800393f8((int)obj, ptr + 0x3a8, 0x350, 0x500, -1, 0);
                    }
                    state[0xa] = 10;
                    ((TrickyState*)state)->stateFlags |= 0x10;
                }
            }
        }
    }
}
