#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "main/objhits_types.h"
#include "main/dll/CF/windlift.h"
#include "main/dll/CF/lanternfirefly_state.h"
#include "main/resource.h"
#include "global.h"

typedef struct PortalspelldoorPlacement {
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
} PortalspelldoorPlacement;


typedef struct LanternFireFlyPlacement {
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 stateId;
    s16 timer;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} LanternFireFlyPlacement;


/* scarab_getExtraSize == 0x34 (collectible money beetle). */
typedef struct ScarabState {
    f32 velX;        /* 0x00 */
    f32 velZ;        /* 0x04 */
    f32 riseAmount;  /* 0x08 */
    f32 baseY;       /* 0x0c: def spawn height */
    s16 despawnTimer;/* 0x10 */
    u8 pad12[2];
    s16 mode;        /* 0x14 */
    s16 yawSpeed;    /* 0x16 */
    s16 spawnYaw;    /* 0x18 */
    s16 fleeTimer;   /* 0x1a */
    s16 riseLimit;   /* 0x1c */
    s16 pickupSfx;   /* 0x1e */
    s16 particleId;  /* 0x20 */
    s16 unk22;       /* 0x22 */
    u8 phase;        /* 0x24 */
    u8 pad25[2];
    u8 moneyKind;    /* 0x27 */
    u8 flags28;      /* 0x28: 1 = collected, waiting on the money message */
    u8 pad29[3];
    s16 msgParamA;   /* 0x2c */
    s16 msgParamB;   /* 0x2e */
    f32 msgParamC;   /* 0x30 */
} ScarabState;
STATIC_ASSERT(sizeof(ScarabState) == 0x34);

/* dll_107_getExtraSize == 0x2c (CF wind lift / blow vent). */
typedef struct WindLift107State {
    int holdTimer;   /* 0x00: countdown while the vent is plugged */
    int holdReload;  /* 0x04 */
    f32 radius;      /* 0x08 */
    s16 yawLow;      /* 0x0c */
    s16 yawHigh;     /* 0x0e */
    s16 ventState;   /* 0x10 */
    s16 maxDist;     /* 0x12 */
    s16 unk14;       /* 0x14 */
    s16 unk16;       /* 0x16 */
    s16 unk18;       /* 0x18 */
    s16 liftTimer;   /* 0x1a */
    u8 pad1C[2];
    s16 spitTimer;   /* 0x1e */
    u8 pad20;
    u8 rideState;    /* 0x21 */
    u8 riding;       /* 0x22 */
    u8 launchPhase;  /* 0x23 */
    u8 pad24;
    u8 unk25;        /* 0x25 */
    u8 glowPulse;    /* 0x26 */
    u8 unk27;        /* 0x27 */
    u8 pad28[4];
} WindLift107State;
STATIC_ASSERT(sizeof(WindLift107State) == 0x2c);

/* portalspelldoor_getExtraSize == 0x10. */
typedef struct PortalSpellDoorState {
    u8 pad00[4];
    f32 openAmount;  /* 0x04 */
    int openTimer;   /* 0x08 */
    u8 flags0C;      /* 0x0c: bit 7 = open (via PortalFlags cast) */
    u8 pad0D[3];
} PortalSpellDoorState;
STATIC_ASSERT(sizeof(PortalSpellDoorState) == 0x10);


extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined8 FUN_800068c0();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80006ba8();
extern uint FUN_80006c00();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId,int value);
extern double FUN_80017708();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_8002f6ac();
extern undefined4 FUN_8002fc3c();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined8 ObjHits_MarkObjectPositionDirty();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 Obj_GetYawDeltaToObject();
extern undefined4 FUN_8003b540();
extern undefined4 FUN_8003b818();
extern int FUN_800575b4();
extern uint FUN_800620e8();
extern int FUN_800632f4();
extern uint FUN_80063a68();
extern undefined4 FUN_80063a74();
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern undefined4 FUN_800810f4();
extern undefined4 FUN_80081118();
extern undefined4 FUN_8013651c();
extern int FUN_80184600();
extern undefined4 FUN_80247eb8();
extern int FUN_80286838();
extern undefined4 FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern uint FUN_80294cc4();
extern undefined4 FUN_80294d28();
extern undefined4 FUN_80294d68();
extern int FUN_80294d6c();

extern undefined4 DAT_802c2a18;
extern undefined4 DAT_802c2a1c;
extern undefined4 DAT_802c2a20;
extern undefined4 DAT_802c2a24;
extern undefined4 DAT_802c2a28;
extern undefined4 DAT_802c2a2c;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dca18;
extern undefined4 DAT_803dca1c;
extern undefined4 DAT_803dca20;
extern char DAT_803dca24;
extern undefined4* DAT_803de750;
extern undefined4* DAT_803de754;
extern undefined4 DAT_803e4688;
extern f64 DOUBLE_803e46e0;
extern f64 DOUBLE_803e46e8;
extern f64 DOUBLE_803e4710;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dca2c;
extern f32 FLOAT_803dca30;
extern f32 FLOAT_803dca34;
extern f32 FLOAT_803dca38;
extern f32 FLOAT_803e468c;
extern f32 FLOAT_803e4690;
extern f32 FLOAT_803e4694;
extern f32 FLOAT_803e4698;
extern f32 FLOAT_803e469c;
extern f32 FLOAT_803e46a0;
extern f32 FLOAT_803e46a4;
extern f32 FLOAT_803e46a8;
extern f32 FLOAT_803e46ac;
extern f32 FLOAT_803e46b0;
extern f32 FLOAT_803e46b4;
extern f32 FLOAT_803e46b8;
extern f32 FLOAT_803e46bc;
extern f32 FLOAT_803e46c0;
extern f32 FLOAT_803e46c4;
extern f32 FLOAT_803e46c8;
extern f32 FLOAT_803e46cc;
extern f32 FLOAT_803e46d0;
extern f32 FLOAT_803e46d4;
extern f32 FLOAT_803e46d8;
extern f32 FLOAT_803e46f0;
extern f32 FLOAT_803e46f4;
extern f32 FLOAT_803e46f8;
extern f32 FLOAT_803e46fc;
extern f32 FLOAT_803e4700;
extern f32 FLOAT_803e4704;
extern f32 FLOAT_803e4708;
extern f32 FLOAT_803e470c;
extern f32 FLOAT_803e4718;

extern f32 timeDelta;
extern u8 framesThisStep;
extern u32 lbl_803E39F0;
extern f32 lbl_803E39F4;
extern f32 lbl_803E39F8;
extern f32 lbl_803E39FC;
extern f32 lbl_803E3A00;
extern f32 lbl_803E3A08;
extern f32 lbl_803E3A0C;
extern f32 lbl_803E3A10;
extern f32 lbl_803E3A14;
extern f32 lbl_803E3A18;
extern f32 lbl_803E3A1C;
extern f32 lbl_803E3A20;
extern f32 lbl_803E3A24;
extern f32 lbl_803E3A28;
extern f32 lbl_803E3A2C;
extern f32 lbl_803E3A30;
extern f32 lbl_803E3A34;
extern f32 lbl_803E3A38;
extern f32 lbl_803E3A3C;
extern f32 lbl_803E3A40;
extern f32 lbl_803DBDD0;
extern f64 lbl_803E3A48;
extern f64 lbl_803E3A50;
extern f32 lbl_803E3AA0;
extern f32 lbl_803E3AA4;
extern f32 lbl_803E3AA8;
extern f64 lbl_803E3AB0;
extern f32 lbl_803E3AB8;
extern f32 lbl_803E3ABC;
extern f32 lbl_803E3AC0;
extern f32 lbl_803E3AC4;
extern f32 lbl_803DBDC4;
extern f32 lbl_803DBDC8;
extern f32 lbl_803DBDCC;
extern u32 lbl_802C2298[3];
extern u32 lbl_802C22A4[3];

extern int Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int obj);
extern void Sfx_KeepAliveLoopedObjectSoundLimited(int obj, int sfx, int limit);
extern f32 sqrtf(f32 x);
extern s16 getAngle(f32 dx, f32 dz);
extern u32 randomGetRange(int min, int max);
extern void objHitDetectFn_80062e84(int obj, int a, int b);
extern void vecRotateZXY(void *rotation, f32 *outVec);
extern int gameBitIncrement(int eventId);
extern f32 Vec_distance(void *a, void *b);
extern void playerAddMoney(int player, u8 b);
extern int objHitboxFn_801843c0(int obj);
extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, void *p5, int obj, int p7, int p8, int p9, int p10);
extern int ViewFrustum_IsSphereVisible(f32 *pos, f32 radius);
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, void *out, int p5, int p6);
extern int hitDetect_calcSweptSphereBounds(void *bounds, void *start, void *end, void *sphere, int n);
extern int hitDetectFn_800691c0(int obj, void *p2, int p3, int p4);
extern int hitDetectFn_80067958(int obj, void *p2, void *p3, int p4, void *p5, int p6);
extern int fn_801845FC(int obj, int p2, int p3, void *p4);
extern f32 FLOAT_803e471c;

/*
 * --INFO--
 *
 * Function: scarab_update
 * EN v1.0 Address: 0x80184930
 * EN v1.0 Size: 292b
 * EN v1.1 Address: 0x80184D4C
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void scarab_update(int obj)
{
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern f32 Vec_xzDistance(f32 *a, f32 *b);
    extern void PSVECSubtract(void *a, void *b, void *out);
    extern void itemPickupDoParticleFx(int obj, f32 scale, int a, int b);
    typedef struct { f32 x, y, z; } ScarabVec3;
    typedef struct { s16 ang; s16 b; s16 c; f32 scale; f32 x; f32 y; f32 z; } ScarabRot;
    typedef struct { f32 vals[4]; s8 a; u8 pad[3]; u8 b; u8 pad2[27]; } ScarabSphere;

    u8 hitResults[84];
    u8 hitBuf[64];
    ScarabSphere sph;
    ScarabRot rot;
    u8 bounds[24];
    ScarabVec3 start;
    ScarabVec3 end;
    f32 vsub[3];
    f32 **list;
    int msg;
    f32 phase;
    u32 money1;
    u32 money2;
    u32 money3;
    int best;
    int flag;
    int player;
    int state;
    char ph;
    s16 mode;
    f32 bestDist;
    f32 dy;
    f32 sumsq;
    u32 ang;
    int diff;
    int count;
    int i;
    f32 **p;
    u8 hits;

    best = 0;
    list = NULL;
    start = *(ScarabVec3 *)lbl_802C2298;
    end = *(ScarabVec3 *)lbl_802C22A4;
    flag = best;
    state = *(int *)&((GameObject *)obj)->extra;
    player = Obj_GetPlayerObject();
    if ((*(u8 *)(state + 0x28) & 1) != 0) {
        while (ObjMsg_Pop(obj, &msg, 0, 0) != 0) {
            switch (msg) {
            case 0x7000b:
                money1 = lbl_803E39F0;
                playerAddMoney(player, *((u8 *)&money1 + *(u8 *)(state + 0x27)));
                *(s16 *)(state + 0x10) = 0x50;
                *(s16 *)(state + 0x14) = 0;
                *(u8 *)(state + 0x28) &= ~1;
                break;
            }
        }
        if ((*(u8 *)(state + 0x28) & 1) != 0) {
            return;
        }
    }
    Sfx_KeepAliveLoopedObjectSoundLimited(obj, 0x406, 3);
    mode = *(s16 *)(state + 0x14);
    if (mode == 0) {
        *(s16 *)(state + 0x10) -= framesThisStep;
        if (*(s16 *)(state + 0x10) <= 0) {
            *(s16 *)(state + 0x10) = 0;
            Obj_FreeObject(obj);
        }
    } else {
        ph = *(s8 *)(state + 0x24);
        if (ph == 0) {
            if (((GameObject *)obj)->anim.hitReactState != NULL) {
                ObjHits_EnableObject(obj);
            }
            ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.velocityX * timeDelta + ((GameObject *)obj)->anim.localPosX;
            ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
            ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.velocityZ * timeDelta + ((GameObject *)obj)->anim.localPosZ;
            if (((GameObject *)obj)->anim.velocityY > lbl_803E3A08) {
                ((GameObject *)obj)->anim.velocityY = lbl_803E3A0C * timeDelta + ((GameObject *)obj)->anim.velocityY;
            }
            ((GameObject *)obj)->anim.rotZ = ((GameObject *)obj)->anim.rotZ + *(s16 *)(state + 0x16) * framesThisStep;
            if (objHitboxFn_801843c0(obj) != 0) {
                flag = 1;
            }
            if (flag == 0) {
                flag = objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E3A00, 0, hitResults, obj, 8, -1, 0, 0);
            }
            if (flag != 0) {
                ((GameObject *)obj)->anim.rotZ = 0;
                *(u8 *)(state + 0x24) = 1;
                *(s16 *)(state + 0x18) = *(s16 *)obj;
                if (((GameObject *)obj)->anim.seqId == 0x3d3) {
                    {
                        f32 k = lbl_803E3A10;
                        *(f32 *)state = k * ((GameObject *)obj)->anim.velocityX;
                        *(f32 *)(state + 4) = k * ((GameObject *)obj)->anim.velocityZ;
                    }
                } else if (((GameObject *)obj)->anim.seqId == 0x3d4) {
                    {
                        f32 k = lbl_803E3A14;
                        *(f32 *)state = k * ((GameObject *)obj)->anim.velocityX;
                        *(f32 *)(state + 4) = k * ((GameObject *)obj)->anim.velocityZ;
                    }
                } else if (((GameObject *)obj)->anim.seqId == 0x3d5) {
                    {
                        f32 k = lbl_803E3A18;
                        *(f32 *)state = k * ((GameObject *)obj)->anim.velocityX;
                        *(f32 *)(state + 4) = k * ((GameObject *)obj)->anim.velocityZ;
                    }
                } else if (((GameObject *)obj)->anim.seqId == 0x3d6) {
                    {
                        f32 k = lbl_803E3A1C;
                        *(f32 *)state = k * ((GameObject *)obj)->anim.velocityX;
                        *(f32 *)(state + 4) = k * ((GameObject *)obj)->anim.velocityZ;
                    }
                } else if (((GameObject *)obj)->anim.seqId == 0x3df) {
                    *(f32 *)state = lbl_803E39F8;
                    *(f32 *)(state + 4) = lbl_803E39F8;
                }
            }
        } else if (ph == 2 && mode != 0) {
            if (*(f32 *)(state + 8) < (f32)*(s16 *)(state + 0x1c)) {
                f32 spd = lbl_803E3A20;
                *(f32 *)(state + 8) = spd * timeDelta + *(f32 *)(state + 8);
                end.x = spd * (((GameObject *)obj)->anim.velocityX * timeDelta) + ((GameObject *)obj)->anim.localPosX;
                end.y = spd * timeDelta + ((GameObject *)obj)->anim.localPosY;
                end.z = spd * (((GameObject *)obj)->anim.velocityZ * timeDelta) + ((GameObject *)obj)->anim.localPosZ;
                start.x = ((GameObject *)obj)->anim.localPosX;
                start.y = ((GameObject *)obj)->anim.localPosY;
                start.z = ((GameObject *)obj)->anim.localPosZ;
                sph.vals[0] = lbl_803E39F8;
                sph.a = -1;
                sph.b = 0;
                hitDetect_calcSweptSphereBounds(bounds, &start, &end, &sph, 1);
                hitDetectFn_800691c0(obj, bounds, 0, 1);
                count = hitDetectFn_80067958(obj, &start, &end, 1, hitBuf, 0);
                ((GameObject *)obj)->anim.localPosX = end.x;
                ((GameObject *)obj)->anim.localPosY = end.y;
                ((GameObject *)obj)->anim.localPosZ = end.z;
                if (count != 0) {
                    fn_801845FC(obj, 0, 0, hitBuf);
                }
            }
            if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe) {
                *(s16 *)(state + 0x1a) = 0xfa;
                Sfx_PlayFromObject(obj, SFXen_firlp6);
                ((GameObject *)obj)->anim.velocityX = ((GameObject *)player)->anim.localPosX - ((GameObject *)obj)->anim.localPosX;
                ((GameObject *)obj)->anim.velocityZ = ((GameObject *)player)->anim.localPosZ - ((GameObject *)obj)->anim.localPosZ;
                *(s16 *)obj = 0;
                sumsq = ((GameObject *)obj)->anim.velocityX * ((GameObject *)obj)->anim.velocityX + ((GameObject *)obj)->anim.velocityZ * ((GameObject *)obj)->anim.velocityZ;
                if (sumsq != lbl_803E39F8) {
                    sumsq = sqrtf(sumsq);
                }
                ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX / (dy = lbl_803E39FC * sumsq);
                ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ / dy;
                ((GameObject *)obj)->anim.rotY = 0;
                ((GameObject *)obj)->anim.velocityY = lbl_803E3A24;
                rot.x = lbl_803E39F8;
                rot.y = lbl_803E39F8;
                rot.z = lbl_803E39F8;
                rot.scale = lbl_803E3A00;
                rot.c = 0;
                rot.b = 0;
                rot.ang = (s16)randomGetRange(-10000, 10000);
                vecRotateZXY(&rot, (f32 *)(obj + 0x24));
                ang = (u16)getAngle(((GameObject *)obj)->anim.velocityX, -((GameObject *)obj)->anim.velocityZ);
                diff = *(s16 *)obj - ang;
                if (diff > 0x8000) {
                    diff += -0xffff;
                }
                if (diff < -0x8000) {
                    diff += 0xffff;
                }
                *(s16 *)obj = (s16)diff;
                *(u8 *)(state + 0x24) = 0;
                *(f32 *)(state + 8) = lbl_803E39F8;
                {
                    f32 k = lbl_803E39F4;
                    ((GameObject *)obj)->anim.localPosX = k * (((GameObject *)obj)->anim.velocityX * timeDelta) + ((GameObject *)obj)->anim.localPosX;
                    ((GameObject *)obj)->anim.localPosY = k * (((GameObject *)obj)->anim.velocityY * timeDelta) + ((GameObject *)obj)->anim.localPosY;
                    ((GameObject *)obj)->anim.localPosZ = k * (((GameObject *)obj)->anim.velocityZ * timeDelta) + ((GameObject *)obj)->anim.localPosZ;
                }
            }
        } else if (ph == 1 && mode != 0) {
            if (*(s16 *)(state + 0x1a) == 0) {
                best = 0;
                bestDist = lbl_803E3A28;
                count = hitDetectFn_80065e50(obj, ((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY, ((GameObject *)obj)->anim.localPosZ, &list, 1, 0);
                i = 0;
                p = list;
                for (; i < count; i++) {
                    dy = **p - ((GameObject *)obj)->anim.localPosY;
                    if (dy > lbl_803DBDC8) {
                    } else {
                        dy = (dy >= lbl_803E39F8) ? dy : -dy;
                        if (dy < bestDist) {
                            best = i;
                            bestDist = dy;
                        }
                    }
                    p++;
                }
                if (list != NULL) {
                    ((GameObject *)obj)->anim.localPosY = *list[best];
                    dy = list[best][2];
                    dy = (dy >= lbl_803E39F8) ? dy : -dy;
                    if (dy < lbl_803DBDC4) {
                        flag = 1;
                    } else {
                        fn_801845FC(obj, (int)list[best], 1, hitBuf);
                    }
                } else {
                    ((GameObject *)obj)->anim.localPosY = *(f32 *)(state + 0xc);
                }
                if (((GameObject *)obj)->anim.seqId != 0x3d6) {
                    *(s16 *)obj = (s16)(*(s16 *)obj + (int)randomGetRange(-1460, 1460));
                }
                *(f32 *)(obj + 0x24) = *(f32 *)state;
                {
                    f32 fz = lbl_803E39F8;
                    ((GameObject *)obj)->anim.velocityY = fz;
                    ((GameObject *)obj)->anim.velocityZ = *(f32 *)(state + 4);
                    rot.x = fz;
                    rot.y = fz;
                    rot.z = fz;
                }
                rot.scale = lbl_803E3A00;
                rot.c = 0;
                rot.b = 0;
                rot.ang = *(s16 *)obj - *(s16 *)(state + 0x18);
                vecRotateZXY(&rot, (f32 *)(obj + 0x24));
                *(s16 *)(state + 0x14) -= framesThisStep;
                if (*(s16 *)(state + 0x14) <= 0) {
                    if (ViewFrustum_IsSphereVisible((f32 *)(obj + 0xc), ((GameObject *)obj)->anim.hitboxScale * ((GameObject *)obj)->anim.rootMotionScale) == 0) {
                        *(s16 *)(state + 0x14) = 0;
                    } else {
                        *(s16 *)(state + 0x14) = 1;
                    }
                }
                if (flag != 0) {
                    ang = (u16)getAngle(list[best][1], list[best][3]);
                    *(s16 *)obj = (f32)ang * lbl_803DBDCC + lbl_803E3A2C;
                    ((GameObject *)obj)->anim.localPosX = timeDelta * (lbl_803E39F4 * list[best][1]) + ((GameObject *)obj)->anim.localPosX;
                    ((GameObject *)obj)->anim.localPosZ = timeDelta * (lbl_803E39F4 * list[best][3]) + ((GameObject *)obj)->anim.localPosZ;
                    ((GameObject *)obj)->anim.velocityX = list[best][1];
                    ((GameObject *)obj)->anim.velocityZ = list[best][3];
                } else {
                    ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.velocityX * timeDelta + ((GameObject *)obj)->anim.localPosX;
                    ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.velocityZ * timeDelta + ((GameObject *)obj)->anim.localPosZ;
                    sumsq = sqrtf(((GameObject *)obj)->anim.velocityX * ((GameObject *)obj)->anim.velocityX +
                                  ((GameObject *)obj)->anim.velocityZ * ((GameObject *)obj)->anim.velocityZ);
                    ObjAnim_SampleRootCurvePhase(sumsq, (ObjAnimComponent *)obj, &phase);
                    ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, phase, timeDelta, NULL);
                }
                flag = objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E3A00, 0, hitResults, obj, 8, -1, 0, 0);
                sph.vals[0] = lbl_803E3A00;
                sph.a = -1;
                sph.b = 10;
                hitDetect_calcSweptSphereBounds(bounds, (void *)(obj + 0x80), (void *)(obj + 0xc), &sph, 1);
                hitDetectFn_800691c0(obj, bounds, 0, 1);
                hits = hitDetectFn_80067958(obj, (void *)(obj + 0x80), (void *)(obj + 0xc), 1, hitBuf, 0);
                if (flag != 0 ||
                    Vec_distance((void *)(obj + 0x18), (void *)(*(int *)&((GameObject *)obj)->anim.placementData + 8)) > lbl_803E3A30 ||
                    ((hits & 1) != 0 && (hits & 0x10) == 0)) {
                    PSVECSubtract((void *)(*(int *)&((GameObject *)obj)->anim.placementData + 8), (void *)(obj + 0xc), vsub);
                    ang = (u16)getAngle(vsub[0], vsub[2]);
                    *(s16 *)obj = (f32)ang * lbl_803DBDD0 + lbl_803E3A2C;
                }
            } else {
                bestDist = lbl_803E3A28;
                count = hitDetectFn_80065e50(obj, ((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY, ((GameObject *)obj)->anim.localPosZ, &list, 1, 0);
                i = 0;
                p = list;
                for (; i < count; i++) {
                    dy = **p - ((GameObject *)obj)->anim.localPosY;
                    if (dy < lbl_803E39F8) {
                        dy = dy * lbl_803E3A34;
                    }
                    if (dy < bestDist) {
                        best = i;
                        bestDist = dy;
                    }
                    p++;
                }
                if (list == NULL) {
                    ((GameObject *)obj)->anim.localPosY = *(f32 *)(state + 0xc);
                } else {
                    ((GameObject *)obj)->anim.localPosY = *list[best];
                    fn_801845FC(obj, (int)list[best], 1, hitBuf);
                }
                *(s16 *)(state + 0x1a) -= framesThisStep;
                if (*(s16 *)(state + 0x1a) <= 0) {
                    *(s16 *)(state + 0x1a) = 0;
                }
            }
            if ((*(s16 *)(state + 0x1a) != 0 || ((GameObject *)obj)->anim.seqId != 0x3d6) &&
                Vec_xzDistance(&((GameObject *)player)->anim.worldPosX, (f32 *)(obj + 0x18)) < lbl_803E3A38) {
                dy = ((GameObject *)obj)->anim.localPosY - ((GameObject *)player)->anim.localPosY;
                if (dy >= lbl_803E39F8) {
                } else {
                    dy = -dy;
                }
                if (dy < lbl_803E3A3C) {
                    if (GameBit_Get(0x910) == 0) {
                        *(s16 *)(state + 0x2c) = -1;
                        *(s16 *)(state + 0x2e) = 0;
                        *(f32 *)(state + 0x30) = lbl_803E3A00;
                        ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x2c);
                        GameBit_Set(0x910, 1);
                        *(u8 *)(state + 0x28) |= 1;
                    } else {
                        money2 = lbl_803E39F0;
                        playerAddMoney(player, *((u8 *)&money2 + *(u8 *)(state + 0x27)));
                        *(s16 *)(state + 0x10) = 0x50;
                        *(s16 *)(state + 0x14) = 0;
                    }
                    if (((GameObject *)obj)->anim.hitReactState != NULL) {
                        ObjHits_DisableObject(obj);
                    }
                    Sfx_PlayFromObject(obj, (u16)*(s16 *)(state + 0x1e));
                    itemPickupDoParticleFx(obj, lbl_803E3A00, *(s16 *)(state + 0x20), 0x28);
                }
            }
            if (*(s16 *)(state + 0x1a) == 0 && ((GameObject *)obj)->anim.seqId == 0x3d6) {
                if (Vec_xzDistance(&((GameObject *)player)->anim.worldPosX, (f32 *)(obj + 0x18)) < lbl_803E3A3C) {
                    dy = ((GameObject *)obj)->anim.localPosY - ((GameObject *)player)->anim.localPosY;
                    if (dy >= lbl_803E39F8) {
                    } else {
                        dy = -dy;
                    }
                    if (dy < lbl_803E3A3C) {
                        if (GameBit_Get(0x1d9) == 0) {
                            ObjMsg_SendToObject(player, 0x60004, obj, 1);
                        }
                        {
                            f32 k = lbl_803E3A40;
                            ((GameObject *)obj)->anim.localPosX = k * -((GameObject *)obj)->anim.velocityX + ((GameObject *)obj)->anim.localPosX;
                            ((GameObject *)obj)->anim.localPosZ = k * -((GameObject *)obj)->anim.velocityZ + ((GameObject *)obj)->anim.localPosZ;
                        }
                        Sfx_PlayFromObject(obj, SFXen_lwfl1_c);
                    }
                }
                if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe) {
                    *(s16 *)(state + 0x1a) = 0xfa;
                    Sfx_PlayFromObject(obj, SFXen_firlp6);
                }
            } else if (*(s16 *)(state + 0x1a) != 0 && ((GameObject *)obj)->anim.seqId == 0x3d6 &&
                       ObjHits_GetPriorityHit(obj, 0, 0, 0) == 0xe) {
                Sfx_PlayFromObject(obj, SFXen_mossyloop16);
                money3 = lbl_803E39F0;
                playerAddMoney(player, *((u8 *)&money3 + *(u8 *)(state + 0x27)));
                *(s16 *)(state + 0x10) = 0x50;
                *(s16 *)(state + 0x14) = 0;
            }
        }
    }
}

/*
 * --INFO--
 *
 * Function: FUN_80184a54
 * EN v1.0 Address: 0x80184A54
 * EN v1.0 Size: 3668b
 * EN v1.1 Address: 0x80184E88
 * EN v1.1 Size: 3476b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: fn_80185868
 * EN v1.0 Address: 0x80185A48
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x80185DC0
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_80185868(int obj, f32 arg)
{
  extern void *lbl_803DDAD0;
  extern void *lbl_803DDAD4;
  extern f32 lbl_803E3A58;
  extern void Sfx_PlayFromObject(int obj, int sfx);
  struct {
    u8 pad[8];
    f32 val;
    u8 pad2[12];
  } stk;
  WindLift107State *sub;
  f32 fz;

  sub = ((GameObject *)obj)->extra;
  stk.val = sub->radius;
  (*(code *)(*(int *)lbl_803DDAD0 + 4))(obj, 0xf, 0, 2, -1, 0);
  (*(code *)(*(int *)lbl_803DDAD4 + 4))(obj, 0, stk.pad, 2, -1, 0);
  Sfx_PlayFromObject(obj, SFXmn_eggylaugh116);
  fz = lbl_803E3A58;
  ((GameObject *)obj)->anim.velocityX = fz;
  ((GameObject *)obj)->anim.velocityZ = fz;
  sub->ventState = 0x32;
  sub->liftTimer = 800;
  sub->launchPhase = 0;
  sub->rideState = 0;
  ((GameObject *)obj)->unkF8 = 0;
  ((GameObject *)obj)->unkF4 = 2;
  ObjHits_EnableObject(obj);
  ObjHits_MarkObjectPositionDirty(obj);
  sub->spitTimer = 0;
  if (arg < sub->radius) {
    ObjMsg_SendToObject(Obj_GetPlayerObject(), 0x60004, obj, 0);
  }
  ObjHitbox_SetCapsuleBounds(obj, (int)sub->radius, -5, 10);
  ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
  ObjHits_EnableObject(obj);
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: fn_80185A24
 * EN v1.0 Address: 0x80185C9C
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80185F7C
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_80185A24(int obj, int p2, int p3, int p4, int p5, s8 renderState)
{
    extern void fn_8003B5E0(int a, int b, int c, int d);
    extern void objRenderFn_8003b8f4(int p1, int p2, int p3, int p4, int p5, f32 scale);
    extern f32 lbl_803E3A5C;
    WindLift107State *state;
    s16 t;

    state = ((GameObject *)obj)->extra;
    if ((state->ventState == 0 || state->ventState > 50) && state->holdTimer == 0) {
        goto ok;
    }
    goto end;
ok:
    if (((GameObject *)obj)->unkF8 != 0) {
        if (renderState == -1) {
        } else {
            goto end;
        }
    } else {
        if (renderState == 0) {
            goto end;
        }
    }
    t = state->spitTimer;
    if (t != 0) {
        if (t < 60) {
            state->glowPulse = state->glowPulse + framesThisStep * 10;
            if (state->glowPulse > 0x80) {
                state->glowPulse = 0;
            }
            fn_8003B5E0(200, 30, 30, state->glowPulse);
        } else if (t < 240) {
            state->glowPulse = state->glowPulse + framesThisStep * 5;
            if (state->glowPulse > 0x80) {
                state->glowPulse = 0;
            }
            fn_8003B5E0(200, 30, 30, state->glowPulse);
        }
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E3A5C);
end:;
}

/*
 * --INFO--
 *
 * Function: fn_80185B74
 * EN v1.0 Address: 0x80185DC4
 * EN v1.0 Size: 2392b
 * EN v1.1 Address: 0x801860CC
 * EN v1.1 Size: 1880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma opt_common_subs off
void fn_80185B74(int obj)
{
    extern void *lbl_803DDAD4;
    extern void *gSHthorntailAnimationInterface;
    extern EffectInterface **gPartfxInterface;
    extern f32 lbl_803E3A58;
    extern f32 lbl_803E3A5C;
    extern f32 lbl_803E3A60;
    extern f32 lbl_803E3A64;
    extern f32 lbl_803E3A68;
    extern f32 lbl_803E3A6C;
    extern f32 lbl_803E3A70;
    extern f32 lbl_803E3A74;
    extern f64 lbl_803E3A78;
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void Sfx_StopObjectChannel(int obj, int channel);
    extern int buttonDisable(int p1, int p2);
    extern u32 getButtonsJustPressed(int controller);
    extern f32 getXZDistance(void *a, void *b);
    extern void ObjHits_ClearHitVolumes(int obj);
    typedef struct { s16 ang; s16 b; s16 c; f32 scale; f32 x; f32 y; f32 z; } WindLiftRot;
    typedef struct { u8 pad[8]; f32 val; u8 pad2[12]; } WindLiftStk;

    WindLiftRot rot;
    WindLiftStk stkA;
    WindLiftStk stkB;
    WindLiftStk stkC;
    f32 spd;
    u8 yawBuf[4];
    int player;
    int p4c;
    WindLift107State *state;
    int sub;
    f32 dist;
    u8 ph;
    char on;
    u8 held;

    p4c = *(int *)&((GameObject *)obj)->anim.placementData;
    spd = lbl_803E3A5C;
    (*(code *)(*(int *)gSHthorntailAnimationInterface + 0x18))(&spd);
    state = ((GameObject *)obj)->extra;
    player = Obj_GetPlayerObject();
    sub = *(int *)&((GameObject *)player)->extra;
    dist = Vec_distance((void *)&((GameObject *)player)->anim.worldPosX, (void *)&((GameObject *)obj)->anim.worldPosX);
    if (state->liftTimer <= 0) {
        state->ventState = 1;
        state->launchPhase = 0;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        {
            f32 fz = lbl_803E3A58;
            ((GameObject *)obj)->anim.velocityX = fz;
            ((GameObject *)obj)->anim.velocityZ = fz;
        }
    }
    if (state->spitTimer != 0) {
        Sfx_PlayFromObject(obj, SFXmn_dimspit6);
        state->spitTimer -= framesThisStep;
        if ((int)randomGetRange(0, 2) == 2) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x51c, NULL, 1, -1, NULL);
        }
        if (state->spitTimer <= 0) {
            fn_80185868(obj, dist);
            return;
        }
    }
    if (state->holdTimer != 0) {
        state->holdTimer = state->holdTimer - (s16)(int)(timeDelta * spd);
        if (state->holdTimer <= 0) {
            state->holdTimer = 0;
            state->ventState = 0;
            ObjHits_EnableObject(obj);
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
            ((GameObject *)obj)->unkF4 = 0;
        }
        return;
    }
    if (state->ventState != 0) {
        Sfx_StopObjectChannel(obj, SFXen_firlp6);
        state->ventState -= framesThisStep;
        if (state->ventState <= 0) {
            if (state->holdReload != 0) {
                state->holdTimer = state->holdReload;
            } else {
                state->holdTimer = 1;
            }
        }
        if (state->ventState <= 50) {
            return;
        }
    }
    if (*(s8 *)&state->launchPhase == 0) {
        if (*(s8 *)&state->rideState == 0) {
            int cam = (*gCameraInterface)->getOverrideTarget();
            on = 0;
            if ((void *)cam != (void *)obj &&
                (*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0 && ((GameObject *)obj)->unkF8 == 0) {
                buttonDisable(0, 0x100);
                Obj_GetYawDeltaToObject(obj, player, yawBuf);
                state->yawLow = -32768;
                state->yawHigh = 0;
                on = 1;
            }
            *(s8 *)&state->rideState = on;
            if (*(s8 *)&state->rideState != 0) {
                state->riding = 1;
                state->spitTimer = 600;
            }
            if (((GameObject *)obj)->unkF8 == 0) {
                ObjHits_EnableObject(obj);
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
            }
            ((GameObject *)obj)->anim.previousLocalPosX = ((GameObject *)obj)->anim.localPosX;
            ((GameObject *)obj)->anim.previousLocalPosY = ((GameObject *)obj)->anim.localPosZ;
            ((GameObject *)obj)->anim.previousLocalPosZ = ((GameObject *)obj)->anim.localPosZ;
        } else {
            u8 st21;
            ObjHitsPriorityState *hitState;
            ObjHits_DisableObject(obj);
            hitState = (ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState;
            hitState->localPosX = ((GameObject *)obj)->anim.localPosX;
            hitState->localPosY = ((GameObject *)obj)->anim.localPosY;
            hitState->localPosZ = ((GameObject *)obj)->anim.localPosZ;
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
            if ((getButtonsJustPressed(0) & 0x100) != 0) {
                state->riding = 0;
            }
            if (*(s8 *)&state->riding != 0) {
                state->ventState = 0;
                state->holdTimer = 0;
                ObjMsg_SendToObject(player, 0x100010, obj,
                                    (state->yawHigh << 0x10) | ((u16)state->yawLow));
            }
            if (((GameObject *)obj)->unkF8 == 1) {
                state->rideState = 2;
            }
            st21 = state->rideState;
            if ((s8)st21 == 2 && ((GameObject *)obj)->unkF8 == 0 && ((GameObject *)player)->anim.currentMove != 0x447) {
                state->rideState = 0;
                state->launchPhase = 1;
                {
                    f32 fz = lbl_803E3A58;
                    ((GameObject *)obj)->anim.velocityX = fz;
                    ((GameObject *)obj)->anim.velocityY = lbl_803E3A64 * *(f32 *)(sub + 0x298) + lbl_803E3A60;
                    ((GameObject *)obj)->anim.velocityZ = lbl_803E3A6C * *(f32 *)(sub + 0x298) + lbl_803E3A68;
                    rot.x = fz;
                    rot.y = fz;
                    rot.z = fz;
                }
                rot.scale = lbl_803E3A5C;
                rot.c = 0;
                rot.b = 0;
                rot.ang = *(s16 *)player;
                vecRotateZXY(&rot, &((GameObject *)obj)->anim.velocityX);
                Sfx_PlayFromObject(obj, SFXmn_dimbos46);
            } else if ((s8)st21 == 2 && ((GameObject *)obj)->unkF8 == 0) {
                f32 fz;
                state->rideState = 0;
                state->launchPhase = 2;
                fz = lbl_803E3A58;
                ((GameObject *)obj)->anim.velocityX = fz;
                ((GameObject *)obj)->anim.velocityY = fz;
                ((GameObject *)obj)->anim.velocityZ = fz;
                Sfx_PlayFromObject(obj, SFXmn_dimbos46);
            }
        }
    }
    ph = state->launchPhase;
    if ((s8)ph == 0 && *(s8 *)&state->rideState == 0) {
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
            sub = *(int *)&((GameObject *)obj)->extra;
            stkA.val = ((WindLift107State *)sub)->radius;
            (*(code *)(*(int *)lbl_803DDAD4 + 4))(obj, 0, stkA.pad, 2, -1, 0);
            ((WindLift107State *)sub)->spitTimer = 1;
            return;
        }
    } else if ((s8)ph != 0) {
        state->liftTimer -= framesThisStep;
        if (*(s8 *)&state->launchPhase == 1) {
            ObjHits_SetHitVolumeSlot(obj, 0xe, 3, 0);
            if (((GameObject *)obj)->anim.velocityY > lbl_803E3A70) {
                ((GameObject *)obj)->anim.velocityY = lbl_803E3A74 * timeDelta + ((GameObject *)obj)->anim.velocityY;
            }
            ObjHits_EnableObject(obj);
        }
        held = ((ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState)->contactFlags;
        if ((s8)held != 0 && *(s8 *)&state->launchPhase == 1) {
            ((GameObject *)obj)->anim.velocityY = lbl_803E3A58;
            state->launchPhase = 0;
            sub = *(int *)&((GameObject *)obj)->extra;
            stkB.val = ((WindLift107State *)sub)->radius;
            (*(code *)(*(int *)lbl_803DDAD4 + 4))(obj, 0, stkB.pad, 2, -1, 0);
            ((WindLift107State *)sub)->spitTimer = 1;
            return;
        }
        if ((s8)held != 0 && *(s8 *)&state->launchPhase == 2) {
            state->launchPhase = 0;
            sub = *(int *)&((GameObject *)obj)->extra;
            stkC.val = ((WindLift107State *)sub)->radius;
            (*(code *)(*(int *)lbl_803DDAD4 + 4))(obj, 0, stkC.pad, 2, -1, 0);
            ((WindLift107State *)sub)->spitTimer = 1;
            ((GameObject *)obj)->anim.velocityY = lbl_803E3A58;
            return;
        }
        ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.velocityX * timeDelta + ((GameObject *)obj)->anim.localPosX;
        ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
        ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.velocityZ * timeDelta + ((GameObject *)obj)->anim.localPosZ;
    }
    ((GameObject *)obj)->anim.worldPosX = ((GameObject *)obj)->anim.localPosX;
    ((GameObject *)obj)->anim.worldPosY = ((GameObject *)obj)->anim.localPosY;
    ((GameObject *)obj)->anim.worldPosZ = ((GameObject *)obj)->anim.localPosZ;
    state->unk16 -= framesThisStep;
    if (*(s8 *)&state->rideState != 0) {
        if (getXZDistance((void *)&((GameObject *)obj)->anim.worldPosX, (void *)(p4c + 8)) >=
            (f32)(state->maxDist * state->maxDist)) {
            f32 fz = lbl_803E3A58;
            ((GameObject *)obj)->anim.velocityX = fz;
            ((GameObject *)obj)->anim.velocityZ = fz;
            state->ventState = 500;
            state->launchPhase = 0;
            ((GameObject *)obj)->unkF8 = 0;
            ObjHits_EnableObject(obj);
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
            ObjHits_ClearHitVolumes(obj);
        }
    }
}
#pragma opt_common_subs reset

void fn_801862CC(int obj, int p)
{
  extern void *lbl_803DDAD0;
  extern void *lbl_803DDAD4;
  extern f32 lbl_803E3A78;
  extern f32 lbl_803E3A80;
  extern f32 lbl_803E3A84;
  WindLift107State *sub;
  int p54;
  int p64;

  sub = ((GameObject *)obj)->extra;
  ((GameObject *)obj)->anim.rotX = 0;
  p54 = *(int *)(obj + 0x54);
  *(int *)&((ObjHitsPriorityState *)p54)->skeletonHitMask = 16;
  p54 = *(int *)&((GameObject *)obj)->anim.hitReactState;
  *(int *)&((ObjHitsPriorityState *)p54)->objectHitMask = 16;
  ObjHits_DisableObject(obj);
  ObjGroup_AddObject(obj, 16);
  sub->ventState = 0;
  sub->launchPhase = 0;
  {
    s16 v = *(s16 *)(p + 0x1c);
    if (v == 0) {
      sub->holdReload = 0;
    } else {
      sub->holdReload = v * 0x34BC0;
    }
  }
  sub->holdTimer = 0;
  sub->unk25 = 0;
  lbl_803DDAD0 = Resource_Acquire(91, 1);
  lbl_803DDAD4 = Resource_Acquire(170, 1);
  sub->unk16 = 100;
  sub->unk18 = 400;
  ((GameObject *)obj)->anim.rotX = (s16)(*(char *)(p + 0x18) << 8);
  sub->unk14 = *(s16 *)(p + 0x1e);
  sub->maxDist = *(s16 *)(p + 0x20);
  if (sub->maxDist == 0) {
    sub->maxDist = 30;
  }
  sub->liftTimer = 800;
  sub->spitTimer = 0;
  sub->glowPulse = 0xff;
  sub->unk27 = 0;
  if (*(char *)(p + 0x19) != '\0') {
    sub->radius = lbl_803E3A80 * (f32)(s32)*(char *)(p + 0x19);
  } else {
    sub->radius = lbl_803E3A84;
  }
  ((GameObject *)obj)->unkF4 = 0;
  if (((GameObject *)obj)->anim.modelState != NULL) {
    p64 = *(int *)&((GameObject *)obj)->anim.modelState;
    *(u32 *)(p64 + 0x30) |= 0x8000;
  }
}

/*
 * --INFO--
 *
 * Function: portalspelldoor_update
 * EN v1.0 Address: 0x80186748
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x80186A38
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void portalspelldoor_update(int obj)
{
    extern int playerHasSpell(int player, int spell);
    extern int objGetAnimState80A(int player);
    extern void fn_80296B78(int player, int v);
    extern int getTrickyObject(void);
    extern void trickyImpress(int tricky);
    extern ObjectTriggerInterface **gObjectTriggerInterface;
    typedef struct {
        u8 open : 1;
    } PortalFlags;
    PortalSpellDoorState *state;
    int player;
    int p4c;
    int t;

    player = Obj_GetPlayerObject();
    state = ((GameObject *)obj)->extra;
    p4c = *(int *)&((GameObject *)obj)->anim.placementData;
    if (playerHasSpell(player, 3) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x10;
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
    }
    if (((PortalFlags *)&state->flags0C)->open) {
        ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        if (objGetAnimState80A(player) == 0x5bd) {
            fn_80296B78(player, -1);
        }
        GameBit_Set(((PortalspelldoorPlacement *)p4c)->unk1E, 1);
    } else {
        if (objGetAnimState80A(player) == 0x5bd && state->openTimer == -1) {
            state->openTimer = 0;
        }
    }
    if (state->openTimer != -1) {
        t = state->openTimer - framesThisStep;
        state->openTimer = t;
        if (t < 0) {
            int tricky;
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
            (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
            tricky = getTrickyObject();
            if ((void *)tricky != NULL) {
                trickyImpress(tricky);
            }
            ((PortalFlags *)&state->flags0C)->open = 1;
            state->openTimer = -1;
        }
    }
}


/* Trivial 4b 0-arg blr leaves. */
void dll_107_hitDetect_nop(void) {}
void dll_107_release_nop(void) {}
void dll_107_initialise_nop(void) {}
void Dummy108_free(void) {}
void Dummy108_render(void) {}
void Dummy108_hitDetect(void) {}
void Dummy108_update(void) {}
void Dummy108_init(void) {}
void Dummy108_release(void) {}
void Dummy108_initialise(void) {}
void portalspelldoor_free(void) {}
void portalspelldoor_hitDetect(void) {}
void portalspelldoor_release(void) {}
void portalspelldoor_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int dll_107_getExtraSize_ret_44(void) { return 0x2c; }
int dll_107_getObjectTypeId(void) { return 0x0; }
int Dummy108_getExtraSize(void) { return 0x0; }
int Dummy108_getObjectTypeId(void) { return 0x0; }
int portalspelldoor_getExtraSize(void) { return 0x10; }
int portalspelldoor_getObjectTypeId(void) { return 0x0; }
int LanternFireFly_getExtraSize(void) { return 0x74; }
int LanternFireFly_getObjectTypeId(void) { return 0x0; }

/* LanternFireFly_modelMtxFn: receives (obj, f1, f2, f3) and stores the
 * three floats into obj->_b8 at +0x54/+0x58/+0x5c. */
void LanternFireFly_modelMtxFn(u8* obj, f32 a, f32 b, f32 c) {
    LanternFireFlyState* sub = ((GameObject *)obj)->extra;
    sub->anchorX = a;
    sub->anchorY = b;
    sub->anchorZ = c;
}

typedef struct LanternFireFlyVectorParams {
    s16 yaw;
    s16 pitch;
    s16 roll;
    s16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} LanternFireFlyVectorParams;

void LanternFireFly_func0B(int obj)
{
    typedef struct { u8 mode : 2; } LFFlags;
    LanternFireFlyState *state;
    int setup;
    int p;
    f32 vec[3];
    f32 *vp = vec;
    f32 py;
    f32 y2;

    state = ((GameObject *)obj)->extra;
    setup = *(int *)&((GameObject *)obj)->anim.placementData;
    state->field68 = ((LanternFireFlyPlacement *)setup)->unk18;
    state->stateId = ((LanternFireFlyPlacement *)setup)->stateId;
    state->field4C = lbl_803E3AA0;
    state->field50 = (f32)(int)((LanternFireFlyPlacement *)setup)->unk1C;
    state->field6F = 0;
    objHitDetectFn_80062e84(obj, 0, 1);
    p = Obj_GetPlayerObject();
    vec[0] = *(f32 *)(p + 0x18);
    py = *(f32 *)(p + 0x1c);
    vec[1] = py;
    vec[2] = *(f32 *)(p + 0x20);
    vec[1] = py + lbl_803E3AA4;
    y2 = lbl_803E3AA8 + py;
    {
        LanternFireFlyState *st = ((GameObject *)obj)->extra;
        st->anchorX = vec[0];
        st->anchorY = y2;
        st->anchorZ = vec[2];
        st = ((GameObject *)obj)->extra;
        vec[0] = vec[0] - st->anchorX;
        vec[1] = vec[1] - st->anchorY;
        vec[2] = vec[2] - st->anchorZ;
        st->offX = vec[0];
        st->offY = vec[1];
        st->offZ = vec[2];
        st->animFrame = 4;
    }
    fn_801869DC(obj);
    fn_801869DC(obj);
    fn_801869DC(obj);
    fn_801869DC(obj);
    fn_801869DC(obj);
    fn_801869DC(obj);
    ((LFFlags *)&state->modeFlags)->mode = 1;
    state->timer = ((LanternFireFlyPlacement *)setup)->timer;
    gameBitIncrement(0x698);
}

void fn_801868D0(int obj)
{
    typedef struct { s16 ang; s16 b; s16 c; f32 scale; f32 x; f32 y; f32 z; } LFRot;
    extern f32 lbl_803E3ABC;
    LFRot rot;
    LanternFireFlyState *state;
    s16 r;
    f32 fz;

    state = ((GameObject *)obj)->extra;
    state->offX = lbl_803E3AB8;
    state->offY = (f32)(int)randomGetRange(-state->field68, state->field68);
    if (state->field50 < lbl_803E3ABC) {
        state->offZ = lbl_803E3AB8;
    } else {
        state->offZ = state->field50 -
                      (f32)(int)randomGetRange(0x14, (s16)(int)state->field50);
    }
    r = (s16)randomGetRange(3000, 5000);
    state->randAngle += r;
    fz = lbl_803E3AB8;
    rot.x = fz;
    rot.y = fz;
    rot.z = fz;
    rot.scale = lbl_803E3AA0;
    rot.c = 0;
    rot.b = 0;
    rot.ang = state->randAngle;
    vecRotateZXY(&rot, &state->offX);
}

void fn_801869DC(int obj)
{
    typedef struct { u8 mode : 2; } LFF2;
    LanternFireFlyState *state;

    state = ((GameObject *)obj)->extra;
    state->controlX[0] = state->controlX[1];
    state->controlY[0] = state->controlY[1];
    state->controlZ[0] = state->controlZ[1];
    state->controlX[1] = state->controlX[2];
    state->controlY[1] = state->controlY[2];
    state->controlZ[1] = state->controlZ[2];
    state->controlX[2] = state->controlX[3];
    state->controlY[2] = state->controlY[3];
    state->controlZ[2] = state->controlZ[3];
    if (((LFF2 *)&state->modeFlags)->mode == 1) {
        int player = Obj_GetPlayerObject();
        state->speed =
            lbl_803E3AC4 * Vec_distance((void *)&((GameObject *)obj)->anim.worldPosX, (void *)&((GameObject *)player)->anim.worldPosX) + lbl_803E3AC0;
    } else {
        state->speed = lbl_803E3AC4 * (f32)(s32)randomGetRange(0x3c, 0x5a);
    }
    state->controlX[3] = state->offX;
    state->controlY[3] = state->offY;
    state->controlZ[3] = state->offZ;
}

/* portalspelldoor_init: byte<<8 / halfword<<8 stash at obj+0..+2, prime
 * obj+8 with lbl_803E3A8C, derive sub+4 = obj->_a8 * obj+8 * lbl_803E3A90,
 * GameBit-gated bit-set on obj+6 (0x4000) and obj+b0 (0xe000), then
 * latch sub+8 = -1. */
extern f32 lbl_803E3A8C;
extern f32 lbl_803E3A90;
void portalspelldoor_init(u8* obj, u8* data) {
    PortalSpellDoorState* sub = ((GameObject *)obj)->extra;
    *(s16*)obj = (s16)((s32)(s8)data[0x18] << 8);
    ((GameObject *)obj)->anim.rotY = (s16)((s32)*(s16*)(data + 0x1c) << 8);
    ((GameObject *)obj)->anim.rootMotionScale = lbl_803E3A8C;
    {
        f32 _ab = ((GameObject *)obj)->anim.hitboxScale * ((GameObject *)obj)->anim.rootMotionScale;
        sub->openAmount = _ab * lbl_803E3A90;
    }
    if (GameBit_Get(*(s16*)(data + 0x1e)) != 0) {
        ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0xe000);
    }
    sub->openTimer = -1;
}

/* LanternFireFly_setScale: subtract sub->_54..5c from vec[0..2] (overwriting
 * vec), copy the result to sub->_34..3c, set sub->_6c = 4. */
void LanternFireFly_setScale(u8* obj, f32* vec) {
    LanternFireFlyState* sub = ((GameObject *)obj)->extra;
    vec[0] = vec[0] - sub->anchorX;
    vec[1] = vec[1] - sub->anchorY;
    vec[2] = vec[2] - sub->anchorZ;
    sub->offX = vec[0];
    sub->offY = vec[1];
    sub->offZ = vec[2];
    sub->animFrame = 4;
}

/* LanternFireFly_free: free the light struct at sub[0] if present, then
 * (when p2==0 and the freshly-cleared sub[0] is NULL and mode bits 6..7
 * aren't 1) reset lbl_803DDAD8 to 0; finally ObjGroup_RemoveObject(obj, 0x30)
 * and dispatch vtable[6] of *gExpgfxInterface. */
extern void ModelLightStruct_free(void* p);
extern u8 lbl_803DDAD8;
void LanternFireFly_free(u8* obj, int p2) {
    LanternFireFlyState* sub = ((GameObject *)obj)->extra;
    if (*(void **)&sub->light != NULL) {
        ModelLightStruct_free(*(void **)&sub->light);
        *(void **)&sub->light = NULL;
    }
    if (p2 == 0 && *(void **)&sub->light != NULL && ((sub->modeFlags >> 6) & 3) != 1u) {
        lbl_803DDAD8 = 0;
    }
    ObjGroup_RemoveObject(obj, 0x30);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

ObjectDescriptor gDummy108ObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Dummy108_initialise,
    (ObjectDescriptorCallback)Dummy108_release,
    0,
    (ObjectDescriptorCallback)Dummy108_init,
    (ObjectDescriptorCallback)Dummy108_update,
    (ObjectDescriptorCallback)Dummy108_hitDetect,
    (ObjectDescriptorCallback)Dummy108_render,
    (ObjectDescriptorCallback)Dummy108_free,
    (ObjectDescriptorCallback)Dummy108_getObjectTypeId,
    Dummy108_getExtraSize,
};

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3A88;
extern void objRenderFn_8003b8f4(f32);
void portalspelldoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3A88); }

extern ModgfxInterface **gModgfxInterface;
extern void *lbl_803DDAD0;
extern void *lbl_803DDAD4;
void fn_801859D4(int *obj) {
    (*gModgfxInterface)->detachSource(obj);
    Resource_Release(lbl_803DDAD0);
    lbl_803DDAD0 = NULL;
    Resource_Release(lbl_803DDAD4);
    lbl_803DDAD4 = NULL;
}

extern u8 lbl_803DBDB0;
extern u8 lbl_803DBDB4;
extern u8 lbl_803DBDB8;

void scarab_init(int *obj, u8 *def) {
    ScarabState *state = ((GameObject *)obj)->extra;
    int *model;
    state->phase = 0;
    state->mode = *(s16 *)((char *)def + 0x1a);
    state->yawSpeed = (s16)randomGetRange(0x3e8, 0xfa0);
    state->riseLimit = (s16)randomGetRange(0x32, 0x64);
    state->baseY = ((ObjPlacement *)def)->posY;
    model = (int *)Obj_GetActiveModel(obj);
    switch (((GameObject *)obj)->anim.seqId) {
    case 0x3d3:
        *(u8 *)((char *)*(int *)((char *)model + 0x34) + 8) = (&lbl_803DBDB0)[randomGetRange(0, 2)];
        state->pickupSfx = 0x41;
        state->particleId = 4;
        state->unk22 = 2;
        state->moneyKind = 0;
        break;
    case 0x3d4:
        *(u8 *)((char *)*(int *)((char *)model + 0x34) + 8) = (&lbl_803DBDB4)[randomGetRange(0, 1)];
        state->pickupSfx = 0x42;
        state->particleId = 1;
        state->unk22 = 5;
        state->moneyKind = 1;
        break;
    case 0x3d5:
        *(u8 *)((char *)*(int *)((char *)model + 0x34) + 8) = (&lbl_803DBDB8)[randomGetRange(0, 3)];
        state->pickupSfx = 0x43;
        state->particleId = 2;
        state->unk22 = 4;
        state->moneyKind = 2;
        break;
    case 0x3d6:
    default:
        *(u8 *)((char *)*(int *)((char *)model + 0x34) + 8) = 5;
        state->pickupSfx = 0x44;
        state->particleId = 6;
        state->unk22 = 1;
        state->moneyKind = 3;
        break;
    }
    ObjMsg_AllocQueue(obj, 2);
}
