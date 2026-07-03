/*
 * dbprotection - galleon damage-phase + boss handlers for the SB_Galleon boss.
 * Runs on the SB_Galleon object (extra == SBGalleonState) alongside the
 * SB_Galleon handlers in DBstealerworm.c.
 *
 * fn_801DFA28 is the per-step movement/flight driver: it locates the
 * "tricky" target object (seqId 0x8C), runs the wander/drift bob in phase
 * 0, the flight-pattern approach in phase 1, and the swooping attack sweep
 * in phases 2-8, finally fading the screen out (kind 0x41) and refreshing
 * trigger sequence 0 when the run completes.
 *
 * DBprotection_updateShield drives the screen transition (game bits 0x9f /
 * 0xa0 / 0x91c arm-use-ready), the envfx game-bit cycle, the cloud action
 * interface and the shield-impact sfx (latched on the sine of shieldAngle).
 * DBprotection_updateEnvfxGameBits toggles the A/B envfx cycle game bits
 * (0xa3c-0xa3f), swapping envfxIndex and replaying actions from the
 * SBGalleonState envfx table. DBprotection_getCameraState exposes the
 * boss's cameraState byte to other DLLs; DBprotection_storeHomePosition
 * latches the object's local position as the home position.
 */
#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/dll/DB/sbgalleon_state.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_trigger_ids.h"

#define DBPROTECTION_GAMEBIT_CYCLE_A_PENDING 0xa3c
#define DBPROTECTION_GAMEBIT_CYCLE_B_PENDING 0xa3d
#define DBPROTECTION_GAMEBIT_CYCLE_A_DONE 0xa3e
#define DBPROTECTION_GAMEBIT_CYCLE_B_DONE 0xa3f
#define DBPROTECTION_GAMEBIT_TRANSITION_ARMED 0x9f
#define DBPROTECTION_GAMEBIT_TRANSITION_USED 0xa0
#define DBPROTECTION_GAMEBIT_TRANSITION_READY 0x91c
#define DBPROTECTION_GAMEBIT_MUTE_SFX 0xa71
#define DBPROTECTION_ENVFX_A 0x467e7
#define DBPROTECTION_ENVFX_B 0x467e8
#define DBPROTECTION_PLAYER_ENVFX_FLASH 0x96
#define DBPROTECTION_PLAYER_ENVFX_SWAP 0x8a
#define DBPROTECTION_GAMEBIT_DIVE_ACTIVE 0xF1E

extern int randomGetRange(int lo, int hi);
extern int Obj_GetPlayerObject(void);
extern int ObjList_FindObjectById(int id);
extern int ObjList_GetObjects(int* startIndex, int* objectCount);
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
extern void Sfx_StopFromObject(int obj, int sfxId);
extern void Sfx_StopObjectChannel(u32 obj, u32 channel);
extern s32 Sfx_IsPlayingFromObjectChannel(u32 obj, u32 channel);


extern f32 sqrtf(f32 x);
extern int getAngle(float y, float x);
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern void fn_801EED5C(int obj, f32* x, f32* y, f32* z);
extern u32 fn_801E2570(void);
extern u8 framesThisStep;
extern f32 timeDelta;
extern s8 lbl_803DDC2C;
extern f32 lbl_803E56CC;
extern f32 gDBprotPi;
extern f32 gDBprotAngleUnit;
extern f32 lbl_803E57C8;
extern f32 lbl_803E57CC;
extern f32 lbl_803E57D0;
extern f32 lbl_803E57D4;
extern f32 lbl_803E57D8;
extern f32 lbl_803E57DC;
extern f32 lbl_803E57E0;
extern f32 lbl_803E56C8;
extern f32 lbl_803E56D0;
extern f32 lbl_803E56D4;
extern f32 lbl_803E56D8;
extern f32 lbl_803E56DC;
extern f32 lbl_803E56E0;
extern f32 lbl_803E56EC;
extern f32 lbl_803E56F0;
extern f32 lbl_803E56F4;
extern f32 lbl_803E56F8;
extern f32 lbl_803E56FC;
extern f32 lbl_803E5700;
extern f32 lbl_803E5704;
extern f32 lbl_803E5708;
extern f32 lbl_803E570C;
extern f32 lbl_803E5710;
extern f32 lbl_803E5714;
extern f32 lbl_803E5718;
extern f32 lbl_803E571C;
extern f32 lbl_803E5720;
extern f32 lbl_803E5724;
extern f32 lbl_803E5728;
extern f32 lbl_803E572C;
extern f32 lbl_803E5730;
extern f32 lbl_803E5734;
extern f32 lbl_803E5738;
extern f32 lbl_803E573C;
extern f32 lbl_803E5740;
extern f32 lbl_803E5744;
extern f32 lbl_803E5748;
extern f32 lbl_803E574C;
extern f32 lbl_803E5750;
extern f32 lbl_803E5754;
extern f32 lbl_803E5758;
extern f32 lbl_803E575C;
extern f32 lbl_803E5760;
extern f32 lbl_803E5764;
extern f32 lbl_803E5768;
extern f32 lbl_803E576C;
extern f32 lbl_803E5770;
extern f32 lbl_803E5774;
extern f32 lbl_803E5778;
extern f32 lbl_803E577C;
extern f32 lbl_803E5780;
extern f32 lbl_803E5784;
extern f32 lbl_803E5788;
extern f32 lbl_803E578C;
extern f32 lbl_803E5790;
extern f32 lbl_803E5794;
extern f32 lbl_803E5798;
extern f32 lbl_803E579C;
extern f32 lbl_803E57A0;
extern f32 lbl_803E57A4;
extern f32 lbl_803E57A8;
extern f32 lbl_803E57AC;
extern f32 lbl_803E57B0;
extern f32 lbl_803E57B4;
extern f32 lbl_803E57B8;

#define SCREEN_TRANSITION_FADE(kind, value) \
  (*gScreenTransitionInterface)->start((kind), (value))
#define SCREEN_TRANSITION_START(kind, value) \
  (*gScreenTransitionInterface)->step((kind), (value))
#define SCREEN_TRANSITION_READY() \
  (*gScreenTransitionInterface)->isFinished()
#define OBJECT_TRIGGER_REFRESH(eventId, obj, arg) \
  (*gObjectTriggerInterface)->runSequence((eventId), (obj), (arg))
#define CLOUD_ACTION_SET(a, b) \
  (*gCloudActionInterface)->func12Nop((a), (b))
#define CLOUD_ACTION_ENABLE(flag) \
  (*gCloudActionInterface)->func10Nop((flag))
#define DBPROT_CAMERA_SHAKE(amount, arg) \
  (*gCameraInterface)->releaseAction((amount), (arg))
#define DBPROT_MAP_EVENT(layer, a, b) \
  (*gMapEventInterface)->setObjGroupStatus((layer), (a), (b))
#define DBPROT_CLOUD_SET_A(flag) \
  (*gCloudActionInterface)->func10Nop((flag))
#define DBPROT_CLOUD_SET_B(flag) \
  (*gCloudActionInterface)->func11Nop((flag))

void fn_801DFA28(u8* obj)
{
    int spawnData;
    u8* state;
    u8* tricky;
    int objArray;
    int sfxObj;
    u8* otherObj;
    s8 c;
    int t;
    int nextState;
    int wrap;
    u32 angY;
    int iv;
    int dv;
    int rollA;
    int rollB;
    f32 amp;
    f32 limit;
    f32 negLimit;
    f32 blendK;
    f32 lerpD;
    f32 zRatio;
    f32 tx;
    f32 ty;
    f32 tz;
    f32 ambA;
    f32 dy;
    f32 dz;
    f32 dist;
    f32 ambC;
    f32 ambB;
    f32 threshold;
    f32 dx;
    f32 speedTarget;
    f32 zero;
    f32 mtx[17];
    struct
    {
        s16 rot[3];
        f32 scale;
        f32 vec[3];
    } objPos;
    int objIndex;
    int objCount;
    f32 camShake;

    spawnData = *(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    camShake = lbl_803E56C8;
    ((GameObject*)obj)->anim.mapEventSlot = -1;
    if ((*(void**)&((SBGalleonState*)state)->targetObj != NULL) &&
        ((*(s16*)(((SBGalleonState*)state)->targetObj + 6) & 0x40) != 0))
    {
        ((SBGalleonState*)state)->targetObj = NULL;
    }
    if (*(void**)&((SBGalleonState*)state)->targetObj == NULL)
    {
        objArray = ObjList_GetObjects(&objIndex, &objCount);
        for (t = objIndex; t < objCount; t++)
        {
            otherObj = *(u8**)(objArray + t * 4);
            if (((GameObject*)otherObj)->anim.seqId == 0x8C)
            {
                ((SBGalleonState*)state)->targetObj = otherObj;
                t = objCount;
            }
        }
    }
    if (((SBGalleonState*)state)->phase >= 2)
    {
        Sfx_PlayFromObject((int)obj, SFXwp_cahit2_c);
    }
    else
    {
        Sfx_StopFromObject((int)obj, SFXwp_cahit2_c);
    }
    tricky = ((SBGalleonState*)state)->targetObj;
    if (tricky == NULL) goto end;
    if ((tricky != NULL) && (*(int*)(tricky + 0xF4) == 0))
    {
        fn_801EED5C((int)tricky, (f32*)(state + 0x50), (f32*)(state + 0x54), (f32*)(state + 0x58));
    }
    ((SBGalleonState*)state)->timer26 -= framesThisStep;
    if (((SBGalleonState*)state)->timer26 < 0)
    {
        ((SBGalleonState*)state)->timer26 = 0;
    }
    c = ((SBGalleonState*)state)->stage;
    if (c == 7)
    {
        ((SBGalleonState*)state)->damagePhase = 3;
    }
    else if (c == 8)
    {
        ((SBGalleonState*)state)->damagePhase = 4;
    }
    else if (c == 9)
    {
        ((SBGalleonState*)state)->damagePhase = 5;
    }
    if (((SBGalleonState*)state)->phase < 2)
    {
        ((SBGalleonState*)state)->wanderTimerA -= timeDelta;
        if (((SBGalleonState*)state)->wanderTimerA <= lbl_803E56CC)
        {
            ((SBGalleonState*)state)->wanderFlagA ^= 1;
            ((SBGalleonState*)state)->wanderTimerA = (f32)(int)
            randomGetRange(0xB4, 300);
        }
        if (((SBGalleonState*)state)->wanderFlagA != 0)
        {
            ((SBGalleonState*)state)->wanderA = lbl_803E56D0 * timeDelta + ((SBGalleonState*)state)->wanderA;
        }
        else
        {
            ((SBGalleonState*)state)->wanderA -= timeDelta;
        }
        ((SBGalleonState*)state)->wanderTimerB -= timeDelta;
        if (((SBGalleonState*)state)->wanderTimerB <= lbl_803E56CC)
        {
            ((SBGalleonState*)state)->wanderFlagB ^= 1;
            ((SBGalleonState*)state)->wanderTimerB = (f32)(int)
            randomGetRange(0xB4, 300);
        }
        if (((SBGalleonState*)state)->wanderFlagB != 0)
        {
            ((SBGalleonState*)state)->wanderB = lbl_803E56D0 * timeDelta + ((SBGalleonState*)state)->wanderB;
        }
        else
        {
            ((SBGalleonState*)state)->wanderB -= timeDelta;
        }
    }
    else
    {
        amp = lbl_803E56D4;
        ((SBGalleonState*)state)->wanderA = -(amp * timeDelta - ((SBGalleonState*)state)->wanderA);
        ((SBGalleonState*)state)->wanderB = -(amp * timeDelta - ((SBGalleonState*)state)->wanderB);
    }
    dx = ((SBGalleonState*)state)->wanderA;
    ((SBGalleonState*)state)->wanderA = (dx < lbl_803E56CC) ? lbl_803E56CC : (dx > lbl_803E56D8) ? lbl_803E56D8 : dx;
    dx = ((SBGalleonState*)state)->wanderB;
    ((SBGalleonState*)state)->wanderB = (dx < lbl_803E56CC) ? lbl_803E56CC : (dx > lbl_803E56D8) ? lbl_803E56D8 : dx;
    switch (((SBGalleonState*)state)->phase)
    {
    case 0:
        camShake = lbl_803E56C8;
        Sfx_StopObjectChannel((int)obj, 1);
        DBPROT_CAMERA_SHAKE(&camShake, 0);
        ((GameObject*)obj)->unkF4 = 1;
        tx = ((SBGalleonState*)state)->homeX - lbl_803E56DC;
        tz = lbl_803E56E0 * mathCosf((gDBprotPi * (f32)((SBGalleonState*)state)->bobPhase) / gDBprotAngleUnit) +
            ((SBGalleonState*)state)->homeZ;
        ty = lbl_803E56F0 * mathSinf((gDBprotPi * (f32)((SBGalleonState*)state)->bobPhase) / gDBprotAngleUnit) +
            (((SBGalleonState*)state)->homeY - lbl_803E56EC);
        ((SBGalleonState*)state)->bobPhase = ((SBGalleonState*)state)->bobPhase + framesThisStep * 0xB6;
        dx = tx - ((GameObject*)obj)->anim.localPosX;
        dy = ty - ((GameObject*)obj)->anim.localPosY;
        dz = tz - ((GameObject*)obj)->anim.localPosZ;
        ((SBGalleonState*)state)->speed = lbl_803E56F4;
        dx = dx * lbl_803E56F8;
        dy = dy * lbl_803E56F8;
        dz = dz * lbl_803E56F8;
        limit = ((SBGalleonState*)state)->speed;
        if (dx > limit)
        {
            dx = limit;
        }
        negLimit = -limit;
        if (dx < negLimit)
        {
            dx = negLimit;
        }
        if (dy > limit)
        {
            dy = limit;
        }
        if (dy < negLimit)
        {
            dy = negLimit;
        }
        if (dz > limit)
        {
            dz = limit;
        }
        if (dz < negLimit)
        {
            dz = negLimit;
        }
        t = ((SBGalleonState*)state)->phaseTimer;
        if (t < 0x78)
        {
            dy = lbl_803E56CC;
        }
        else if (t < 0xB4)
        {
            dy = dy * ((f32)(t - 0x78) / lbl_803E56F0);
        }
        ((SBGalleonState*)state)->phaseTimer += framesThisStep;
        ((SBGalleonState*)state)->driftX += (dx - ((SBGalleonState*)state)->driftX) * (blendK = lbl_803E56FC);
        ((SBGalleonState*)state)->driftY += (dy - ((SBGalleonState*)state)->driftY) * (blendK = blendK);
        ((SBGalleonState*)state)->driftZ += (dz - ((SBGalleonState*)state)->driftZ) * (blendK = blendK);
        ambA = lbl_803E5700;
        ambB = lbl_803E5704;
        ambC = lbl_803E5708;
        if (((SBGalleonState*)state)->cycleKind == 0)
        {
            switch (((SBGalleonState*)state)->stage)
            {
            case 0:
            case 1:
                if (((SBGalleonState*)state)->headingLatch != 0)
                {
                    ((SBGalleonState*)state)->headingLatch -= 1;
                    if (((SBGalleonState*)state)->headingLatch <= 0)
                    {
                        ((SBGalleonState*)state)->headingLatch = 200;
                    }
                }
                break;
            default:
                ((SBGalleonState*)state)->stage = 2;
                ((SBGalleonState*)state)->phaseTimer = 0;
                ((SBGalleonState*)state)->phase = 1;
                ((SBGalleonState*)state)->cycleKind = 1;
                ((SBGalleonState*)state)->phaseCounter = 0;
                *(s8*)&((SBGalleonState*)state)->flightPattern = 0;
                ((SBGalleonState*)state)->headingLatch = 200;
                GameBit_Set(DBPROTECTION_GAMEBIT_DIVE_ACTIVE, 1);
                break;
            }
        }
        else
        {
            switch (((SBGalleonState*)state)->stage)
            {
            case 3:
            case 4:
                if (((SBGalleonState*)state)->headingLatch != 0)
                {
                    ((SBGalleonState*)state)->headingLatch -= 1;
                    if (((SBGalleonState*)state)->headingLatch <= 0)
                    {
                        ((SBGalleonState*)state)->headingLatch = 200;
                    }
                }
                break;
            default:
                ((SBGalleonState*)state)->stage = 5;
                ((SBGalleonState*)state)->phaseTimer = 0;
                ((SBGalleonState*)state)->phase = 1;
                ((SBGalleonState*)state)->cycleKind = 2;
                *(s8*)&((SBGalleonState*)state)->flightPattern = 0;
                ((SBGalleonState*)state)->headingLatch = 200;
                break;
            }
        }
        break;
    case 1:
        ((GameObject*)obj)->unkF4 = 2;
        camShake = lbl_803E56C8;
        DBPROT_CAMERA_SHAKE(&camShake, 0);
        if (((SBGalleonState*)state)->headingLatch != 0)
        {
            ((SBGalleonState*)state)->headingLatch -= 1;
        }
        switch (*(s8*)&((SBGalleonState*)state)->flightPattern)
        {
        case 0:
            tx = ((SBGalleonState*)state)->homeX - lbl_803E570C;
            tz = ((SBGalleonState*)state)->homeZ;
            ty = lbl_803E56EC + ((GameObject*)tricky)->anim.localPosY;
            if ((((SBGalleonState*)state)->headingLatch <= 0) &&
                ((((SBGalleonState*)state)->phaseCounter == 0) || (((SBGalleonState*)state)->phaseCounter == 5)))
            {
                ((SBGalleonState*)state)->headingLatch = 200;
            }
            Sfx_IsPlayingFromObjectChannel((int)obj, 2); /* called for side-effect; result discarded in target */
            break;
        case 1:
            tx = ((SBGalleonState*)state)->homeX - lbl_803E5710;
            tz = ((SBGalleonState*)state)->homeZ;
            ty = lbl_803E56EC + ((GameObject*)tricky)->anim.localPosY;
            break;
        case 2:
            tx = ((GameObject*)tricky)->anim.localPosX - lbl_803E5714;
            tz = ((SBGalleonState*)state)->homeZ;
            ty = lbl_803E5718 + ((GameObject*)tricky)->anim.localPosY;
            break;
        case 3:
            tx = ((GameObject*)tricky)->anim.localPosX - lbl_803E571C;
            tz = lbl_803E5720 + ((SBGalleonState*)state)->homeZ;
            ty = lbl_803E5718 + ((GameObject*)tricky)->anim.localPosY;
            tz = tz + (((GameObject*)tricky)->anim.localPosZ - ((SBGalleonState*)state)->posZ);
            ((SBGalleonState*)state)->unk7B = 0;
            break;
        case 4:
            tx = ((GameObject*)tricky)->anim.localPosX - lbl_803E571C;
            tz = lbl_803E5724 + ((SBGalleonState*)state)->homeZ;
            ty = lbl_803E5718 + ((GameObject*)tricky)->anim.localPosY;
            ((SBGalleonState*)state)->unk7B = 0;
            break;
        case 5:
            tx = ((GameObject*)tricky)->anim.localPosX - lbl_803E571C;
            tz = ((SBGalleonState*)state)->homeZ - lbl_803E5720;
            ty = lbl_803E5718 + ((GameObject*)tricky)->anim.localPosY;
            tz = tz + (((GameObject*)tricky)->anim.localPosZ - ((SBGalleonState*)state)->posZ);
            ((SBGalleonState*)state)->unk7B = 0;
            break;
        default:
            ((SBGalleonState*)state)->unk7B = 0;
            tx = ((SBGalleonState*)state)->homeX - lbl_803E5728;
            tz = ((SBGalleonState*)state)->homeZ;
            ty = lbl_803E572C + ((GameObject*)tricky)->anim.localPosY;
            break;
        }
        tx = tx - ((GameObject*)obj)->anim.localPosX;
        dy = ty - ((GameObject*)obj)->anim.localPosY;
        tz = tz - ((GameObject*)obj)->anim.localPosZ;
        ((SBGalleonState*)state)->speed = lbl_803E56F4;
        dist = sqrtf(tz * tz + (tx * tx + dy * dy));
        tx = tx * lbl_803E56FC;
        dy = dy * lbl_803E56F8;
        tz = tz * lbl_803E56F8;
        if (tx > lbl_803E5730)
        {
            tx = lbl_803E5730;
        }
        if (tx < lbl_803E5734)
        {
            tx = lbl_803E5734;
        }
        if (dy > lbl_803E5738)
        {
            dy = lbl_803E5738;
        }
        if (dy < lbl_803E573C)
        {
            dy = lbl_803E573C;
        }
        if (tz > lbl_803E5740)
        {
            tz = lbl_803E5740;
        }
        if (tz < lbl_803E5744)
        {
            tz = lbl_803E5744;
        }
        ((SBGalleonState*)state)->phaseTimer += framesThisStep;
        lerpD = tx - ((SBGalleonState*)state)->driftX;
        ((SBGalleonState*)state)->driftX = lerpD * lbl_803E5748 + ((SBGalleonState*)state)->driftX;
        ((SBGalleonState*)state)->driftY += (dy - ((SBGalleonState*)state)->driftY) / lbl_803E574C;
        ((SBGalleonState*)state)->driftZ += (tz - ((SBGalleonState*)state)->driftZ) / lbl_803E5750;
        ambA = lbl_803E5754;
        ambB = lbl_803E5758;
        ambC = lbl_803E56CC;
        switch (*(s8*)&((SBGalleonState*)state)->flightPattern)
        {
        case 0:
            if (dist < lbl_803E575C)
            {
                ((SBGalleonState*)state)->flightPattern = 1;
                ((SBGalleonState*)state)->phaseTimer = 0;
            }
            break;
        case 1:
            if (dist < lbl_803E5708)
            {
                ((SBGalleonState*)state)->flightPattern = 2;
                ((SBGalleonState*)state)->phaseTimer = 0;
            }
            break;
        case 2:
            if ((((SBGalleonState*)state)->phaseTimer > 0xF0) || (dist < lbl_803E5708))
            {
                ((SBGalleonState*)state)->flightPattern = 0;
                ((SBGalleonState*)state)->phaseTimer = 0;
            }
            break;
        case 3:
            if ((dist < lbl_803E5708) || (((SBGalleonState*)state)->phaseTimer > 0x78))
            {
                ((SBGalleonState*)state)->flightPattern = 0;
                ((SBGalleonState*)state)->phaseTimer = 0;
            }
            break;
        case 4:
            if ((dist < lbl_803E5708) || (((SBGalleonState*)state)->phaseTimer > 0x78))
            {
                ((SBGalleonState*)state)->flightPattern = 5;
                ((SBGalleonState*)state)->phaseTimer = 3;
            }
            break;
        case 5:
            if ((dist < lbl_803E5708) || (((SBGalleonState*)state)->phaseTimer > 0x78))
            {
                ((SBGalleonState*)state)->flightPattern = 0;
                ((SBGalleonState*)state)->phaseTimer = 0;
            }
            break;
        default:
            if (dist < lbl_803E5760)
            {
                if (((SBGalleonState*)state)->stage == 2)
                {
                    ((SBGalleonState*)state)->phaseTimer = 0;
                    ((SBGalleonState*)state)->phase = 0;
                    ((SBGalleonState*)state)->stage = 3;
                }
                else if (((SBGalleonState*)state)->stage == 5)
                {
                    ((SBGalleonState*)state)->phase = 2;
                    ((SBGalleonState*)state)->stage = 6;
                }
            }
            break;
        }
        ((SBGalleonState*)state)->timer26 = 300;
        if ((((SBGalleonState*)state)->phaseCounter >= 4) && (((SBGalleonState*)state)->stage < 3))
        {
            ((SBGalleonState*)state)->phase = 0;
            ((SBGalleonState*)state)->cycleKind = 1;
            ((SBGalleonState*)state)->stage = 3;
            ((SBGalleonState*)state)->phaseCounter = 5;
            ((SBGalleonState*)state)->headingLatch = 200;
            sfxObj = fn_801E2570();
            Sfx_StopFromObject(sfxObj, SFXTRIG_swtst1_c);
            Sfx_PlayFromObject(sfxObj, SFXwp_dsmk2_c);
            GameBit_Set(DBPROTECTION_GAMEBIT_DIVE_ACTIVE, 0);
        }
        else if (((SBGalleonState*)state)->phaseCounter >= 4)
        {
            ((SBGalleonState*)state)->phase = 2;
            ((SBGalleonState*)state)->cycleKind = 3;
            ((SBGalleonState*)state)->stage = 6;
            ((SBGalleonState*)state)->headingLatch = 200;
            ((SBGalleonState*)state)->refZ = ((GameObject*)tricky)->anim.localPosZ;
        }
        break;
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
        camShake = lbl_803E56C8;
        Sfx_StopObjectChannel((int)obj, 2);
        DBPROT_CAMERA_SHAKE(&camShake, 0);
        ((GameObject*)obj)->unkF4 = 3;
        if (((SBGalleonState*)state)->headingLatch != 0)
        {
            ((SBGalleonState*)state)->headingLatch -= 1;
        }
        switch (((SBGalleonState*)state)->phase)
        {
        case 2:
            speedTarget = lbl_803E5764;
            tx = ((SBGalleonState*)state)->homeX - lbl_803E5768;
            tz = -(lbl_803E576C * (f32)((SBGalleonState*)state)->sweepDir - ((SBGalleonState*)state)->homeZ);
            ty = ((SBGalleonState*)state)->homeY;
            threshold = lbl_803E5770;
            nextState = 3;
            break;
        case 3:
            speedTarget = lbl_803E5774;
            tx = ((SBGalleonState*)state)->homeX - lbl_803E5778;
            tz = -(lbl_803E5770 * (f32)((SBGalleonState*)state)->sweepDir - ((SBGalleonState*)state)->homeZ);
            ty = lbl_803E5724 + ((SBGalleonState*)state)->homeY;
            nextState = 4;
            threshold = lbl_803E577C;
            break;
        case 4:
            speedTarget = lbl_803E5774;
            tx = ((SBGalleonState*)state)->homeX - lbl_803E5768;
            tz = -(lbl_803E5708 * (f32)((SBGalleonState*)state)->sweepDir - ((SBGalleonState*)state)->homeZ);
            ty = lbl_803E5724 + ((SBGalleonState*)state)->homeY;
            nextState = 5;
            threshold = lbl_803E577C;
            break;
        case 5:
            speedTarget = lbl_803E5708;
            ((GameObject*)obj)->unkF4 = 4;
            tx = ((SBGalleonState*)state)->homeX - lbl_803E5780;
            tz = ((SBGalleonState*)state)->homeZ;
            ty = ((SBGalleonState*)state)->homeY - lbl_803E5724;
            nextState = 6;
            threshold = lbl_803E577C;
            if ((((SBGalleonState*)state)->headingLatch <= 0) && (((SBGalleonState*)state)->stage == 6))
            {
                ((SBGalleonState*)state)->headingLatch = 200;
            }
            break;
        case 6:
            speedTarget = lbl_803E56D0;
            tx = lbl_803E5784 + ((SBGalleonState*)state)->homeX;
            tz = -(lbl_803E576C * (f32)((SBGalleonState*)state)->sweepDir - ((SBGalleonState*)state)->homeZ);
            ty = lbl_803E5718 + ((SBGalleonState*)state)->homeY;
            nextState = 7;
            threshold = lbl_803E5724;
            break;
        case 7:
            speedTarget = lbl_803E56D0;
            tx = lbl_803E5788 + ((SBGalleonState*)state)->homeX;
            tz = ((SBGalleonState*)state)->homeZ;
            ty = lbl_803E578C + ((GameObject*)tricky)->anim.localPosY;
            nextState = 8;
            threshold = lbl_803E5724;
            break;
        case 8:
            speedTarget = lbl_803E5790;
            tx = ((SBGalleonState*)state)->homeX - lbl_803E5794;
            tz = ((SBGalleonState*)state)->homeZ;
            ty = lbl_803E5724 + ((GameObject*)tricky)->anim.localPosY;
            nextState = 2;
            threshold = lbl_803E5784;
            break;
        }
        dx = tx - ((SBGalleonState*)state)->posX;
        dy = ty - ((SBGalleonState*)state)->posY;
        dz = tz - ((SBGalleonState*)state)->posZ;
        ((SBGalleonState*)state)->speed =
            ((SBGalleonState*)state)->speed + (speedTarget - ((SBGalleonState*)state)->speed) / lbl_803E5798;
        dist = sqrtf(dx * dx + dz * dz);
        if ((((SBGalleonState*)state)->phase == 5) && (dist < lbl_803E579C))
        {
            ((GameObject*)obj)->unkF4 = 5;
        }
        if (dist < threshold)
        {
            if (((SBGalleonState*)state)->phase == 5)
            {
                ((SBGalleonState*)state)->sweepDir = -((SBGalleonState*)state)->sweepDir;
            }
            ((SBGalleonState*)state)->phase = nextState;
        }
        wrap = (getAngle(dx, dz) & 0xFFFF) + 0x8000;
        angY = getAngle(dy, dist) & 0xFFFF;
        wrap = wrap - (((GameObject*)obj)->anim.rotX & 0xFFFF);
        if (wrap > 0x8000)
        {
            wrap = wrap - 0xFFFF;
        }
        if (wrap < -0x8000)
        {
            wrap = wrap + 0xFFFF;
        }
        ((SBGalleonState*)state)->turnRate =
            ((SBGalleonState*)state)->turnRate + ((framesThisStep * (wrap - ((SBGalleonState*)state)->turnRate)) >> 4);
        c = ((SBGalleonState*)state)->phase;
        if ((c == 3) || (c == 4))
        {
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + (((SBGalleonState*)state)->turnRate *
                framesThisStep) / 0x3C;
        }
        else if ((c == 6) || (c == 2))
        {
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + (((SBGalleonState*)state)->turnRate *
                framesThisStep) / 0x78;
        }
        else
        {
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + (((SBGalleonState*)state)->turnRate *
                framesThisStep) / 0x3C;
        }
        wrap = angY - (((GameObject*)obj)->anim.rotY & 0xFFFF);
        if (wrap > 0x8000)
        {
            wrap = wrap - 0xFFFF;
        }
        if (wrap < -0x8000)
        {
            wrap = wrap + 0xFFFF;
        }
        ((GameObject*)obj)->anim.rotY = *(s16*)(int)(obj + 0x2) + ((wrap * framesThisStep) >> 6);
        dx = ((SBGalleonState*)state)->homeX - ((GameObject*)obj)->anim.localPosX;
        dz = ((SBGalleonState*)state)->homeZ - ((GameObject*)obj)->anim.localPosZ;
        sqrtf(dx * dx + dz * dz); /* match: dead sqrt present in target */
        t = ((GameObject*)obj)->anim.rotZ;
        iv = (int)(lbl_803E57A0 * (f32)((SBGalleonState*)state)->turnRate);
        dv = (iv - t) >> 3;
        if (dv > 0x3C)
        {
            dv = 0x3C;
        }
        if (dv < -0x3C)
        {
            dv = -0x3C;
        }
        ((GameObject*)obj)->anim.rotZ = dv * timeDelta + (f32) * (s16*)(int)(obj + 0x4);
        objPos.vec[0] = lbl_803E56CC;
        objPos.vec[1] = lbl_803E56CC;
        objPos.vec[2] = lbl_803E56CC;
        objPos.scale = lbl_803E57A4;
        objPos.rot[0] = ((GameObject*)obj)->anim.rotX;
        objPos.rot[1] = *(s16*)(int)(obj + 0x2);
        objPos.rot[2] = *(s16*)(int)(obj + 0x4);
        setMatrixFromObjectPos(mtx, &objPos);
        Matrix_TransformPoint(mtx, lbl_803E56CC, *(f32*)&lbl_803E56CC, -((SBGalleonState*)state)->speed * timeDelta,
                              (f32*)(state + 0x0), (f32*)(state + 0x4), (f32*)(state + 0x8));
        if (((SBGalleonState*)state)->phase == 7)
        {
            ((SBGalleonState*)state)->posX = tx;
            ((SBGalleonState*)state)->posY = ty;
            ((SBGalleonState*)state)->posZ = tz;
            zero = lbl_803E56CC;
            ((SBGalleonState*)state)->swayX = zero;
            ((SBGalleonState*)state)->swayY = zero;
            ((SBGalleonState*)state)->swayZ = zero;
        }
        else
        {
            ((SBGalleonState*)state)->posX = ((SBGalleonState*)state)->posX + ((SBGalleonState*)state)->driftX;
            ((SBGalleonState*)state)->posY = ((SBGalleonState*)state)->posY + ((SBGalleonState*)state)->driftY;
            ((SBGalleonState*)state)->posZ = ((SBGalleonState*)state)->posZ + ((SBGalleonState*)state)->driftZ;
        }
        ambB = lbl_803E57A8;
        ((GameObject*)obj)->anim.localPosX = ((SBGalleonState*)state)->posX + ((SBGalleonState*)state)->swayX;
        ((GameObject*)obj)->anim.localPosY = ((SBGalleonState*)state)->posY + ((SBGalleonState*)state)->swayY;
        ((GameObject*)obj)->anim.localPosZ = ((SBGalleonState*)state)->posZ + ((SBGalleonState*)state)->swayZ +
            (((GameObject*)tricky)->anim.localPosZ - ((SBGalleonState*)state)->refZ);
        if (((SBGalleonState*)state)->stage >= 7)
        {
            if (((SBGalleonState*)state)->fadeTimer == 0)
            {
                ObjHits_DisableObject((int)obj);
                SCREEN_TRANSITION_FADE(0x41, 1);
            }
            ((SBGalleonState*)state)->fadeTimer += framesThisStep;
            if (((SBGalleonState*)state)->fadeTimer > 0x41)
            {
                ((GameObject*)obj)->anim.rotX = 0;
                ((SBGalleonState*)state)->phase = 6;
                DBPROT_CLOUD_SET_A(0);
                DBPROT_CLOUD_SET_B(0);
                CLOUD_ACTION_SET(lbl_803E56CC, lbl_803E5760);
                if (((SBGalleonState*)state)->musicLatch == 0)
                {
                    ((SBGalleonState*)state)->musicLatch = 1;
                }
                ((SBGalleonState*)state)->cameraState = 1;
                ((GameObject*)obj)->anim.localPosX = *(f32*)(spawnData + 0x8);
                ((GameObject*)obj)->anim.localPosY = lbl_803E57AC;
                ((GameObject*)obj)->anim.localPosZ = *(f32*)(spawnData + 0x10);
                Sfx_StopObjectChannel((int)obj, 1);
                DBPROT_MAP_EVENT(*(u8 *)(obj + 0x34), 2, 1);
                OBJECT_TRIGGER_REFRESH(0, obj, -1);
                goto end;
            }
        }
        break;
    default:
        ((GameObject*)obj)->unkF4 = 7;
        break;
    }
    if (((SBGalleonState*)state)->phase < 2)
    {
        ((SBGalleonState*)state)->posX =
            ((SBGalleonState*)state)->moveScale * (((SBGalleonState*)state)->driftX * timeDelta) + ((SBGalleonState*)
                state)->posX;
        ((SBGalleonState*)state)->posY =
            ((SBGalleonState*)state)->moveScale * (((SBGalleonState*)state)->driftY * timeDelta) + ((SBGalleonState*)
                state)->posY;
        ((SBGalleonState*)state)->posZ =
            ((SBGalleonState*)state)->moveScale * (((SBGalleonState*)state)->driftZ * timeDelta) + ((SBGalleonState*)
                state)->posZ;
        ((SBGalleonState*)state)->moveScale += lbl_803E57B0;
        if (((SBGalleonState*)state)->moveScale > lbl_803E57A4)
        {
            ((SBGalleonState*)state)->moveScale = *(f32*)&lbl_803E57A4;
        }
        blendK = lbl_803E57B4;
        ((SBGalleonState*)state)->unk5C += blendK * (timeDelta * (ambA - ((SBGalleonState*)state)->unk5C));
        ((SBGalleonState*)state)->unk60 += blendK * (timeDelta * (ambC - ((SBGalleonState*)state)->unk60));
        ((SBGalleonState*)state)->unk64 += blendK * (timeDelta * (ambB - ((SBGalleonState*)state)->unk64));
        if (((SBGalleonState*)state)->phase == 0)
        {
            zRatio = (f32) * (s16*)(int)(tricky + 0x2) / ((SBGalleonState*)state)->unk5C;
            ((SBGalleonState*)state)->swayZ +=
                timeDelta * (((SBGalleonState*)state)->unk64 *
                    ((f32) - *(s16*)(int)(tricky + 0x4) / ((SBGalleonState*)state)->unk5C - ((SBGalleonState*)state)->
                        swayZ));
            ((SBGalleonState*)state)->swayY +=
                timeDelta * (((SBGalleonState*)state)->unk64 * (zRatio - ((SBGalleonState*)state)->swayY));
            zero = lbl_803E56CC;
            ((SBGalleonState*)state)->swayX = zero;
            ((SBGalleonState*)state)->swayY = zero;
            rollA = (s16)(-((SBGalleonState*)state)->swayZ * ((SBGalleonState*)state)->unk60);
            rollB = (s16)(lbl_803E57B8 * (-((SBGalleonState*)state)->swayY * ((SBGalleonState*)state)->unk60));
        }
        else
        {
            ((SBGalleonState*)state)->swayZ -= timeDelta * (((SBGalleonState*)state)->swayZ * ((SBGalleonState*)state)->
                unk64);
            ((SBGalleonState*)state)->swayY -= timeDelta * (((SBGalleonState*)state)->swayY * ((SBGalleonState*)state)->
                unk64);
            rollA = 0;
            rollB = rollA;
        }
        ((GameObject*)obj)->anim.localPosX = ((SBGalleonState*)state)->swayX * ((SBGalleonState*)state)->moveScale + ((
            SBGalleonState*)state)->posX;
        ((GameObject*)obj)->anim.localPosY = ((SBGalleonState*)state)->swayY * ((SBGalleonState*)state)->moveScale + ((
            SBGalleonState*)state)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((SBGalleonState*)state)->swayZ * ((SBGalleonState*)state)->moveScale + ((
            SBGalleonState*)state)->posZ;
        ((SBGalleonState*)state)->rollLatch =
            ((SBGalleonState*)state)->rollLatch + ((framesThisStep * (rollA - ((SBGalleonState*)state)->rollLatch)) >>
                5);
        ((GameObject*)obj)->anim.rotY =
            ((GameObject*)obj)->anim.rotY + ((framesThisStep * (rollB - ((GameObject*)obj)->anim.rotY)) >> 5);
        ((GameObject*)obj)->anim.rotX = ((SBGalleonState*)state)->rollLatch + 0x4000;
        ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotX - 0x4000;
    }
end:;
}

void DBprotection_updateEnvfxGameBits(u8* state)
{
    int player;
    int effectObj;

    player = Obj_GetPlayerObject();
    if (GameBit_Get(DBPROTECTION_GAMEBIT_CYCLE_A_PENDING) != 0)
    {
        effectObj = ObjList_FindObjectById(DBPROTECTION_ENVFX_B);
        getEnvfxAct(effectObj, player, state[state[0xa4] + 0xa9], 0);
        effectObj = ObjList_FindObjectById(DBPROTECTION_ENVFX_A);
        getEnvfxAct(effectObj, player, state[(state[0xa4] ^ 1) + 0xa7], 0);
        getEnvfxAct(player, player, DBPROTECTION_PLAYER_ENVFX_FLASH, 0);
        GameBit_Set(DBPROTECTION_GAMEBIT_CYCLE_A_PENDING, 0);
        ((SBGalleonState*)state)->envfxCycle = DBPROTECTION_GAMEBIT_CYCLE_A_DONE;
    }

    if (GameBit_Get(DBPROTECTION_GAMEBIT_CYCLE_B_PENDING) != 0)
    {
        effectObj = ObjList_FindObjectById(DBPROTECTION_ENVFX_A);
        getEnvfxAct(effectObj, player, state[state[0xa4] + 0xa9], 0);
        effectObj = ObjList_FindObjectById(DBPROTECTION_ENVFX_B);
        getEnvfxAct(effectObj, player, state[(state[0xa4] ^ 1) + 0xa7], 0);
        getEnvfxAct(player, player, DBPROTECTION_PLAYER_ENVFX_FLASH, 0);
        GameBit_Set(DBPROTECTION_GAMEBIT_CYCLE_B_PENDING, 0);
        ((SBGalleonState*)state)->envfxCycle = DBPROTECTION_GAMEBIT_CYCLE_B_DONE;
    }

    if (GameBit_Get(DBPROTECTION_GAMEBIT_CYCLE_A_DONE) != 0)
    {
        if (((SBGalleonState*)state)->envfxCycle != DBPROTECTION_GAMEBIT_CYCLE_A_DONE)
        {
            state[0xa4] = (u8)(state[0xa4] ^ 1);
        }
        getEnvfxAct(player, player, state[(state[0xa4] ^ 1) + 0xa5], 0);
        getEnvfxAct(player, player, state[state[0xa4] + 0xa9], 0);
        getEnvfxAct(player, player, DBPROTECTION_PLAYER_ENVFX_SWAP, 0);
        GameBit_Set(DBPROTECTION_GAMEBIT_CYCLE_A_DONE, 0);
    }

    if (GameBit_Get(DBPROTECTION_GAMEBIT_CYCLE_B_DONE) != 0)
    {
        if (((SBGalleonState*)state)->envfxCycle != DBPROTECTION_GAMEBIT_CYCLE_B_DONE)
        {
            state[0xa4] = (u8)(state[0xa4] ^ 1);
        }
        getEnvfxAct(player, player, state[(state[0xa4] ^ 1) + 0xa5], 0);
        getEnvfxAct(player, player, state[state[0xa4] + 0xa9], 0);
        getEnvfxAct(player, player, DBPROTECTION_PLAYER_ENVFX_SWAP, 0);
        GameBit_Set(DBPROTECTION_GAMEBIT_CYCLE_B_DONE, 0);
    }
}

int DBprotection_getCameraState(int* obj) { return *(s8*)((char*)(int*)((GameObject*)obj)->extra + 0x70); }

void DBprotection_updateShield(int* obj)
{
    SBGalleonState* state;
    f32 angleCos;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->unkF4 = 7;

    if (GameBit_Get(DBPROTECTION_GAMEBIT_TRANSITION_ARMED) != 0 &&
        GameBit_Get(DBPROTECTION_GAMEBIT_TRANSITION_USED) == 0 &&
        GameBit_Get(DBPROTECTION_GAMEBIT_TRANSITION_READY) != 0)
    {
        lbl_803DDC2C = 1;
        GameBit_Set(DBPROTECTION_GAMEBIT_TRANSITION_USED, 1);
        SCREEN_TRANSITION_FADE(0xa, 1);
    }

    DBprotection_updateEnvfxGameBits((u8*)state);

    if (lbl_803DDC2C != 0 && SCREEN_TRANSITION_READY() != 0)
    {
        SCREEN_TRANSITION_START(0x50, 1);
        OBJECT_TRIGGER_REFRESH(1, obj, -1);
        state->cameraState = 3;
        lbl_803DDC2C = 0;
    }

    CLOUD_ACTION_SET(lbl_803E57C8, lbl_803E56CC);
    CLOUD_ACTION_ENABLE(0);

    angleCos = mathSinf((gDBprotPi * state->shieldAngle) / gDBprotAngleUnit);
    if (state->shieldSfxLatch == 0)
    {
        if (angleCos < lbl_803E57CC)
        {
            if (GameBit_Get(DBPROTECTION_GAMEBIT_MUTE_SFX) == 0)
            {
                Sfx_PlayFromObject((int)obj, SFXwp_crthit6);
            }
            state->shieldSfxLatch = 1;
        }
        else if (angleCos > lbl_803E57D0)
        {
            if (GameBit_Get(DBPROTECTION_GAMEBIT_MUTE_SFX) == 0)
            {
                Sfx_PlayFromObject((int)obj, SFXwp_crtsmsh6);
            }
            state->shieldSfxLatch = 1;
        }
    }
    else if (angleCos > lbl_803E57D4 && angleCos < lbl_803E57D8)
    {
        state->shieldSfxLatch = 0;
    }

    *(u16*)&((GameObject*)obj)->anim.rotZ = lbl_803E57DC * angleCos;
    state->shieldAngle = (u16)(s32)(lbl_803E57E0 * timeDelta + state->shieldAngle);
}

void DBprotection_storeHomePosition(int* obj)
{
    SBGalleonState* state = ((GameObject*)obj)->extra;
    state->posX = ((GameObject*)obj)->anim.localPosX;
    state->posY = ((GameObject*)obj)->anim.localPosY;
    state->posZ = ((GameObject*)obj)->anim.localPosZ;
}
