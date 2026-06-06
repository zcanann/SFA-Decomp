#include "main/audio/sfx_ids.h"
#include "main/dll/DB/DBprotection.h"
#include "main/mapEventTypes.h"
#include "global.h"

/* Per-object extra state for the DB protection spirit (no getExtraSize in
 * this TU; offsets verified by offsetof asserts, tail table left raw). */
typedef struct DBProtectionState {
    f32 driftX;      /* 0x00: wander offset integrated each step */
    f32 driftY;      /* 0x04 */
    f32 driftZ;      /* 0x08 */
    f32 refZ;        /* 0x0c: tricky Z latched at dive start */
    u8 pad10[0xC];
    f32 speed;       /* 0x1c */
    s16 bobPhase;    /* 0x20 */
    s16 rollLatch;   /* 0x22 */
    s16 turnRate;    /* 0x24 */
    s16 timer26;     /* 0x26 */
    s8 cycleKind;    /* 0x28 */
    s8 phase;        /* 0x29 */
    s8 sweepDir;     /* 0x2a */
    s8 stage;        /* 0x2b */
    f32 posX;        /* 0x2c */
    f32 posY;        /* 0x30 */
    f32 posZ;        /* 0x34 */
    f32 swayX;       /* 0x38 */
    f32 swayY;       /* 0x3c */
    f32 swayZ;       /* 0x40 */
    f32 moveScale;   /* 0x44 */
    u8 *targetObj;   /* 0x48 */
    u8 pad4C[4];
    f32 homeX;       /* 0x50 */
    f32 homeY;       /* 0x54 */
    f32 homeZ;       /* 0x58 */
    f32 unk5C;       /* 0x5c */
    f32 unk60;       /* 0x60 */
    f32 unk64;       /* 0x64 */
    u16 shieldAngle; /* 0x68 */
    u8 pad6A[2];
    s16 fadeTimer;   /* 0x6c */
    s16 phaseTimer;  /* 0x6e */
    u8 cameraState;  /* 0x70 */
    u8 pad71[8];
    u8 unk79;        /* 0x79 */
    u8 flightPattern;/* 0x7a */
    u8 unk7B;        /* 0x7b */
    s8 unk7C;        /* 0x7c */
    u8 pad7D[3];
    u8 unk80;        /* 0x80 */
    u8 shieldSfxLatch;/* 0x81 */
    s16 headingLatch;/* 0x82 */
    u8 pad84[4];
    f32 wanderA;     /* 0x88 */
    f32 wanderB;     /* 0x8c */
    f32 wanderTimerA;/* 0x90 */
    f32 wanderTimerB;/* 0x94 */
    u8 pad98[8];
    u8 wanderFlagA;  /* 0xa0 */
    u8 wanderFlagB;  /* 0xa1 */
    u16 envfxCycle;  /* 0xa2 */
    u8 envfxIndex;   /* 0xa4: index into the envfx action table below */
    u8 envfxActs[6]; /* 0xa5..0xaa */
    u8 padAB;
} DBProtectionState;
STATIC_ASSERT(offsetof(DBProtectionState, phase) == 0x29);
STATIC_ASSERT(offsetof(DBProtectionState, targetObj) == 0x48);
STATIC_ASSERT(offsetof(DBProtectionState, shieldAngle) == 0x68);
STATIC_ASSERT(offsetof(DBProtectionState, headingLatch) == 0x82);
STATIC_ASSERT(offsetof(DBProtectionState, envfxActs) == 0xA5);

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

extern undefined4 FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern undefined4 GameBit_Set(int eventId,int value);
extern uint GameBit_Get(int eventId);
extern uint FUN_80017730();
extern undefined4 FUN_80017754();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern int FUN_80017b00();
extern undefined4 ObjHits_DisableObject();
extern uint FUN_801e2184();
extern undefined4 FUN_801ef1e0();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern int Obj_GetPlayerObject(void);
extern int ObjList_FindObjectById(int id);
extern void getEnvfxAct(int effectObj, int playerObj, int action, int unused);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern f32 fn_80293E80(f32 x);

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e6458;
extern f32 lbl_803DC074;
extern f32 timeDelta;
extern f32 lbl_803E6360;
extern f32 lbl_803E6364;
extern f32 lbl_803E6368;
extern f32 lbl_803E636C;
extern f32 lbl_803E6370;
extern f32 lbl_803E6374;
extern f32 lbl_803E6378;
extern f32 lbl_803E6384;
extern f32 lbl_803E6388;
extern f32 lbl_803E638C;
extern f32 lbl_803E6390;
extern f32 lbl_803E6394;
extern f32 lbl_803E6398;
extern f32 lbl_803E639C;
extern f32 lbl_803E63A0;
extern f32 lbl_803E63A4;
extern f32 lbl_803E63A8;
extern f32 lbl_803E63AC;
extern f32 lbl_803E63B0;
extern f32 lbl_803E63B4;
extern f32 lbl_803E63B8;
extern f32 lbl_803E63BC;
extern f32 lbl_803E63C0;
extern f32 lbl_803E63C4;
extern f32 lbl_803E63C8;
extern f32 lbl_803E63CC;
extern f32 lbl_803E63D0;
extern f32 lbl_803E63D4;
extern f32 lbl_803E63D8;
extern f32 lbl_803E63DC;
extern f32 lbl_803E63E0;
extern f32 lbl_803E63E4;
extern f32 lbl_803E63E8;
extern f32 lbl_803E63EC;
extern f32 lbl_803E63F0;
extern f32 lbl_803E63F4;
extern f32 lbl_803E63F8;
extern f32 lbl_803E63FC;
extern f32 lbl_803E6400;
extern f32 lbl_803E6404;
extern f32 lbl_803E6408;
extern f32 lbl_803E640C;
extern f32 lbl_803E6410;
extern f32 lbl_803E6414;
extern f32 lbl_803E6418;
extern f32 lbl_803E641C;
extern f32 lbl_803E6420;
extern f32 lbl_803E6424;
extern f32 lbl_803E6428;
extern f32 lbl_803E642C;
extern f32 lbl_803E6430;
extern f32 lbl_803E6434;
extern f32 lbl_803E6438;
extern f32 lbl_803E643C;
extern f32 lbl_803E6440;
extern f32 lbl_803E6444;
extern f32 lbl_803E6448;
extern f32 lbl_803E644C;
extern f32 lbl_803E6450;
extern s8 lbl_803DDC2C;
extern int *gCloudActionInterface;
extern int *gObjectTriggerInterface;
extern int *gScreenTransitionInterface;
extern f32 lbl_803E56CC;
extern f32 lbl_803E56E4;
extern f32 lbl_803E56E8;
extern f32 lbl_803E57C8;
extern f32 lbl_803E57CC;
extern f32 lbl_803E57D0;
extern f32 lbl_803E57D4;
extern f32 lbl_803E57D8;
extern f32 lbl_803E57DC;
extern f32 lbl_803E57E0;

#define SCREEN_TRANSITION_FADE(kind, value) \
  ((void (*)(int, int))(*(u32 *)((u8 *)*gScreenTransitionInterface + 0x8)))((kind), (value))
#define SCREEN_TRANSITION_START(kind, value) \
  ((void (*)(int, int))(*(u32 *)((u8 *)*gScreenTransitionInterface + 0xc)))((kind), (value))
#define SCREEN_TRANSITION_READY() \
  ((int (*)(void))(*(u32 *)((u8 *)*gScreenTransitionInterface + 0x14)))()
#define OBJECT_TRIGGER_REFRESH(eventId, obj, arg) \
  ((void (*)(int, int *, int))(*(u32 *)((u8 *)*gObjectTriggerInterface + 0x48)))((eventId), (obj), (arg))
#define CLOUD_ACTION_SET(a, b) \
  ((void (*)(f32, f32))(*(u32 *)((u8 *)*gCloudActionInterface + 0x28)))((a), (b))
#define CLOUD_ACTION_ENABLE(flag) \
  ((void (*)(int))(*(u32 *)((u8 *)*gCloudActionInterface + 0x20)))((flag))

/*
 * --INFO--
 *
 * Function: fn_801DFA28
 * EN v1.0 Address: 0x801DFA28
 * EN v1.0 Size: 5732b
 * EN v1.1 Address: 0x801E0018
 * EN v1.1 Size: 6060b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 framesThisStep;
extern int *gCameraInterface;
extern int *gMapEventInterface;
extern f32 sqrtf(f32 x);
extern f32 sin(f32 x);
extern int getAngle(f32 dx, f32 dz);
extern int ObjList_GetObjects(int *startIndex, int *objectCount);
extern void Sfx_StopFromObject(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern void fn_801EED5C(int obj, f32 *x, f32 *y, f32 *z);
extern int fn_801E2570(void);
extern void setMatrixFromObjectPos(f32 *matrix, void *objPos);
extern void Matrix_TransformPoint(f32 *matrix, f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ);

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

#define DBPROT_CAMERA_SHAKE(amount, arg) \
  ((void (*)(f32 *, int))(*(u32 *)((u8 *)*gCameraInterface + 0x60)))((amount), (arg))
#define DBPROT_MAP_EVENT(layer, a, b) \
  ((MapEventInterface *)*gMapEventInterface)->setAnimEvent((layer), (a), (b))
#define DBPROT_SCREEN_FADE(kind, value) \
  ((void (*)(int, int))(*(u32 *)((u8 *)*gScreenTransitionInterface + 0x8)))((kind), (value))
#define DBPROT_CLOUD_SET_A(flag) \
  ((void (*)(int))(*(u32 *)((u8 *)*gCloudActionInterface + 0x20)))((flag))
#define DBPROT_CLOUD_SET_B(flag) \
  ((void (*)(int))(*(u32 *)((u8 *)*gCloudActionInterface + 0x24)))((flag))
#define DBPROT_CLOUD_SET_RANGE(a, b) \
  ((void (*)(f32, f32))(*(u32 *)((u8 *)*gCloudActionInterface + 0x28)))((a), (b))

#pragma scheduling off
#pragma peephole off
void fn_801DFA28(u8 *obj)
{
  u8 *tricky;
  u8 *state;
  int spawnData;
  int objArray;
  int sfxObj;
  u8 *otherObj;
  s8 c;
  int t;
  int nextState;
  int wrap;
  uint angY;
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
  f32 dx;
  f32 dy;
  f32 dz;
  f32 dist;
  f32 speedTarget;
  f32 threshold;
  f32 ambA;
  f32 ambB;
  f32 ambC;
  f32 zero;
  f32 mtx[17];
  struct {
    s16 rot[3];
    f32 scale;
    f32 vec[3];
  } objPos;
  int objIndex;
  int objCount;
  f32 camShake;

  spawnData = *(int *)(obj + 0x4C);
  state = *(u8 **)(obj + 0xB8);
  camShake = lbl_803E56C8;
  *(s8 *)(obj + 0xAC) = -1;
  if ((*(void **)&((DBProtectionState *)state)->targetObj != NULL) &&
      ((*(s16 *)(((DBProtectionState *)state)->targetObj + 6) & 0x40) != 0)) {
    ((DBProtectionState *)state)->targetObj = NULL;
  }
  if (*(void **)&((DBProtectionState *)state)->targetObj == NULL) {
    objArray = ObjList_GetObjects(&objIndex, &objCount);
    for (t = objIndex; t < objCount; t++) {
      otherObj = *(u8 **)(objArray + t * 4);
      if (*(s16 *)(otherObj + 0x46) == 0x8C) {
        ((DBProtectionState *)state)->targetObj = otherObj;
        t = objCount;
      }
    }
  }
  if (((DBProtectionState *)state)->phase >= 2) {
    Sfx_PlayFromObject((int)obj, SFXwp_cahit2_c);
  }
  else {
    Sfx_StopFromObject((int)obj, SFXwp_cahit2_c);
  }
  tricky = ((DBProtectionState *)state)->targetObj;
  if (tricky == NULL) goto end;
  if ((tricky != NULL) && (*(int *)(tricky + 0xF4) == 0)) {
    fn_801EED5C((int)tricky, (f32 *)(state + 0x50), (f32 *)(state + 0x54), (f32 *)(state + 0x58));
  }
  ((DBProtectionState *)state)->timer26 -= framesThisStep;
  if (((DBProtectionState *)state)->timer26 < 0) {
    ((DBProtectionState *)state)->timer26 = 0;
  }
  c = ((DBProtectionState *)state)->stage;
  if (c == 7) {
    ((DBProtectionState *)state)->unk79 = 3;
  }
  else if (c == 8) {
    ((DBProtectionState *)state)->unk79 = 4;
  }
  else if (c == 9) {
    ((DBProtectionState *)state)->unk79 = 5;
  }
  if (((DBProtectionState *)state)->phase < 2) {
    ((DBProtectionState *)state)->wanderTimerA -= timeDelta;
    if (((DBProtectionState *)state)->wanderTimerA <= lbl_803E56CC) {
      ((DBProtectionState *)state)->wanderFlagA ^= 1;
      ((DBProtectionState *)state)->wanderTimerA = (f32)(int)randomGetRange(0xB4, 300);
    }
    if (((DBProtectionState *)state)->wanderFlagA != 0) {
      ((DBProtectionState *)state)->wanderA = lbl_803E56D0 * timeDelta + ((DBProtectionState *)state)->wanderA;
    }
    else {
      ((DBProtectionState *)state)->wanderA -= timeDelta;
    }
    ((DBProtectionState *)state)->wanderTimerB -= timeDelta;
    if (((DBProtectionState *)state)->wanderTimerB <= lbl_803E56CC) {
      ((DBProtectionState *)state)->wanderFlagB ^= 1;
      ((DBProtectionState *)state)->wanderTimerB = (f32)(int)randomGetRange(0xB4, 300);
    }
    if (((DBProtectionState *)state)->wanderFlagB != 0) {
      ((DBProtectionState *)state)->wanderB = lbl_803E56D0 * timeDelta + ((DBProtectionState *)state)->wanderB;
    }
    else {
      ((DBProtectionState *)state)->wanderB -= timeDelta;
    }
  }
  else {
    amp = lbl_803E56D4;
    ((DBProtectionState *)state)->wanderA = -(amp * timeDelta - ((DBProtectionState *)state)->wanderA);
    ((DBProtectionState *)state)->wanderB = -(amp * timeDelta - ((DBProtectionState *)state)->wanderB);
  }
  dx = ((DBProtectionState *)state)->wanderA;
  ((DBProtectionState *)state)->wanderA = (dx < lbl_803E56CC) ? lbl_803E56CC : (dx > lbl_803E56D8) ? lbl_803E56D8 : dx;
  dx = ((DBProtectionState *)state)->wanderB;
  ((DBProtectionState *)state)->wanderB = (dx < lbl_803E56CC) ? lbl_803E56CC : (dx > lbl_803E56D8) ? lbl_803E56D8 : dx;
  switch (((DBProtectionState *)state)->phase) {
  case 0:
    camShake = lbl_803E56C8;
    Sfx_StopObjectChannel((int)obj, 1);
    DBPROT_CAMERA_SHAKE(&camShake, 0);
    *(int *)(obj + 0xF4) = 1;
    tx = *(f32 *)(state + 0x50) - lbl_803E56DC;
    tz = lbl_803E56E0 * sin((lbl_803E56E4 * (f32)((DBProtectionState *)state)->bobPhase) / lbl_803E56E8) +
         *(f32 *)(state + 0x58);
    ty = lbl_803E56F0 * fn_80293E80((lbl_803E56E4 * (f32)((DBProtectionState *)state)->bobPhase) / lbl_803E56E8) +
         (*(f32 *)(state + 0x54) - lbl_803E56EC);
    ((DBProtectionState *)state)->bobPhase = ((DBProtectionState *)state)->bobPhase + framesThisStep * 0xB6;
    dx = tx - *(f32 *)(obj + 0xC);
    dy = ty - *(f32 *)(obj + 0x10);
    dz = tz - *(f32 *)(obj + 0x14);
    ((DBProtectionState *)state)->speed = lbl_803E56F4;
    dx = dx * lbl_803E56F8;
    dy = dy * lbl_803E56F8;
    dz = dz * lbl_803E56F8;
    limit = ((DBProtectionState *)state)->speed;
    if (dx > limit) {
      dx = limit;
    }
    negLimit = -limit;
    if (dx < negLimit) {
      dx = negLimit;
    }
    if (dy > limit) {
      dy = limit;
    }
    if (dy < negLimit) {
      dy = negLimit;
    }
    if (dz > limit) {
      dz = limit;
    }
    if (dz < negLimit) {
      dz = negLimit;
    }
    t = ((DBProtectionState *)state)->phaseTimer;
    if (t < 0x78) {
      dy = lbl_803E56CC;
    }
    else if (t < 0xB4) {
      dy = dy * ((f32)(t - 0x78) / lbl_803E56F0);
    }
    ((DBProtectionState *)state)->phaseTimer += framesThisStep;
    *(f32 *)(state + 0x0) += (dx - *(f32 *)(state + 0x0)) * (blendK = lbl_803E56FC);
    *(f32 *)(state + 0x4) += (dy - *(f32 *)(state + 0x4)) * blendK;
    *(f32 *)(state + 0x8) += (dz - *(f32 *)(state + 0x8)) * blendK;
    ambA = lbl_803E5700;
    ambB = lbl_803E5704;
    ambC = lbl_803E5708;
    if (((DBProtectionState *)state)->cycleKind == 0) {
      if ((((DBProtectionState *)state)->stage < 2) && (((DBProtectionState *)state)->stage >= 0)) {
        if (((DBProtectionState *)state)->headingLatch != 0) {
          ((DBProtectionState *)state)->headingLatch -= 1;
          if (((DBProtectionState *)state)->headingLatch <= 0) {
            ((DBProtectionState *)state)->headingLatch = 200;
          }
        }
      }
      else {
        ((DBProtectionState *)state)->stage = 2;
        ((DBProtectionState *)state)->phaseTimer = 0;
        ((DBProtectionState *)state)->phase = 1;
        ((DBProtectionState *)state)->cycleKind = 1;
        ((DBProtectionState *)state)->unk7C = 0;
        *(s8 *)&((DBProtectionState *)state)->flightPattern = 0;
        ((DBProtectionState *)state)->headingLatch = 200;
        GameBit_Set(0xF1E, 1);
      }
    }
    else {
      if ((((DBProtectionState *)state)->stage < 5) && (((DBProtectionState *)state)->stage >= 3)) {
        if (((DBProtectionState *)state)->headingLatch != 0) {
          ((DBProtectionState *)state)->headingLatch -= 1;
          if (((DBProtectionState *)state)->headingLatch <= 0) {
            ((DBProtectionState *)state)->headingLatch = 200;
          }
        }
      }
      else {
        ((DBProtectionState *)state)->stage = 5;
        ((DBProtectionState *)state)->phaseTimer = 0;
        ((DBProtectionState *)state)->phase = 1;
        ((DBProtectionState *)state)->cycleKind = 2;
        *(s8 *)&((DBProtectionState *)state)->flightPattern = 0;
        ((DBProtectionState *)state)->headingLatch = 200;
      }
    }
    break;
  case 1:
    *(int *)(obj + 0xF4) = 2;
    camShake = lbl_803E56C8;
    DBPROT_CAMERA_SHAKE(&camShake, 0);
    if (((DBProtectionState *)state)->headingLatch != 0) {
      ((DBProtectionState *)state)->headingLatch -= 1;
    }
    switch (*(s8 *)&((DBProtectionState *)state)->flightPattern) {
    case 0:
      tx = *(f32 *)(state + 0x50) - lbl_803E570C;
      tz = *(f32 *)(state + 0x58);
      ty = lbl_803E56EC + *(f32 *)(tricky + 0x10);
      if ((((DBProtectionState *)state)->headingLatch <= 0) &&
          ((((DBProtectionState *)state)->unk7C == 0) || (((DBProtectionState *)state)->unk7C == 5))) {
        ((DBProtectionState *)state)->headingLatch = 200;
      }
      Sfx_IsPlayingFromObjectChannel((int)obj, 2);
      break;
    case 1:
      tx = *(f32 *)(state + 0x50) - lbl_803E5710;
      tz = *(f32 *)(state + 0x58);
      ty = lbl_803E56EC + *(f32 *)(tricky + 0x10);
      break;
    case 2:
      tx = *(f32 *)(tricky + 0xC) - lbl_803E5714;
      tz = *(f32 *)(state + 0x58);
      ty = lbl_803E5718 + *(f32 *)(tricky + 0x10);
      break;
    case 3:
      tx = *(f32 *)(tricky + 0xC) - lbl_803E571C;
      tz = lbl_803E5720 + *(f32 *)(state + 0x58);
      ty = lbl_803E5718 + *(f32 *)(tricky + 0x10);
      tz = tz + (*(f32 *)(tricky + 0x14) - ((DBProtectionState *)state)->posZ);
      ((DBProtectionState *)state)->unk7B = 0;
      break;
    case 4:
      tx = *(f32 *)(tricky + 0xC) - lbl_803E571C;
      tz = lbl_803E5724 + *(f32 *)(state + 0x58);
      ty = lbl_803E5718 + *(f32 *)(tricky + 0x10);
      ((DBProtectionState *)state)->unk7B = 0;
      break;
    case 5:
      tx = *(f32 *)(tricky + 0xC) - lbl_803E571C;
      tz = *(f32 *)(state + 0x58) - lbl_803E5720;
      ty = lbl_803E5718 + *(f32 *)(tricky + 0x10);
      tz = tz + (*(f32 *)(tricky + 0x14) - ((DBProtectionState *)state)->posZ);
      ((DBProtectionState *)state)->unk7B = 0;
      break;
    default:
      ((DBProtectionState *)state)->unk7B = 0;
      tx = *(f32 *)(state + 0x50) - lbl_803E5728;
      tz = *(f32 *)(state + 0x58);
      ty = lbl_803E572C + *(f32 *)(tricky + 0x10);
      break;
    }
    tx = tx - *(f32 *)(obj + 0xC);
    dy = ty - *(f32 *)(obj + 0x10);
    tz = tz - *(f32 *)(obj + 0x14);
    ((DBProtectionState *)state)->speed = lbl_803E56F4;
    dist = sqrtf(tz * tz + (tx * tx + dy * dy));
    tx = tx * lbl_803E56FC;
    dy = dy * lbl_803E56F8;
    tz = tz * lbl_803E56F8;
    if (tx > lbl_803E5730) {
      tx = lbl_803E5730;
    }
    if (tx < lbl_803E5734) {
      tx = lbl_803E5734;
    }
    if (dy > lbl_803E5738) {
      dy = lbl_803E5738;
    }
    if (dy < lbl_803E573C) {
      dy = lbl_803E573C;
    }
    if (tz > lbl_803E5740) {
      tz = lbl_803E5740;
    }
    if (tz < lbl_803E5744) {
      tz = lbl_803E5744;
    }
    ((DBProtectionState *)state)->phaseTimer += framesThisStep;
    lerpD = tx - *(f32 *)(state + 0x0);
    *(f32 *)(state + 0x0) = lerpD * lbl_803E5748 + *(f32 *)(state + 0x0);
    *(f32 *)(state + 0x4) += (dy - *(f32 *)(state + 0x4)) / lbl_803E574C;
    *(f32 *)(state + 0x8) += (tz - *(f32 *)(state + 0x8)) / lbl_803E5750;
    ambA = lbl_803E5754;
    ambB = lbl_803E5758;
    ambC = lbl_803E56CC;
    switch (*(s8 *)&((DBProtectionState *)state)->flightPattern) {
    case 0:
      if (dist < lbl_803E575C) {
        ((DBProtectionState *)state)->flightPattern = 1;
        ((DBProtectionState *)state)->phaseTimer = 0;
      }
      break;
    case 1:
      if (dist < lbl_803E5708) {
        ((DBProtectionState *)state)->flightPattern = 2;
        ((DBProtectionState *)state)->phaseTimer = 0;
      }
      break;
    case 2:
      if ((((DBProtectionState *)state)->phaseTimer > 0xF0) || (dist < lbl_803E5708)) {
        ((DBProtectionState *)state)->flightPattern = 0;
        ((DBProtectionState *)state)->phaseTimer = 0;
      }
      break;
    case 3:
      if ((dist < lbl_803E5708) || (((DBProtectionState *)state)->phaseTimer > 0x78)) {
        ((DBProtectionState *)state)->flightPattern = 0;
        ((DBProtectionState *)state)->phaseTimer = 0;
      }
      break;
    case 4:
      if ((dist < lbl_803E5708) || (((DBProtectionState *)state)->phaseTimer > 0x78)) {
        ((DBProtectionState *)state)->flightPattern = 5;
        ((DBProtectionState *)state)->phaseTimer = 3;
      }
      break;
    case 5:
      if ((dist < lbl_803E5708) || (((DBProtectionState *)state)->phaseTimer > 0x78)) {
        ((DBProtectionState *)state)->flightPattern = 0;
        ((DBProtectionState *)state)->phaseTimer = 0;
      }
      break;
    default:
      if (dist < lbl_803E5760) {
        if (((DBProtectionState *)state)->stage == 2) {
          ((DBProtectionState *)state)->phaseTimer = 0;
          ((DBProtectionState *)state)->phase = 0;
          ((DBProtectionState *)state)->stage = 3;
        }
        else if (((DBProtectionState *)state)->stage == 5) {
          ((DBProtectionState *)state)->phase = 2;
          ((DBProtectionState *)state)->stage = 6;
        }
      }
      break;
    }
    ((DBProtectionState *)state)->timer26 = 300;
    if ((((DBProtectionState *)state)->unk7C >= 4) && (((DBProtectionState *)state)->stage < 3)) {
      ((DBProtectionState *)state)->phase = 0;
      ((DBProtectionState *)state)->cycleKind = 1;
      ((DBProtectionState *)state)->stage = 3;
      ((DBProtectionState *)state)->unk7C = 5;
      ((DBProtectionState *)state)->headingLatch = 200;
      sfxObj = fn_801E2570();
      Sfx_StopFromObject(sfxObj, 0x2C6);
      Sfx_PlayFromObject(sfxObj, SFXwp_dsmk2_c);
      GameBit_Set(0xF1E, 0);
    }
    else if (((DBProtectionState *)state)->unk7C >= 4) {
      ((DBProtectionState *)state)->phase = 2;
      ((DBProtectionState *)state)->cycleKind = 3;
      ((DBProtectionState *)state)->stage = 6;
      ((DBProtectionState *)state)->headingLatch = 200;
      ((DBProtectionState *)state)->refZ = *(f32 *)(tricky + 0x14);
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
    *(int *)(obj + 0xF4) = 3;
    if (((DBProtectionState *)state)->headingLatch != 0) {
      ((DBProtectionState *)state)->headingLatch -= 1;
    }
    switch (((DBProtectionState *)state)->phase) {
    case 2:
      speedTarget = lbl_803E5764;
      tx = *(f32 *)(state + 0x50) - lbl_803E5768;
      tz = -(lbl_803E576C * (f32)((DBProtectionState *)state)->sweepDir - *(f32 *)(state + 0x58));
      ty = *(f32 *)(state + 0x54);
      threshold = lbl_803E5770;
      nextState = 3;
      break;
    case 3:
      speedTarget = lbl_803E5774;
      tx = *(f32 *)(state + 0x50) - lbl_803E5778;
      tz = -(lbl_803E5770 * (f32)((DBProtectionState *)state)->sweepDir - *(f32 *)(state + 0x58));
      ty = lbl_803E5724 + *(f32 *)(state + 0x54);
      nextState = 4;
      threshold = lbl_803E577C;
      break;
    case 4:
      speedTarget = lbl_803E5774;
      tx = *(f32 *)(state + 0x50) - lbl_803E5768;
      tz = -(lbl_803E5708 * (f32)((DBProtectionState *)state)->sweepDir - *(f32 *)(state + 0x58));
      ty = lbl_803E5724 + *(f32 *)(state + 0x54);
      nextState = 5;
      threshold = lbl_803E577C;
      break;
    case 5:
      speedTarget = lbl_803E5708;
      *(int *)(obj + 0xF4) = 4;
      tx = *(f32 *)(state + 0x50) - lbl_803E5780;
      tz = *(f32 *)(state + 0x58);
      ty = *(f32 *)(state + 0x54) - lbl_803E5724;
      nextState = 6;
      threshold = lbl_803E577C;
      if ((((DBProtectionState *)state)->headingLatch <= 0) && (((DBProtectionState *)state)->stage == 6)) {
        ((DBProtectionState *)state)->headingLatch = 200;
      }
      break;
    case 6:
      speedTarget = lbl_803E56D0;
      tx = lbl_803E5784 + *(f32 *)(state + 0x50);
      tz = -(lbl_803E576C * (f32)((DBProtectionState *)state)->sweepDir - *(f32 *)(state + 0x58));
      ty = lbl_803E5718 + *(f32 *)(state + 0x54);
      nextState = 7;
      threshold = lbl_803E5724;
      break;
    case 7:
      speedTarget = lbl_803E56D0;
      tx = lbl_803E5788 + *(f32 *)(state + 0x50);
      tz = *(f32 *)(state + 0x58);
      ty = lbl_803E578C + *(f32 *)(tricky + 0x10);
      nextState = 8;
      threshold = lbl_803E5724;
      break;
    case 8:
      speedTarget = lbl_803E5790;
      tx = *(f32 *)(state + 0x50) - lbl_803E5794;
      tz = *(f32 *)(state + 0x58);
      ty = lbl_803E5724 + *(f32 *)(tricky + 0x10);
      nextState = 2;
      threshold = lbl_803E5784;
      break;
    }
    dx = tx - ((DBProtectionState *)state)->posX;
    dy = ty - ((DBProtectionState *)state)->posY;
    dz = tz - ((DBProtectionState *)state)->posZ;
    ((DBProtectionState *)state)->speed =
        ((DBProtectionState *)state)->speed + (speedTarget - ((DBProtectionState *)state)->speed) / lbl_803E5798;
    dist = sqrtf(dx * dx + dz * dz);
    if ((((DBProtectionState *)state)->phase == 5) && (dist < lbl_803E579C)) {
      *(int *)(obj + 0xF4) = 5;
    }
    if (dist < threshold) {
      if (((DBProtectionState *)state)->phase == 5) {
        ((DBProtectionState *)state)->sweepDir = -((DBProtectionState *)state)->sweepDir;
      }
      ((DBProtectionState *)state)->phase = (s8)nextState;
    }
    wrap = (getAngle(dx, dz) & 0xFFFF) + 0x8000;
    angY = getAngle(dy, dist) & 0xFFFF;
    wrap = wrap - (*(s16 *)(obj + 0x0) & 0xFFFF);
    if (wrap > 0x8000) {
      wrap = wrap - 0xFFFF;
    }
    if (wrap < -0x8000) {
      wrap = wrap + 0xFFFF;
    }
    ((DBProtectionState *)state)->turnRate =
        ((DBProtectionState *)state)->turnRate + ((framesThisStep * (wrap - ((DBProtectionState *)state)->turnRate)) >> 4);
    c = ((DBProtectionState *)state)->phase;
    if ((c == 3) || (c == 4)) {
      *(s16 *)(obj + 0x0) = *(s16 *)(obj + 0x0) + (((DBProtectionState *)state)->turnRate * framesThisStep) / 0x3C;
    }
    else if ((c == 6) || (c == 2)) {
      *(s16 *)(obj + 0x0) = *(s16 *)(obj + 0x0) + (((DBProtectionState *)state)->turnRate * framesThisStep) / 0x78;
    }
    else {
      *(s16 *)(obj + 0x0) = *(s16 *)(obj + 0x0) + (((DBProtectionState *)state)->turnRate * framesThisStep) / 0x3C;
    }
    wrap = angY - (*(s16 *)(obj + 0x2) & 0xFFFF);
    if (wrap > 0x8000) {
      wrap = wrap - 0xFFFF;
    }
    if (wrap < -0x8000) {
      wrap = wrap + 0xFFFF;
    }
    *(s16 *)(obj + 0x2) = *(s16 *)(int)(obj + 0x2) + ((wrap * framesThisStep) >> 6);
    dx = *(f32 *)(state + 0x50) - *(f32 *)(obj + 0xC);
    dz = *(f32 *)(state + 0x58) - *(f32 *)(obj + 0x14);
    sqrtf(dx * dx + dz * dz);
    t = *(s16 *)(obj + 0x4);
    iv = (int)(lbl_803E57A0 * (f32)((DBProtectionState *)state)->turnRate);
    dv = (iv - t) >> 3;
    if (dv > 0x3C) {
      dv = 0x3C;
    }
    if (dv < -0x3C) {
      dv = -0x3C;
    }
    *(s16 *)(obj + 0x4) = (f32)dv * timeDelta + (f32)*(s16 *)(int)(obj + 0x4);
    objPos.vec[0] = lbl_803E56CC;
    objPos.vec[1] = lbl_803E56CC;
    objPos.vec[2] = lbl_803E56CC;
    objPos.scale = lbl_803E57A4;
    objPos.rot[0] = *(s16 *)(obj + 0x0);
    objPos.rot[1] = *(s16 *)(int)(obj + 0x2);
    objPos.rot[2] = *(s16 *)(int)(obj + 0x4);
    setMatrixFromObjectPos(mtx, &objPos);
    Matrix_TransformPoint(mtx, lbl_803E56CC, *(f32 *)&lbl_803E56CC, -((DBProtectionState *)state)->speed * timeDelta,
                          (f32 *)(state + 0x0), (f32 *)(state + 0x4), (f32 *)(state + 0x8));
    if (((DBProtectionState *)state)->phase == 7) {
      ((DBProtectionState *)state)->posX = tx;
      ((DBProtectionState *)state)->posY = ty;
      ((DBProtectionState *)state)->posZ = tz;
      zero = lbl_803E56CC;
      ((DBProtectionState *)state)->swayX = zero;
      ((DBProtectionState *)state)->swayY = zero;
      ((DBProtectionState *)state)->swayZ = zero;
    }
    else {
      ((DBProtectionState *)state)->posX = ((DBProtectionState *)state)->posX + *(f32 *)(state + 0x0);
      ((DBProtectionState *)state)->posY = ((DBProtectionState *)state)->posY + *(f32 *)(state + 0x4);
      ((DBProtectionState *)state)->posZ = ((DBProtectionState *)state)->posZ + *(f32 *)(state + 0x8);
    }
    ambB = lbl_803E57A8;
    *(f32 *)(obj + 0xC) = ((DBProtectionState *)state)->posX + ((DBProtectionState *)state)->swayX;
    *(f32 *)(obj + 0x10) = ((DBProtectionState *)state)->posY + ((DBProtectionState *)state)->swayY;
    *(f32 *)(obj + 0x14) = ((DBProtectionState *)state)->posZ + ((DBProtectionState *)state)->swayZ +
                           (*(f32 *)(tricky + 0x14) - ((DBProtectionState *)state)->refZ);
    if (((DBProtectionState *)state)->stage >= 7) {
      if (((DBProtectionState *)state)->fadeTimer == 0) {
        ObjHits_DisableObject(obj);
        DBPROT_SCREEN_FADE(0x41, 1);
      }
      ((DBProtectionState *)state)->fadeTimer += framesThisStep;
      if (((DBProtectionState *)state)->fadeTimer > 0x41) {
        *(s16 *)(obj + 0x0) = 0;
        ((DBProtectionState *)state)->phase = 6;
        DBPROT_CLOUD_SET_A(0);
        DBPROT_CLOUD_SET_B(0);
        DBPROT_CLOUD_SET_RANGE(lbl_803E56CC, lbl_803E5760);
        if (((DBProtectionState *)state)->unk80 == 0) {
          ((DBProtectionState *)state)->unk80 = 1;
        }
        ((DBProtectionState *)state)->cameraState = 1;
        *(f32 *)(obj + 0xC) = *(f32 *)(spawnData + 0x8);
        *(f32 *)(obj + 0x10) = lbl_803E57AC;
        *(f32 *)(obj + 0x14) = *(f32 *)(spawnData + 0x10);
        Sfx_StopObjectChannel((int)obj, 1);
        DBPROT_MAP_EVENT(*(u8 *)(obj + 0x34), 2, 1);
        OBJECT_TRIGGER_REFRESH(0, (int *)obj, -1);
        goto end;
      }
    }
    break;
  default:
    *(int *)(obj + 0xF4) = 7;
    break;
  }
  if (((DBProtectionState *)state)->phase < 2) {
    ((DBProtectionState *)state)->posX =
        ((DBProtectionState *)state)->moveScale * (*(f32 *)(state + 0x0) * timeDelta) + ((DBProtectionState *)state)->posX;
    ((DBProtectionState *)state)->posY =
        ((DBProtectionState *)state)->moveScale * (*(f32 *)(state + 0x4) * timeDelta) + ((DBProtectionState *)state)->posY;
    ((DBProtectionState *)state)->posZ =
        ((DBProtectionState *)state)->moveScale * (*(f32 *)(state + 0x8) * timeDelta) + ((DBProtectionState *)state)->posZ;
    ((DBProtectionState *)state)->moveScale += lbl_803E57B0;
    if (((DBProtectionState *)state)->moveScale > lbl_803E57A4) {
      ((DBProtectionState *)state)->moveScale = lbl_803E57A4;
    }
    blendK = lbl_803E57B4;
    ((DBProtectionState *)state)->unk5C += blendK * (timeDelta * (ambA - ((DBProtectionState *)state)->unk5C));
    ((DBProtectionState *)state)->unk60 += blendK * (timeDelta * (ambC - ((DBProtectionState *)state)->unk60));
    ((DBProtectionState *)state)->unk64 += blendK * (timeDelta * (ambB - ((DBProtectionState *)state)->unk64));
    if (((DBProtectionState *)state)->phase == 0) {
      zRatio = (f32)*(s16 *)(int)(tricky + 0x2) / ((DBProtectionState *)state)->unk5C;
      ((DBProtectionState *)state)->swayZ +=
          timeDelta * (((DBProtectionState *)state)->unk64 *
                       ((f32)-*(s16 *)(int)(tricky + 0x4) / ((DBProtectionState *)state)->unk5C - ((DBProtectionState *)state)->swayZ));
      ((DBProtectionState *)state)->swayY +=
          timeDelta * (((DBProtectionState *)state)->unk64 * (zRatio - ((DBProtectionState *)state)->swayY));
      zero = lbl_803E56CC;
      ((DBProtectionState *)state)->swayX = zero;
      ((DBProtectionState *)state)->swayY = zero;
      rollA = (s16)(-((DBProtectionState *)state)->swayZ * ((DBProtectionState *)state)->unk60);
      rollB = (s16)(lbl_803E57B8 * (-((DBProtectionState *)state)->swayY * ((DBProtectionState *)state)->unk60));
    }
    else {
      ((DBProtectionState *)state)->swayZ -= timeDelta * (((DBProtectionState *)state)->swayZ * ((DBProtectionState *)state)->unk64);
      ((DBProtectionState *)state)->swayY -= timeDelta * (((DBProtectionState *)state)->swayY * ((DBProtectionState *)state)->unk64);
      rollA = 0;
      rollB = rollA;
    }
    *(f32 *)(obj + 0xC) = ((DBProtectionState *)state)->swayX * ((DBProtectionState *)state)->moveScale + ((DBProtectionState *)state)->posX;
    *(f32 *)(obj + 0x10) = ((DBProtectionState *)state)->swayY * ((DBProtectionState *)state)->moveScale + ((DBProtectionState *)state)->posY;
    *(f32 *)(obj + 0x14) = ((DBProtectionState *)state)->swayZ * ((DBProtectionState *)state)->moveScale + ((DBProtectionState *)state)->posZ;
    ((DBProtectionState *)state)->rollLatch =
        ((DBProtectionState *)state)->rollLatch + ((framesThisStep * (rollA - ((DBProtectionState *)state)->rollLatch)) >> 5);
    *(s16 *)(obj + 0x2) =
        *(s16 *)(obj + 0x2) + ((framesThisStep * (rollB - *(s16 *)(obj + 0x2))) >> 5);
    *(s16 *)(obj + 0x0) = ((DBProtectionState *)state)->rollLatch + 0x4000;
    *(s16 *)(obj + 0x4) = *(s16 *)(obj + 0x0) - 0x4000;
  }
end:;
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off


void DBprotection_updateEnvfxGameBits(u8 *state)
{
  int player;
  int effectObj;

  player = Obj_GetPlayerObject();
  if (GameBit_Get(DBPROTECTION_GAMEBIT_CYCLE_A_PENDING) != 0) {
    effectObj = ObjList_FindObjectById(DBPROTECTION_ENVFX_B);
    getEnvfxAct(effectObj, player, state[state[0xa4] + 0xa9], 0);
    effectObj = ObjList_FindObjectById(DBPROTECTION_ENVFX_A);
    getEnvfxAct(effectObj, player, state[(state[0xa4] ^ 1) + 0xa7], 0);
    getEnvfxAct(player, player, DBPROTECTION_PLAYER_ENVFX_FLASH, 0);
    GameBit_Set(DBPROTECTION_GAMEBIT_CYCLE_A_PENDING, 0);
    *(u16 *)(state + 0xa2) = DBPROTECTION_GAMEBIT_CYCLE_A_DONE;
  }

  if (GameBit_Get(DBPROTECTION_GAMEBIT_CYCLE_B_PENDING) != 0) {
    effectObj = ObjList_FindObjectById(DBPROTECTION_ENVFX_A);
    getEnvfxAct(effectObj, player, state[state[0xa4] + 0xa9], 0);
    effectObj = ObjList_FindObjectById(DBPROTECTION_ENVFX_B);
    getEnvfxAct(effectObj, player, state[(state[0xa4] ^ 1) + 0xa7], 0);
    getEnvfxAct(player, player, DBPROTECTION_PLAYER_ENVFX_FLASH, 0);
    GameBit_Set(DBPROTECTION_GAMEBIT_CYCLE_B_PENDING, 0);
    *(u16 *)(state + 0xa2) = DBPROTECTION_GAMEBIT_CYCLE_B_DONE;
  }

  if (GameBit_Get(DBPROTECTION_GAMEBIT_CYCLE_A_DONE) != 0) {
    if (*(u16 *)(state + 0xa2) != DBPROTECTION_GAMEBIT_CYCLE_A_DONE) {
      state[0xa4] = (u8)(state[0xa4] ^ 1);
    }
    getEnvfxAct(player, player, state[(state[0xa4] ^ 1) + 0xa5], 0);
    getEnvfxAct(player, player, state[state[0xa4] + 0xa9], 0);
    getEnvfxAct(player, player, DBPROTECTION_PLAYER_ENVFX_SWAP, 0);
    GameBit_Set(DBPROTECTION_GAMEBIT_CYCLE_A_DONE, 0);
  }

  if (GameBit_Get(DBPROTECTION_GAMEBIT_CYCLE_B_DONE) != 0) {
    if (*(u16 *)(state + 0xa2) != DBPROTECTION_GAMEBIT_CYCLE_B_DONE) {
      state[0xa4] = (u8)(state[0xa4] ^ 1);
    }
    getEnvfxAct(player, player, state[(state[0xa4] ^ 1) + 0xa5], 0);
    getEnvfxAct(player, player, state[state[0xa4] + 0xa9], 0);
    getEnvfxAct(player, player, DBPROTECTION_PLAYER_ENVFX_SWAP, 0);
    GameBit_Set(DBPROTECTION_GAMEBIT_CYCLE_B_DONE, 0);
  }
}

/* 16b chained patterns. */
int DBprotection_getCameraState(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x70); }

void DBprotection_updateShield(int *obj)
{
  DBProtectionState *state;
  f32 angleCos;

  state = *(DBProtectionState **)((u8 *)obj + 0xb8);
  *(int *)((u8 *)obj + 0xf4) = 7;

  if (GameBit_Get(DBPROTECTION_GAMEBIT_TRANSITION_ARMED) != 0 &&
      GameBit_Get(DBPROTECTION_GAMEBIT_TRANSITION_USED) == 0 &&
      GameBit_Get(DBPROTECTION_GAMEBIT_TRANSITION_READY) != 0) {
    lbl_803DDC2C = 1;
    GameBit_Set(DBPROTECTION_GAMEBIT_TRANSITION_USED, 1);
    SCREEN_TRANSITION_FADE(0xa, 1);
  }

  DBprotection_updateEnvfxGameBits((u8 *)state);

  if (lbl_803DDC2C != 0 && SCREEN_TRANSITION_READY() != 0) {
    SCREEN_TRANSITION_START(0x50, 1);
    OBJECT_TRIGGER_REFRESH(1, obj, -1);
    state->cameraState = 3;
    lbl_803DDC2C = 0;
  }

  CLOUD_ACTION_SET(lbl_803E57C8, lbl_803E56CC);
  CLOUD_ACTION_ENABLE(0);

  angleCos = fn_80293E80((lbl_803E56E4 * (f32)state->shieldAngle) / lbl_803E56E8);
  if (state->shieldSfxLatch == 0) {
    if (angleCos < lbl_803E57CC) {
      if (GameBit_Get(DBPROTECTION_GAMEBIT_MUTE_SFX) == 0) {
        Sfx_PlayFromObject((int)obj, SFXwp_crthit6);
      }
      state->shieldSfxLatch = 1;
    } else if (angleCos > lbl_803E57D0) {
      if (GameBit_Get(DBPROTECTION_GAMEBIT_MUTE_SFX) == 0) {
        Sfx_PlayFromObject((int)obj, SFXwp_crtsmsh6);
      }
      state->shieldSfxLatch = 1;
    }
  } else if (angleCos > lbl_803E57D4 && angleCos < lbl_803E57D8) {
    state->shieldSfxLatch = 0;
  }

  *(u16 *)((u8 *)obj + 4) = (s32)(lbl_803E57DC * angleCos);
  state->shieldAngle = (u16)(s32)(lbl_803E57E0 * timeDelta + (f32)state->shieldAngle);
}

void DBprotection_storeHomePosition(int *obj) {
    DBProtectionState *state = *(DBProtectionState**)((char*)obj + 0xb8);
    state->posX = *(f32*)((char*)obj + 0xc);
    state->posY = *(f32*)((char*)obj + 0x10);
    state->posZ = *(f32*)((char*)obj + 0x14);
}
