#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DB/DBprotection.h"

#define SFXwp_cahit2_c 0x143
#define SFXwp_dsmk2_c 0x146

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
extern void Matrix_TransformPoint(f32 x, f32 y, f32 z, f32 *matrix, f32 *outX, f32 *outY, f32 *outZ);

extern f32 lbl_803E56C8;
extern f32 lbl_803E56CC;
extern f32 lbl_803E56D0;
extern f32 lbl_803E56D4;
extern f32 lbl_803E56D8;
extern f32 lbl_803E56DC;
extern f32 lbl_803E56E0;
extern f32 lbl_803E56E4;
extern f32 lbl_803E56E8;
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
  ((void (*)(int, int, int))(*(u32 *)((u8 *)*gMapEventInterface + 0x50)))((layer), (a), (b))
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
  if ((*(void **)(state + 0x48) != NULL) &&
      ((*(s16 *)(*(u8 **)(state + 0x48) + 6) & 0x40) != 0)) {
    *(u8 **)(state + 0x48) = NULL;
  }
  if (*(void **)(state + 0x48) == NULL) {
    objArray = ObjList_GetObjects(&objIndex, &objCount);
    for (t = objIndex; t < objCount; t++) {
      otherObj = *(u8 **)(objArray + t * 4);
      if (*(s16 *)(otherObj + 0x46) == 0x8C) {
        *(u8 **)(state + 0x48) = otherObj;
        t = objCount;
      }
    }
  }
  if (*(s8 *)(state + 0x29) >= 2) {
    Sfx_PlayFromObject((int)obj, SFXwp_cahit2_c);
  }
  else {
    Sfx_StopFromObject((int)obj, SFXwp_cahit2_c);
  }
  tricky = *(u8 **)(state + 0x48);
  if (tricky == NULL) goto end;
  if ((tricky != NULL) && (*(int *)(tricky + 0xF4) == 0)) {
    fn_801EED5C((int)tricky, (f32 *)(state + 0x50), (f32 *)(state + 0x54), (f32 *)(state + 0x58));
  }
  *(s16 *)(state + 0x26) -= framesThisStep;
  if (*(s16 *)(state + 0x26) < 0) {
    *(s16 *)(state + 0x26) = 0;
  }
  c = *(s8 *)(state + 0x2B);
  if (c == 7) {
    *(u8 *)(state + 0x79) = 3;
  }
  else if (c == 8) {
    *(u8 *)(state + 0x79) = 4;
  }
  else if (c == 9) {
    *(u8 *)(state + 0x79) = 5;
  }
  if (*(s8 *)(state + 0x29) < 2) {
    *(f32 *)(state + 0x90) -= timeDelta;
    if (*(f32 *)(state + 0x90) <= lbl_803E56CC) {
      *(u8 *)(state + 0xA0) ^= 1;
      *(f32 *)(state + 0x90) = (f32)(int)randomGetRange(0xB4, 300);
    }
    if (*(u8 *)(state + 0xA0) != 0) {
      *(f32 *)(state + 0x88) = lbl_803E56D0 * timeDelta + *(f32 *)(state + 0x88);
    }
    else {
      *(f32 *)(state + 0x88) -= timeDelta;
    }
    *(f32 *)(state + 0x94) -= timeDelta;
    if (*(f32 *)(state + 0x94) <= lbl_803E56CC) {
      *(u8 *)(state + 0xA1) ^= 1;
      *(f32 *)(state + 0x94) = (f32)(int)randomGetRange(0xB4, 300);
    }
    if (*(u8 *)(state + 0xA1) != 0) {
      *(f32 *)(state + 0x8C) = lbl_803E56D0 * timeDelta + *(f32 *)(state + 0x8C);
    }
    else {
      *(f32 *)(state + 0x8C) -= timeDelta;
    }
  }
  else {
    amp = lbl_803E56D4;
    *(f32 *)(state + 0x88) = -(amp * timeDelta - *(f32 *)(state + 0x88));
    *(f32 *)(state + 0x8C) = -(amp * timeDelta - *(f32 *)(state + 0x8C));
  }
  dx = *(f32 *)(state + 0x88);
  *(f32 *)(state + 0x88) = (dx < lbl_803E56CC) ? lbl_803E56CC : (dx > lbl_803E56D8) ? lbl_803E56D8 : dx;
  dx = *(f32 *)(state + 0x8C);
  *(f32 *)(state + 0x8C) = (dx < lbl_803E56CC) ? lbl_803E56CC : (dx > lbl_803E56D8) ? lbl_803E56D8 : dx;
  switch (*(s8 *)(state + 0x29)) {
  case 0:
    camShake = lbl_803E56C8;
    Sfx_StopObjectChannel((int)obj, 1);
    DBPROT_CAMERA_SHAKE(&camShake, 0);
    *(int *)(obj + 0xF4) = 1;
    tx = *(f32 *)(state + 0x50) - lbl_803E56DC;
    tz = lbl_803E56E0 * sin((lbl_803E56E4 * (f32)*(s16 *)(state + 0x20)) / lbl_803E56E8) +
         *(f32 *)(state + 0x58);
    ty = lbl_803E56F0 * fn_80293E80((lbl_803E56E4 * (f32)*(s16 *)(state + 0x20)) / lbl_803E56E8) +
         (*(f32 *)(state + 0x54) - lbl_803E56EC);
    *(s16 *)(state + 0x20) = *(s16 *)(state + 0x20) + framesThisStep * 0xB6;
    dx = tx - *(f32 *)(obj + 0xC);
    dy = ty - *(f32 *)(obj + 0x10);
    dz = tz - *(f32 *)(obj + 0x14);
    *(f32 *)(state + 0x1C) = lbl_803E56F4;
    dx = dx * lbl_803E56F8;
    dy = dy * lbl_803E56F8;
    dz = dz * lbl_803E56F8;
    limit = *(f32 *)(state + 0x1C);
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
    t = *(s16 *)(state + 0x6E);
    if (t < 0x78) {
      dy = lbl_803E56CC;
    }
    else if (t < 0xB4) {
      dy = dy * ((f32)(t - 0x78) / lbl_803E56F0);
    }
    *(s16 *)(state + 0x6E) += framesThisStep;
    *(f32 *)(state + 0x0) += (dx - *(f32 *)(state + 0x0)) * lbl_803E56FC;
    *(f32 *)(state + 0x4) += (dy - *(f32 *)(state + 0x4)) * lbl_803E56FC;
    *(f32 *)(state + 0x8) += (dz - *(f32 *)(state + 0x8)) * lbl_803E56FC;
    ambA = lbl_803E5700;
    ambB = lbl_803E5704;
    ambC = lbl_803E5708;
    if (*(s8 *)(state + 0x28) == 0) {
      if ((*(s8 *)(state + 0x2B) < 2) && (-1 < *(s8 *)(state + 0x2B))) {
        if (*(s16 *)(state + 0x82) != 0) {
          *(s16 *)(state + 0x82) -= 1;
          if (*(s16 *)(state + 0x82) <= 0) {
            *(s16 *)(state + 0x82) = 200;
          }
        }
      }
      else {
        *(s8 *)(state + 0x2B) = 2;
        *(s16 *)(state + 0x6E) = 0;
        *(s8 *)(state + 0x29) = 1;
        *(s8 *)(state + 0x28) = 1;
        *(s8 *)(state + 0x7C) = 0;
        *(s8 *)(state + 0x7A) = 0;
        *(s16 *)(state + 0x82) = 200;
        GameBit_Set(0xF1E, 1);
      }
    }
    else {
      if ((*(s8 *)(state + 0x2B) < 5) && (2 < *(s8 *)(state + 0x2B))) {
        if (*(s16 *)(state + 0x82) != 0) {
          *(s16 *)(state + 0x82) -= 1;
          if (*(s16 *)(state + 0x82) <= 0) {
            *(s16 *)(state + 0x82) = 200;
          }
        }
      }
      else {
        *(s8 *)(state + 0x2B) = 5;
        *(s16 *)(state + 0x6E) = 0;
        *(s8 *)(state + 0x29) = 1;
        *(s8 *)(state + 0x28) = 2;
        *(s8 *)(state + 0x7A) = 0;
        *(s16 *)(state + 0x82) = 200;
      }
    }
    break;
  case 1:
    *(int *)(obj + 0xF4) = 2;
    camShake = lbl_803E56C8;
    DBPROT_CAMERA_SHAKE(&camShake, 0);
    if (*(s16 *)(state + 0x82) != 0) {
      *(s16 *)(state + 0x82) -= 1;
    }
    switch (*(s8 *)(state + 0x7A)) {
    case 0:
      tx = *(f32 *)(state + 0x50) - lbl_803E570C;
      tz = *(f32 *)(state + 0x58);
      ty = lbl_803E56EC + *(f32 *)(tricky + 0x10);
      if ((*(s16 *)(state + 0x82) <= 0) &&
          ((*(s8 *)(state + 0x7C) == 0) || (*(s8 *)(state + 0x7C) == 5))) {
        *(s16 *)(state + 0x82) = 200;
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
      tz = tz + (*(f32 *)(tricky + 0x14) - *(f32 *)(state + 0x34));
      *(u8 *)(state + 0x7B) = 0;
      break;
    case 4:
      tx = *(f32 *)(tricky + 0xC) - lbl_803E571C;
      tz = lbl_803E5724 + *(f32 *)(state + 0x58);
      ty = lbl_803E5718 + *(f32 *)(tricky + 0x10);
      *(u8 *)(state + 0x7B) = 0;
      break;
    case 5:
      tx = *(f32 *)(tricky + 0xC) - lbl_803E571C;
      tz = *(f32 *)(state + 0x58) - lbl_803E5720;
      ty = lbl_803E5718 + *(f32 *)(tricky + 0x10);
      tz = tz + (*(f32 *)(tricky + 0x14) - *(f32 *)(state + 0x34));
      *(u8 *)(state + 0x7B) = 0;
      break;
    default:
      *(u8 *)(state + 0x7B) = 0;
      tx = *(f32 *)(state + 0x50) - lbl_803E5728;
      tz = *(f32 *)(state + 0x58);
      ty = lbl_803E572C + *(f32 *)(tricky + 0x10);
      break;
    }
    tx = tx - *(f32 *)(obj + 0xC);
    dy = ty - *(f32 *)(obj + 0x10);
    tz = tz - *(f32 *)(obj + 0x14);
    *(f32 *)(state + 0x1C) = lbl_803E56F4;
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
    *(s16 *)(state + 0x6E) += framesThisStep;
    *(f32 *)(state + 0x0) += (tx - *(f32 *)(state + 0x0)) * lbl_803E5748;
    *(f32 *)(state + 0x4) += (dy - *(f32 *)(state + 0x4)) / lbl_803E574C;
    *(f32 *)(state + 0x8) += (tz - *(f32 *)(state + 0x8)) / lbl_803E5750;
    ambA = lbl_803E5754;
    ambB = lbl_803E5758;
    ambC = lbl_803E56CC;
    switch (*(s8 *)(state + 0x7A)) {
    case 0:
      if (dist < lbl_803E575C) {
        *(u8 *)(state + 0x7A) = 1;
        *(s16 *)(state + 0x6E) = 0;
      }
      break;
    case 1:
      if (dist < lbl_803E5708) {
        *(u8 *)(state + 0x7A) = 2;
        *(s16 *)(state + 0x6E) = 0;
      }
      break;
    case 2:
      if ((*(s16 *)(state + 0x6E) > 0xF0) || (dist < lbl_803E5708)) {
        *(u8 *)(state + 0x7A) = 0;
        *(s16 *)(state + 0x6E) = 0;
      }
      break;
    case 3:
      if ((dist < lbl_803E5708) || (*(s16 *)(state + 0x6E) > 0x78)) {
        *(u8 *)(state + 0x7A) = 0;
        *(s16 *)(state + 0x6E) = 0;
      }
      break;
    case 4:
      if ((dist < lbl_803E5708) || (*(s16 *)(state + 0x6E) > 0x78)) {
        *(u8 *)(state + 0x7A) = 5;
        *(s16 *)(state + 0x6E) = 3;
      }
      break;
    case 5:
      if ((dist < lbl_803E5708) || (*(s16 *)(state + 0x6E) > 0x78)) {
        *(u8 *)(state + 0x7A) = 0;
        *(s16 *)(state + 0x6E) = 0;
      }
      break;
    default:
      if (dist < lbl_803E5760) {
        if (*(s8 *)(state + 0x2B) == 2) {
          *(s16 *)(state + 0x6E) = 0;
          *(s8 *)(state + 0x29) = 0;
          *(s8 *)(state + 0x2B) = 3;
        }
        else if (*(s8 *)(state + 0x2B) == 5) {
          *(s8 *)(state + 0x29) = 2;
          *(s8 *)(state + 0x2B) = 6;
        }
      }
      break;
    }
    *(s16 *)(state + 0x26) = 300;
    if ((*(s8 *)(state + 0x7C) >= 4) && (*(s8 *)(state + 0x2B) < 3)) {
      *(s8 *)(state + 0x29) = 0;
      *(s8 *)(state + 0x28) = 1;
      *(s8 *)(state + 0x2B) = 3;
      *(s8 *)(state + 0x7C) = 5;
      *(s16 *)(state + 0x82) = 200;
      sfxObj = fn_801E2570();
      Sfx_StopFromObject(sfxObj, 0x2C6);
      Sfx_PlayFromObject(sfxObj, SFXwp_dsmk2_c);
      GameBit_Set(0xF1E, 0);
    }
    else if (*(s8 *)(state + 0x7C) >= 4) {
      *(s8 *)(state + 0x29) = 2;
      *(s8 *)(state + 0x28) = 3;
      *(s8 *)(state + 0x2B) = 6;
      *(s16 *)(state + 0x82) = 200;
      *(f32 *)(state + 0xC) = *(f32 *)(tricky + 0x14);
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
    if (*(s16 *)(state + 0x82) != 0) {
      *(s16 *)(state + 0x82) -= 1;
    }
    switch (*(s8 *)(state + 0x29)) {
    case 2:
      speedTarget = lbl_803E5764;
      tx = *(f32 *)(state + 0x50) - lbl_803E5768;
      tz = -(lbl_803E576C * (f32)*(s8 *)(state + 0x2A) - *(f32 *)(state + 0x58));
      ty = *(f32 *)(state + 0x54);
      threshold = lbl_803E5770;
      nextState = 3;
      break;
    case 3:
      speedTarget = lbl_803E5774;
      tx = *(f32 *)(state + 0x50) - lbl_803E5778;
      tz = -(lbl_803E5770 * (f32)*(s8 *)(state + 0x2A) - *(f32 *)(state + 0x58));
      ty = lbl_803E5724 + *(f32 *)(state + 0x54);
      nextState = 4;
      threshold = lbl_803E577C;
      break;
    case 4:
      speedTarget = lbl_803E5774;
      tx = *(f32 *)(state + 0x50) - lbl_803E5768;
      tz = -(lbl_803E5708 * (f32)*(s8 *)(state + 0x2A) - *(f32 *)(state + 0x58));
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
      if ((*(s16 *)(state + 0x82) <= 0) && (*(s8 *)(state + 0x2B) == 6)) {
        *(s16 *)(state + 0x82) = 200;
      }
      break;
    case 6:
      speedTarget = lbl_803E56D0;
      tx = lbl_803E5784 + *(f32 *)(state + 0x50);
      tz = -(lbl_803E576C * (f32)*(s8 *)(state + 0x2A) - *(f32 *)(state + 0x58));
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
    dx = tx - *(f32 *)(state + 0x2C);
    dy = ty - *(f32 *)(state + 0x30);
    dz = tz - *(f32 *)(state + 0x34);
    *(f32 *)(state + 0x1C) =
        *(f32 *)(state + 0x1C) + (speedTarget - *(f32 *)(state + 0x1C)) / lbl_803E5798;
    dist = sqrtf(dx * dx + dz * dz);
    if ((*(s8 *)(state + 0x29) == 5) && (dist < lbl_803E579C)) {
      *(int *)(obj + 0xF4) = 5;
    }
    if (dist < threshold) {
      if (*(s8 *)(state + 0x29) == 5) {
        *(s8 *)(state + 0x2A) = -*(s8 *)(state + 0x2A);
      }
      *(s8 *)(state + 0x29) = (s8)nextState;
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
    *(s16 *)(state + 0x24) =
        *(s16 *)(state + 0x24) + ((framesThisStep * (wrap - *(s16 *)(state + 0x24))) >> 4);
    c = *(s8 *)(state + 0x29);
    if ((c == 3) || (c == 4)) {
      *(s16 *)(obj + 0x0) = *(s16 *)(obj + 0x0) + (*(s16 *)(state + 0x24) * framesThisStep) / 0x3C;
    }
    else if ((c == 6) || (c == 2)) {
      *(s16 *)(obj + 0x0) = *(s16 *)(obj + 0x0) + (*(s16 *)(state + 0x24) * framesThisStep) / 0x78;
    }
    else {
      *(s16 *)(obj + 0x0) = *(s16 *)(obj + 0x0) + (*(s16 *)(state + 0x24) * framesThisStep) / 0x3C;
    }
    wrap = angY - (*(s16 *)(obj + 0x2) & 0xFFFF);
    if (wrap > 0x8000) {
      wrap = wrap - 0xFFFF;
    }
    if (wrap < -0x8000) {
      wrap = wrap + 0xFFFF;
    }
    *(s16 *)(obj + 0x2) = *(s16 *)(obj + 0x2) + ((wrap * framesThisStep) >> 6);
    dx = *(f32 *)(state + 0x50) - *(f32 *)(obj + 0xC);
    dz = *(f32 *)(state + 0x58) - *(f32 *)(obj + 0x14);
    sqrtf(dx * dx + dz * dz);
    t = *(s16 *)(obj + 0x4);
    iv = (int)(lbl_803E57A0 * (f32)*(s16 *)(state + 0x24));
    dv = (iv - t) >> 3;
    if (dv > 0x3C) {
      dv = 0x3C;
    }
    if (dv < -0x3C) {
      dv = -0x3C;
    }
    *(s16 *)(obj + 0x4) = (f32)dv * timeDelta + (f32)*(s16 *)(obj + 0x4);
    objPos.vec[0] = lbl_803E56CC;
    objPos.vec[1] = lbl_803E56CC;
    objPos.vec[2] = lbl_803E56CC;
    objPos.scale = lbl_803E57A4;
    objPos.rot[0] = *(s16 *)(obj + 0x0);
    objPos.rot[1] = *(s16 *)(obj + 0x2);
    objPos.rot[2] = *(s16 *)(obj + 0x4);
    setMatrixFromObjectPos(mtx, &objPos);
    Matrix_TransformPoint(lbl_803E56CC, lbl_803E56CC, -*(f32 *)(state + 0x1C) * timeDelta, mtx,
                          (f32 *)(state + 0x0), (f32 *)(state + 0x4), (f32 *)(state + 0x8));
    if (*(s8 *)(state + 0x29) == 7) {
      *(f32 *)(state + 0x2C) = tx;
      *(f32 *)(state + 0x30) = ty;
      *(f32 *)(state + 0x34) = tz;
      zero = lbl_803E56CC;
      *(f32 *)(state + 0x38) = zero;
      *(f32 *)(state + 0x3C) = zero;
      *(f32 *)(state + 0x40) = zero;
    }
    else {
      *(f32 *)(state + 0x2C) = *(f32 *)(state + 0x2C) + *(f32 *)(state + 0x0);
      *(f32 *)(state + 0x30) = *(f32 *)(state + 0x30) + *(f32 *)(state + 0x4);
      *(f32 *)(state + 0x34) = *(f32 *)(state + 0x34) + *(f32 *)(state + 0x8);
    }
    ambB = lbl_803E57A8;
    *(f32 *)(obj + 0xC) = *(f32 *)(state + 0x2C) + *(f32 *)(state + 0x38);
    *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x30) + *(f32 *)(state + 0x3C);
    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x34) + *(f32 *)(state + 0x40) +
                           (*(f32 *)(tricky + 0x14) - *(f32 *)(state + 0xC));
    if (*(s8 *)(state + 0x2B) >= 7) {
      if (*(s16 *)(state + 0x6C) == 0) {
        ObjHits_DisableObject(obj);
        DBPROT_SCREEN_FADE(0x41, 1);
      }
      *(s16 *)(state + 0x6C) += framesThisStep;
      if (*(s16 *)(state + 0x6C) > 0x41) {
        *(s16 *)(obj + 0x0) = 0;
        *(s8 *)(state + 0x29) = 6;
        DBPROT_CLOUD_SET_A(0);
        DBPROT_CLOUD_SET_B(0);
        DBPROT_CLOUD_SET_RANGE(lbl_803E56CC, lbl_803E5760);
        if (*(u8 *)(state + 0x80) == 0) {
          *(u8 *)(state + 0x80) = 1;
        }
        *(u8 *)(state + 0x70) = 1;
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
  if (*(s8 *)(state + 0x29) < 2) {
    *(f32 *)(state + 0x2C) =
        *(f32 *)(state + 0x44) * (*(f32 *)(state + 0x0) * timeDelta) + *(f32 *)(state + 0x2C);
    *(f32 *)(state + 0x30) =
        *(f32 *)(state + 0x44) * (*(f32 *)(state + 0x4) * timeDelta) + *(f32 *)(state + 0x30);
    *(f32 *)(state + 0x34) =
        *(f32 *)(state + 0x44) * (*(f32 *)(state + 0x8) * timeDelta) + *(f32 *)(state + 0x34);
    *(f32 *)(state + 0x44) += lbl_803E57B0;
    if (*(f32 *)(state + 0x44) > lbl_803E57A4) {
      *(f32 *)(state + 0x44) = lbl_803E57A4;
    }
    blendK = lbl_803E57B4;
    *(f32 *)(state + 0x5C) += blendK * (timeDelta * (ambA - *(f32 *)(state + 0x5C)));
    *(f32 *)(state + 0x60) += blendK * (timeDelta * (ambC - *(f32 *)(state + 0x60)));
    *(f32 *)(state + 0x64) += blendK * (timeDelta * (ambB - *(f32 *)(state + 0x64)));
    if (*(s8 *)(state + 0x29) == 0) {
      zRatio = (f32)*(s16 *)(tricky + 0x2) / *(f32 *)(state + 0x5C);
      *(f32 *)(state + 0x40) +=
          timeDelta * (*(f32 *)(state + 0x64) *
                       ((f32)-*(s16 *)(tricky + 0x4) / *(f32 *)(state + 0x5C) - *(f32 *)(state + 0x40)));
      *(f32 *)(state + 0x3C) +=
          timeDelta * (*(f32 *)(state + 0x64) * (zRatio - *(f32 *)(state + 0x3C)));
      zero = lbl_803E56CC;
      *(f32 *)(state + 0x38) = zero;
      *(f32 *)(state + 0x3C) = zero;
      rollA = (s16)(int)(-*(f32 *)(state + 0x40) * *(f32 *)(state + 0x60));
      rollB = (s16)(int)(lbl_803E57B8 * (-*(f32 *)(state + 0x3C) * *(f32 *)(state + 0x60)));
    }
    else {
      *(f32 *)(state + 0x40) =
          -(timeDelta * (*(f32 *)(state + 0x40) * *(f32 *)(state + 0x64)) - *(f32 *)(state + 0x40));
      *(f32 *)(state + 0x3C) =
          -(timeDelta * (*(f32 *)(state + 0x3C) * *(f32 *)(state + 0x64)) - *(f32 *)(state + 0x3C));
      rollB = rollA = 0;
    }
    *(f32 *)(obj + 0xC) = *(f32 *)(state + 0x38) * *(f32 *)(state + 0x44) + *(f32 *)(state + 0x2C);
    *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x3C) * *(f32 *)(state + 0x44) + *(f32 *)(state + 0x30);
    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x40) * *(f32 *)(state + 0x44) + *(f32 *)(state + 0x34);
    *(s16 *)(state + 0x22) =
        *(s16 *)(state + 0x22) + ((framesThisStep * (rollA - *(s16 *)(state + 0x22))) >> 5);
    *(s16 *)(obj + 0x2) =
        *(s16 *)(obj + 0x2) + ((framesThisStep * (rollB - *(s16 *)(obj + 0x2))) >> 5);
    *(s16 *)(obj + 0x0) = *(s16 *)(state + 0x22) + 0x4000;
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
  u8 *state;
  f32 angleCos;

  state = *(u8 **)((u8 *)obj + 0xb8);
  *(int *)((u8 *)obj + 0xf4) = 7;

  if (GameBit_Get(DBPROTECTION_GAMEBIT_TRANSITION_ARMED) != 0 &&
      GameBit_Get(DBPROTECTION_GAMEBIT_TRANSITION_USED) == 0 &&
      GameBit_Get(DBPROTECTION_GAMEBIT_TRANSITION_READY) != 0) {
    lbl_803DDC2C = 1;
    GameBit_Set(DBPROTECTION_GAMEBIT_TRANSITION_USED, 1);
    SCREEN_TRANSITION_FADE(0xa, 1);
  }

  DBprotection_updateEnvfxGameBits(state);

  if (lbl_803DDC2C != 0 && SCREEN_TRANSITION_READY() != 0) {
    SCREEN_TRANSITION_START(0x50, 1);
    OBJECT_TRIGGER_REFRESH(1, obj, -1);
    state[0x70] = 3;
    lbl_803DDC2C = 0;
  }

  CLOUD_ACTION_SET(lbl_803E57C8, lbl_803E56CC);
  CLOUD_ACTION_ENABLE(0);

  angleCos = fn_80293E80((lbl_803E56E4 * (f32)*(u16 *)(state + 0x68)) / lbl_803E56E8);
  if (state[0x81] == 0) {
    if (angleCos < lbl_803E57CC) {
      if (GameBit_Get(DBPROTECTION_GAMEBIT_MUTE_SFX) == 0) {
        Sfx_PlayFromObject((int)obj, SFXwp_crthit6);
      }
      state[0x81] = 1;
    } else if (angleCos > lbl_803E57D0) {
      if (GameBit_Get(DBPROTECTION_GAMEBIT_MUTE_SFX) == 0) {
        Sfx_PlayFromObject((int)obj, SFXwp_crtsmsh6);
      }
      state[0x81] = 1;
    }
  } else if (angleCos > lbl_803E57D4 && angleCos < lbl_803E57D8) {
    state[0x81] = 0;
  }

  *(u16 *)((u8 *)obj + 4) = (s32)(lbl_803E57DC * angleCos);
  *(u16 *)(state + 0x68) = (u16)(s32)(lbl_803E57E0 * timeDelta + (f32)*(u16 *)(state + 0x68));
}

void DBprotection_storeHomePosition(int *obj) {
    char *state = *(char**)((char*)obj + 0xb8);
    *(f32*)(state + 0x2c) = *(f32*)((char*)obj + 0xc);
    *(f32*)(state + 0x30) = *(f32*)((char*)obj + 0x10);
    *(f32*)(state + 0x34) = *(f32*)((char*)obj + 0x14);
}
