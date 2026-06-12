#include "main/dll/DIM/DIM2icicle.h"
#include "main/audio/sfx.h"
#include "main/effect_interfaces.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/objanim_internal.h"
#include "main/objhits.h"
#include "main/objhits_types.h"

static inline int *DIM2Icicle_GetActiveModel(void *obj) {
  ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
  return (int *)objAnim->banks[objAnim->bankIndex];
}

extern undefined4 FUN_80003494();
extern undefined8 FUN_80006728();
extern undefined4 FUN_80006824();
extern undefined4 FUN_8000691c();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017544();
extern undefined4 FUN_80017548();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017580();
extern undefined4 FUN_80017584();
extern undefined4 FUN_80017588();
extern undefined4 FUN_80017594();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_800175ec();
extern void* FUN_80017624();
extern int randomGetRange(int min, int max);
extern int FUN_80017a90();
extern int FUN_80017a98();
extern uint ObjPath_GetPointModelMtx();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80053c98();
extern undefined8 FUN_8012e0b8();
extern undefined4 FUN_801bbf98();
extern undefined4 FUN_80247bf8();
extern undefined8 FUN_80286824();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286870();
extern undefined4 FUN_8028688c();
extern uint FUN_80294bd8();

extern undefined4 DAT_802c2ac8;
extern undefined4 DAT_802c2acc;
extern undefined4 DAT_802c2ad0;
extern undefined4 DAT_802c2ad4;
extern undefined4 DAT_80326620;
extern undefined4 DAT_80326624;
extern undefined4 DAT_803266f8;
extern undefined4 DAT_803266fc;
extern undefined4 DAT_80326700;
extern undefined4 DAT_80326704;
extern undefined4 DAT_803ad5d0;
extern undefined4 DAT_803ad5d4;
extern undefined4 DAT_803ad5d8;
extern undefined4 DAT_803ad5dc;
extern undefined4 DAT_803ad5e8;
extern undefined4 DAT_803ad5ec;
extern undefined4 DAT_803ad5f0;
extern undefined4 DAT_803ad5f4;
extern undefined4 DAT_803ad5f6;
extern undefined4 DAT_803ad5f8;
extern undefined4 DAT_803ad5fc;
extern undefined4 DAT_803ad600;
extern undefined4 DAT_803ad604;
extern undefined4 DAT_803ad608;
extern undefined4 DAT_803adc60;
extern undefined4 DAT_803adc78;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd734;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de800;
extern undefined4* DAT_803de808;
extern undefined4 DAT_803de80c;
extern f64 DOUBLE_803e5878;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E5854;
extern f32 lbl_803E585C;
extern f32 lbl_803E5860;
extern f32 lbl_803E5864;
extern f32 lbl_803E5870;
extern f32 lbl_803E5884;
extern f32 lbl_803E588C;
extern f32 lbl_803E5890;
extern f32 lbl_803E58A8;
extern f32 lbl_803E58C0;
extern f32 lbl_803E58C4;
extern f32 lbl_803E58C8;
extern f32 lbl_803E58CC;
extern f32 lbl_803E58D0;
extern f32 lbl_803E58D4;
extern f32 lbl_803E58D8;
extern f32 lbl_803E58DC;
extern f32 lbl_803E58E0;
extern f32 lbl_803E58E4;
extern f32 lbl_803E58E8;
extern f32 lbl_803E58EC;
extern f32 lbl_803E58F0;
extern f32 lbl_803E58F4;
extern f32 lbl_803E58F8;
extern f32 lbl_803E58FC;
extern f32 lbl_803E5900;
extern f32 lbl_803E5904;
extern f32 lbl_803E5908;
extern f32 lbl_803E590C;
extern undefined4 gDIMbossAnimTable[];
extern undefined4 gDIMbossHitDetectAnimTable[];
extern void DIM2icicle_spawnBlueWhiteEffect(int* sourceObj, f32* velocity);
extern void DIM2icicle_createStateLight(int obj, u8 isGreen);

extern int getTrickyObject(void);
extern undefined4* gBaddieControlInterface;
extern int gPlayerInterface;
extern u32 gDIMbossSequenceFlags;
extern f32 timeDelta;
extern f32 lbl_803E4BC8;
extern f32 lbl_803E4BD8;
extern f32 lbl_803E4BEC;
extern f32 lbl_803E4C44;
extern f32 lbl_803E4C70;
extern f32 lbl_803E4C74;
extern u8 lbl_803259E0[];

typedef struct IcicleEntry {
    f32 resetTime;
    u16 bit;
    u16 pad;
} IcicleEntry;

typedef struct IcicleState {
    u8 pad[0xa0];
    f32 meltTimer;
    f32 lightTimer;
    f32 fadeTimer;
    u8 pad2[9];
    u8 index;
} IcicleState;

extern void PSMTXMultVec(f32 *mtx, f32 *src, f32 *dst);
extern void memcpy(void *dst, void *src, int n);
extern EffectInterface **gPartfxInterface;
extern const f32 lbl_803E4BCC;
extern const f32 lbl_803E4C34;
extern const f32 lbl_803E4C38;
extern f32 lbl_803E4C3C;
extern f32 lbl_803E4C40;
extern f32 lbl_803E4C48;
extern u8 lbl_803AC97C[];
extern f32 lbl_803AC970[];

typedef struct IcicleFxPos {
    u8 pad[0xc];
    f32 x;
    f32 y;
    f32 z;
} IcicleFxPos;

/*
 * --INFO--
 *
 * Function: fn_801BB598
 * EN v1.0 Address: 0x801BB598
 * EN v1.0 Size: 1452b
 * EN v1.1 Size: 1452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_801BB598(DIMbossObject *obj, DIMbossRuntime *runtime)
{
  int objIndex;
  int *state;
  DIMbossTopState *topState;
  DIMbossEffect *effect;
  s16 brightness;
  int i;
  f32 zero;
  f32 m[12];
  u8 colA;
  u8 colB;
  u8 colG;
  u8 colR;

  objIndex = (int)obj;
  topState = runtime->topState;
  state = (int *)topState;
  effect = topState->effect;
  if (effect != NULL) {
    if (runtime->phase == DIMBOSS_PHASE_LAUNCH_LIFT) {
      modelLightStruct_setPosition((ModelLightStruct *)effect, *(f32 *)(state + 0x16), *(f32 *)(state + 0x17), *(f32 *)(state + 0x18));
    }
    else {
      modelLightStruct_setPosition((ModelLightStruct *)effect, *(f32 *)(state + 0x10), *(f32 *)(state + 0x11), *(f32 *)(state + 0x12));
    }
    modelLightStruct_getSpecularColor((ModelLightStruct *)effect, &colA, &colB, &colG, &colR);
    modelLightStruct_setGlowColor((ModelLightStruct *)effect, colA, colB, colG, 0xc0);
    if (effect->glowType != 0 && effect->enabled != 0) {
      brightness = effect->glowAlpha + effect->glowAlphaStep;
      if (brightness < 0) {
        brightness = 0;
        effect->glowAlphaStep = 0;
      }
      else if (brightness > 0xc) {
        brightness = brightness + randomGetRange(-0xc, 0xc);
        if (brightness > 0xff) {
          brightness = 0xff;
          effect->glowAlphaStep = 0;
        }
      }
      effect->glowAlpha = brightness;
    }
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_7) {
    ObjPath_GetPointWorldPosition(objIndex, 7, &((IcicleFxPos *)&lbl_803AC97C)->x, &((IcicleFxPos *)&lbl_803AC97C)->y, &((IcicleFxPos *)&lbl_803AC97C)->z, 0);
    i = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)objIndex, 0x4b7, &lbl_803AC97C, 0x200001, -1, NULL);
      i = i + 1;
    } while (i < 0xf);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_8) {
    ObjPath_GetPointWorldPosition(objIndex, 8, &((IcicleFxPos *)&lbl_803AC97C)->x, &((IcicleFxPos *)&lbl_803AC97C)->y, &((IcicleFxPos *)&lbl_803AC97C)->z, 0);
    i = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)objIndex, 0x4b7, &lbl_803AC97C, 0x200001, -1, NULL);
      i = i + 1;
    } while (i < 0xf);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_9) {
    ObjPath_GetPointWorldPosition(objIndex, 9, &((IcicleFxPos *)&lbl_803AC97C)->x, &((IcicleFxPos *)&lbl_803AC97C)->y, &((IcicleFxPos *)&lbl_803AC97C)->z, 0);
    i = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)objIndex, 0x4b7, &lbl_803AC97C, 0x200001, -1, NULL);
      i = i + 1;
    } while (i < 0xf);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_ICICLE_DUST_POINT_10) {
    ObjPath_GetPointWorldPosition(objIndex, 10, &((IcicleFxPos *)&lbl_803AC97C)->x, &((IcicleFxPos *)&lbl_803AC97C)->y, &((IcicleFxPos *)&lbl_803AC97C)->z, 0);
    i = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)objIndex, 0x4b7, &lbl_803AC97C, 0x200001, -1, NULL);
      i = i + 1;
    } while (i < 0xf);
  }
  if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_BREATH_BURST) {
    memcpy(m, (void *)ObjPath_GetPointModelMtx(objIndex, 0xb), 0x30);
    zero = lbl_803E4BD8;
    m[3] = zero;
    m[7] = zero;
    m[11] = zero;
    i = 0;
    do {
      ((IcicleFxPos *)&lbl_803AC97C)->x = (f32)(int)randomGetRange(-0x19, 0x19);
      ((IcicleFxPos *)&lbl_803AC97C)->y = (f32)(int)randomGetRange(-0x19, 0x19);
      ((IcicleFxPos *)&lbl_803AC97C)->z = lbl_803E4C34;
      lbl_803AC970[0] = ((IcicleFxPos *)&lbl_803AC97C)->x / (lbl_803E4C34 * lbl_803E4C38);
      lbl_803AC970[1] = ((IcicleFxPos *)&lbl_803AC97C)->y / (lbl_803E4C34 * lbl_803E4C38);
      lbl_803AC970[2] = lbl_803E4BCC;
      PSMTXMultVec(m, lbl_803AC970, lbl_803AC970);
      ObjPath_GetPointWorldPosition(objIndex, 0xb, &((IcicleFxPos *)&lbl_803AC97C)->x, &((IcicleFxPos *)&lbl_803AC97C)->y, &((IcicleFxPos *)&lbl_803AC97C)->z, 1);
      (*gPartfxInterface)->spawnObject(
          (void *)objIndex, 0x4b8, &lbl_803AC97C, 0x200001, -1, lbl_803AC970);
      i = i + 1;
    } while (i < 5);
  }
  *(f32 *)(state + 10) = lbl_803E4BD8;
  *(f32 *)(state + 0xb) = lbl_803E4C3C;
  *(f32 *)(state + 0xc) = lbl_803E4C40;
  *(f32 *)(state + 9) = lbl_803E4C44;
  *(u16 *)(state + 8) = 0;
  *(u16 *)((int)state + 0x1e) = 0;
  *(u16 *)(state + 7) = 0;
  ObjPath_GetPointWorldPosition(objIndex, 0xd, (f32 *)(state + 10), (f32 *)(state + 0xb), (f32 *)(state + 0xc), 1);
  ObjPath_GetPointWorldPosition(objIndex, 0xd, (f32 *)(state + 4), (f32 *)(state + 5), (f32 *)(state + 6), 0);
  ObjPath_GetPointWorldPosition(objIndex, 0xb, (f32 *)(state + 0x10), (f32 *)(state + 0x11), (f32 *)(state + 0x12), 0);
  *(f32 *)(state + 0x16) = lbl_803E4BD8;
  *(f32 *)(state + 0x17) = lbl_803E4C48;
  *(f32 *)(state + 0x18) = lbl_803E4BC8;
  *(f32 *)(state + 0x15) = lbl_803E4C44;
  *(u16 *)(state + 0x14) = 0;
  *(u16 *)((int)state + 0x4e) = 0;
  *(u16 *)(state + 0x13) = 0;
  ObjPath_GetPointWorldPosition(objIndex, 0xc, (f32 *)(state + 0x16), (f32 *)(state + 0x17), (f32 *)(state + 0x18), 1);
  memcpy(state + 0x19, (void *)ObjPath_GetPointModelMtx(objIndex, 0), 0x30);
  zero = lbl_803E4BD8;
  *(f32 *)(state + 0x1c) = zero;
  *(f32 *)(state + 0x20) = zero;
  *(f32 *)(state + 0x24) = zero;
  gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~DIMBOSS_SEQUENCE_FLAGS_ICICLE_DUST_AND_BREATH;
}

extern void setShowWorldMapHud(int show);
extern void warpToMap(int map, int p2);
extern void getEnvfxAct(int a, int b, int c, int d);
extern void skyFn_80089710(int id, int enabled, int arg);
extern void skyFn_800894a8(int id, f32 x, f32 y, f32 z);
extern void skyFn_800895e0(int id, int red, int green, int blue, int alpha, int arg);
extern void doRumble(f32 v);
extern void Camera_EnableViewYOffset(void);
extern void CameraShake_Start(f32 a, f32 b, f32 c);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern void *lbl_803DCAB4;
extern int lbl_80325AB8[];
extern f32 lbl_803E4BC4;
extern f32 lbl_803E4BF4;
extern f32 lbl_803E4BF8;
extern f32 lbl_803E4C4C;
extern f32 lbl_803E4C50;
extern f32 lbl_803E4C54;
extern const f32 lbl_803E4C58;
extern const f32 lbl_803E4C5C;
extern f32 lbl_803E4C60;
extern f32 lbl_803E4C64;
extern f32 lbl_803E4C68;
extern f32 lbl_803E4C6C;

typedef struct IcicleWarpFlags {
    u8 pending : 1;
    u8 rest : 7;
} IcicleWarpFlags;

/*
 * --INFO--
 *
 * Function: warpDarkIceMines_801bbb44
 * EN v1.0 Address: 0x801BBB44
 * EN v1.0 Size: 1940b
 * EN v1.1 Size: 1940b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void warpDarkIceMines_801bbb44(int obj, int runtime)
{
  u8 *state;
  int counter;
  int i;
  u32 flags;
  f32 vec[3];

  state = *(u8 **)(runtime + 0x40c);
  counter = *(int *)(state + 0xb0);
  if (counter != 0) {
    *(int *)(state + 0xb0) = counter - 1;
    if (*(int *)(state + 0xb0) <= 0) {
      *(int *)(state + 0xb0) = 0;
      setShowWorldMapHud(0);
      warpToMap(0x77, 1);
      return;
    }
  }
  if (((IcicleWarpFlags *)(state + 0xb6))->pending) {
    getEnvfxAct(0, 0, 0xdb, 0);
    getEnvfxAct(0, 0, 0xdc, 0);
    skyFn_80089710(7, 1, 0);
    skyFn_800894a8(7, lbl_803E4C4C, lbl_803E4C50, lbl_803E4C54);
    skyFn_800895e0(7, 0xa0, 0xa0, 0xff, 0x7f, 0x28);
    ((IcicleWarpFlags *)(state + 0xb6))->pending = 0;
  }
  if (*(int *)(runtime + 0x314) & 4) {
    *(int *)(runtime + 0x314) = *(int *)(runtime + 0x314) & ~4;
    Sfx_PlayFromObject(obj, (u16)lbl_80325AB8[0]);
    gDIMbossSequenceFlags |= 0x204;
    doRumble(lbl_803E4BF8);
  }
  if (*(int *)(runtime + 0x314) & 2) {
    *(int *)(runtime + 0x314) = *(int *)(runtime + 0x314) & ~2;
    Sfx_PlayFromObject(obj, (u16)lbl_80325AB8[1]);
    gDIMbossSequenceFlags |= 0x404;
    doRumble(lbl_803E4BF8);
  }
  if (*(int *)(runtime + 0x314) & 0x10) {
    *(int *)(runtime + 0x314) = *(int *)(runtime + 0x314) & ~0x10;
    Sfx_PlayFromObject(obj, (u16)lbl_80325AB8[2]);
    gDIMbossSequenceFlags |= 0x804;
    doRumble(lbl_803E4BF8);
  }
  if (*(int *)(runtime + 0x314) & 8) {
    *(int *)(runtime + 0x314) = *(int *)(runtime + 0x314) & ~8;
    Sfx_PlayFromObject(obj, (u16)lbl_80325AB8[3]);
    gDIMbossSequenceFlags |= 0x1004;
    doRumble(lbl_803E4BF8);
  }
  if (gDIMbossSequenceFlags & 0x2000) {
    i = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)obj, 0x4b1, state + 0x4c, 0x200001, -1, NULL);
      i = i + 1;
    } while (i < 0x32);
    (*gPartfxInterface)->spawnObject((void *)obj, 0x4b2, state + 0x4c, 0x200001, -1, NULL);
    (*gPartfxInterface)->spawnObject((void *)obj, 0x4b3, state + 0x4c, 0x200001, -1, NULL);
  }
  if (gDIMbossSequenceFlags & 0x80000) {
    ((void (*)(int, int, int, int, int))*(code **)(*(int *)lbl_803DCAB4 + 0xc))(obj, 0x800, 0, 1, 0);
  }
  if ((gDIMbossSequenceFlags & 0x8020) || *(s8 *)(runtime + 0x354) < 2) {
    if (gDIMbossSequenceFlags & 0x20) {
      i = 0;
      do {
        (*gPartfxInterface)->spawnObject((void *)obj, 0x4b4, state + 0x34, 0x200001, -1, NULL);
        i = i + 1;
      } while (i < 7);
    }
    else {
      if (randomGetRange(0, *(s8 *)(runtime + 0x354)) == 0 && *(s16 *)(runtime + 0x402) == 2) {
        (*gPartfxInterface)->spawnObject((void *)obj, 0x4b4, state + 0x34, 0x200001, -1, NULL);
      }
    }
    if (gDIMbossSequenceFlags & 0x8000) {
      (*gPartfxInterface)->spawnObject((void *)obj, 0x4b2, state + 0x34, 0x200001, -1, NULL);
      (*gPartfxInterface)->spawnObject((void *)obj, 0x4b3, state + 0x34, 0x200001, -1, NULL);
    }
  }
  if (gDIMbossSequenceFlags & 0x101c0) {
    if (gDIMbossSequenceFlags & 0x40) {
      i = 0;
      do {
        vec[0] = lbl_803E4C58 * (f32)(int)randomGetRange(-5, 5);
        vec[1] = lbl_803E4C58 * (f32)(int)randomGetRange(-5, 5);
        vec[2] = lbl_803E4C5C * (f32)(int)randomGetRange(2, 8);
        PSMTXMultVec((f32 *)(state + 0x64), vec, vec);
        (*gPartfxInterface)->spawnObject((void *)obj, 0x4b5, state + 0x1c, 0x200001, -1, vec);
        i = i + 1;
      } while (i < 5);
    }
    if (gDIMbossSequenceFlags & 0x80) {
      (*gPartfxInterface)->spawnObject((void *)obj, 0x4b5, state + 4, 0x200001, -1, NULL);
    }
    if (gDIMbossSequenceFlags & 0x100) {
      vec[0] = lbl_803E4C58;
      vec[1] = lbl_803E4C60;
      vec[2] = lbl_803E4C64 * (f32)(int)randomGetRange(4, 8);
      PSMTXMultVec((f32 *)(state + 0x64), vec, vec);
      (*gPartfxInterface)->spawnObject((void *)obj, 0x4b6, state + 4, 0x200001, -1, vec);
    }
    if (gDIMbossSequenceFlags & 0x10000) {
      vec[0] = lbl_803E4BD8;
      vec[1] = lbl_803E4C60;
      vec[2] = lbl_803E4C68;
      PSMTXMultVec((f32 *)(state + 0x64), vec, vec);
      memcpy(state + 0x94, vec, 0xc);
      gDIMbossSequenceFlags |= 0x20000LL;
    }
  }
  if (gDIMbossSequenceFlags & 0x4000) {
    i = 0;
    do {
      (*gPartfxInterface)->spawnObject((void *)obj, 0x4b7, NULL, 1, -1, NULL);
      i = i + 1;
    } while (i < 0x32);
  }
  if (gDIMbossSequenceFlags & 1) {
    Camera_EnableViewYOffset();
    doRumble(lbl_803E4BF8);
    CameraShake_Start(lbl_803E4BC4, lbl_803E4BC8, lbl_803E4BCC);
  }
  if (gDIMbossSequenceFlags & 0x40000) {
    Camera_EnableViewYOffset();
    doRumble(lbl_803E4C6C);
    CameraShake_Start(lbl_803E4BC8, lbl_803E4BF4, lbl_803E4BF8);
  }
  if (gDIMbossSequenceFlags & 2) {
    Camera_EnableViewYOffset();
    CameraShake_Start(lbl_803E4BD8, lbl_803E4BD8, lbl_803E4BD8);
    CameraShake_SetAllMagnitudes(lbl_803E4BD8);
  }
  if (gDIMbossSequenceFlags & 4) {
    GameBit_Set(0x25e, 1);
  }
  else {
    GameBit_Set(0x25e, 0);
  }
  gDIMbossSequenceFlags = gDIMbossSequenceFlags & 0xa1ff0;
}

extern int Obj_GetPlayerObject(void);
extern int fn_80295A04(int player, int p2);
extern void ObjMsg_SendToObject(int to, int msg, int obj, int data);
extern int *gTitleMenuControlInterfaceCopy;
extern int *gDIMbossHitEffectResource;
extern int lbl_803DDB8C;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E4C10;
extern u8 lbl_802C2348[];
extern u8 lbl_803AC994[];

typedef struct IcicleHitDesc {
    int f0;
    int f1;
    int f2;
    int f3;
} IcicleHitDesc;

typedef struct IcicleHitEntry {
    f32 q;
    f32 px;
    f32 py;
    f32 pz;
} IcicleHitEntry;

typedef struct IcicleHitFx {
    u16 a;
    u16 b;
    u16 c;
    u16 pad;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} IcicleHitFx;

/*
 * --INFO--
 *
 * Function: fn_801BC2D8
 * EN v1.0 Address: 0x801BC2D8
 * EN v1.0 Size: 1292b
 * EN v1.1 Size: 1292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801BC2D8(int obj, int param_2)
{
  int *state;
  u8 hit;
  int hitResult;
  int player;
  IcicleHitEntry *base;
  int hitType;
  uint hitVolume;
  int hitId;
  IcicleHitDesc desc;

  state = ((GameObject *)obj)->extra;
  Obj_GetPlayerObject();
  hit = 0;
  desc = *(IcicleHitDesc *)lbl_802C2348;
  if (lbl_803DDB8C != 0) {
    lbl_803DDB8C = lbl_803DDB8C - 1;
  }
  hitResult = ObjHits_GetPriorityHit(obj, &hitId, &hitType, &hitVolume);
  if (hitResult != 0) {
    gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~DIMBOSS_SEQUENCE_FLAG_0040;
    if (*(s16 *)((int)state + 0x402) == 1) {
      if ((gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_TONSIL_GUARD_ACTIVE) == 0 ||
          hitType != 2) {
        hit = 1;
      }
    }
    else if (*(s16 *)((int)state + 0x402) == 2) {
      if (hitType != 4 || ((GameObject *)obj)->anim.currentMoveProgress < lbl_803E4C10 || ((GameObject *)obj)->anim.currentMove != 0x12) {
        hit = 1;
      }
    }
    if (hit) {
      if (lbl_803DDB8C == 0) {
        Sfx_PlayFromObject(obj, 0x4b2);
        base = (IcicleHitEntry *)DIM2Icicle_GetActiveModel((void *)obj)[0x14];
        ((IcicleHitFx *)lbl_803AC994)->x = playerMapOffsetX + base[hitType].px;
        ((IcicleHitFx *)lbl_803AC994)->y = base[hitType].py;
        ((IcicleHitFx *)lbl_803AC994)->z = playerMapOffsetZ + base[hitType].pz;
        (*gPartfxInterface)->spawnObject((void *)obj, 0x328, lbl_803AC994, 0x200001, -1, NULL);
        ((IcicleHitFx *)lbl_803AC994)->x = ((IcicleHitFx *)lbl_803AC994)->x - ((GameObject *)obj)->anim.worldPosX;
        ((IcicleHitFx *)lbl_803AC994)->y = ((IcicleHitFx *)lbl_803AC994)->y - ((GameObject *)obj)->anim.worldPosY;
        ((IcicleHitFx *)lbl_803AC994)->z = ((IcicleHitFx *)lbl_803AC994)->z - ((GameObject *)obj)->anim.worldPosZ;
        ((IcicleHitFx *)lbl_803AC994)->scale = lbl_803E4C44;
        ((IcicleHitFx *)lbl_803AC994)->a = 0;
        ((IcicleHitFx *)lbl_803AC994)->b = 0;
        ((IcicleHitFx *)lbl_803AC994)->c = 0;
        desc.f1 += randomGetRange(0, 0x9b);
        desc.f2 += randomGetRange(0, 0x9b);
        ((void (*)(int, int, u8 *, int, int, IcicleHitDesc *))*(code **)(*(int *)gDIMbossHitEffectResource + 4))(obj, 0, lbl_803AC994, 1, -1, &desc);
        lbl_803DDB8C = 0x1e;
      }
    }
    else {
      if (*(void **)(param_2 + 0x2d0) == NULL) {
        player = Obj_GetPlayerObject();
        if (fn_80295A04(player, 1) != 0) {
          ((void (*)(int, int, int, int, int, int, int, int, int))*(code **)(*gBaddieControlInterface + 0x28))
                    (obj, param_2, (int)state + 0x35c, (int)*(s16 *)((int)state + 0x3f4), 0, 2, 10, -1, -1);
          *(int *)(param_2 + 0x2d0) = player;
          *(u8 *)(param_2 + 0x349) = 0;
        }
      }
      if (*(s16 *)((int)state + 0x402) == 1) {
        if (*(s8 *)(param_2 + 0x354) == 3) {
          ((void (*)(int, int, int, int, int))*(code **)(*(int *)gTitleMenuControlInterfaceCopy + 4))(obj, 0x68, 0, 0, 0);
        }
        else if (*(s8 *)(param_2 + 0x354) == 2) {
          ((void (*)(int, int, int, int, int))*(code **)(*(int *)gTitleMenuControlInterfaceCopy + 4))(obj, 0x6c, 0, 0, 0);
        }
      }
      else if (*(s16 *)((int)state + 0x402) == 2) {
        if (*(s8 *)(param_2 + 0x354) == 3) {
          ((void (*)(int, int, int, int, int))*(code **)(*(int *)gTitleMenuControlInterfaceCopy + 4))(obj, 0x77, 0, 0, 0);
        }
        else if (*(s8 *)(param_2 + 0x354) == 2) {
          ((void (*)(int, int, int, int, int))*(code **)(*(int *)gTitleMenuControlInterfaceCopy + 4))(obj, 0x78, 0, 0, 0);
        }
      }
      *(u8 *)(param_2 + 0x346) = 0;
      *(s8 *)(param_2 + 0x34f) = hitResult;
      *(u8 *)(param_2 + 0x354) -= 1;
      Sfx_PlayFromObject(obj, 0x4b1);
      if (*(s8 *)(param_2 + 0x354) <= 0) {
        *(u8 *)(param_2 + 0x354) = 0;
        *(u8 *)(param_2 + 0x349) = 0;
        ((void (*)(int, int, int))*(code **)(*(int *)gPlayerInterface + 0x14))(obj, param_2, 0);
        ((ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState)->flags &= ~1;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x80;
        GameBit_Set(0x20e, 1);
        if (*(s16 *)((int)state + 0x402) == 1) {
          GameBit_Set(0x20b, 1);
        }
        else if (*(s16 *)((int)state + 0x402) == 2) {
          GameBit_Set(0x266, 1);
        }
      }
      else if (*(s16 *)((int)state + 0x402) == 1) {
        ((void (*)(int, int, int))*(code **)(*(int *)gPlayerInterface + 0x14))(obj, param_2, 10);
      }
      else {
        ((void (*)(int, int, int))*(code **)(*(int *)gPlayerInterface + 0x14))(obj, param_2, 0xb);
      }
      ObjMsg_SendToObject(hitId, 0xe0001, obj, 0);
    }
  }
}

/*
 * --INFO--
 *
 * Function: fn_801BC7E4
 * EN v1.0 Address: 0x801BC7E4
 * EN v1.0 Size: 848b
 * EN v1.1 Size: 848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801BC7E4(int obj, int animUpdate, int runtime, int updateRuntime)
{
  IcicleState *state;
  u8 *tricky;
  f32 timer;
  f32 limit;

  state = *(IcicleState **)(runtime + 0x40c);
  tricky = (u8 *)getTrickyObject();
  ObjHits_EnableObject(obj);
  *(u8 *)(updateRuntime + 0x25f) = 1;
  ((void (*)(int, int, f32, int))*(code **)(*gBaddieControlInterface + 0x2c))(obj, updateRuntime, lbl_803E4C70, 1);
  ((void (*)(int, int, int, int, int, int, int, int))*(code **)(*gBaddieControlInterface + 0x54))
            (obj, updateRuntime, runtime + 0x35c, (int)*(s16 *)(runtime + 0x3f4), runtime + 0x405, 0, 0, 0);
  if (*(s16 *)(updateRuntime + 0x274) == 6) {
    state->meltTimer =
         -(timeDelta * (lbl_803E4BC8 * ((GameObject *)obj)->anim.currentMoveProgress + lbl_803E4C44) - state->meltTimer);
  }
  else {
    state->meltTimer = state->meltTimer - timeDelta;
  }
  if (state->meltTimer <= lbl_803E4BD8) {
    IcicleEntry *entry = (IcicleEntry *)lbl_803259E0;
    GameBit_Set(entry[state->index].bit, 1);
    state->meltTimer = *(f32 *)(lbl_803259E0 + state->index * 8);
    state->index++;
    if (state->index > 0x17) {
      state->index = 0;
    }
  }
  if (tricky != NULL) {
    timer = state->lightTimer;
    if (timer > lbl_803E4BD8) {
      limit = lbl_803E4C74;
      if (timer <= limit) {
        state->lightTimer = timer + timeDelta;
        if (state->lightTimer >= limit) {
          ((void (*)(u8 *, int, int))*(code **)(*(int *)(*(int *)(tricky + 0x68)) + 0x34))(tricky, 1, obj);
        }
      }
    }
    if (state->fadeTimer > (timer = lbl_803E4BD8)) {
      state->fadeTimer = state->fadeTimer + timeDelta;
      if (state->fadeTimer >= lbl_803E4BEC) {
        *(u16 *)(runtime + 0x400) &= ~4;
        state->fadeTimer = timer;
        ((void (*)(u8 *, int, int))*(code **)(*(int *)(*(int *)(tricky + 0x68)) + 0x34))(tricky, 0, 0);
        state->lightTimer = lbl_803E4C44;
      }
    }
    else if (*(s16 *)(runtime + 0x402) == 1) {
      *(u16 *)(runtime + 0x400) |= 4;
      state->fadeTimer = lbl_803E4C44;
      DIM2icicle_createStateLight(obj, 0);
    }
  }
  if (*(s16 *)(runtime + 0x402) == 2) {
    DIM2icicle_createStateLight(obj, 1);
  }
  {
    if (gDIMbossSequenceFlags & DIMBOSS_SEQUENCE_FLAG_SPAWN_BLUE_WHITE_EFFECT) {
      gDIMbossSequenceFlags &= ~DIMBOSS_SEQUENCE_FLAG_SPAWN_BLUE_WHITE_EFFECT;
      DIM2icicle_spawnBlueWhiteEffect((int *)(*(int *)(runtime + 0x40c) + 4), (f32 *)(*(int *)(runtime + 0x40c) + 0x94));
    }
  }
  if (*(u16 *)(runtime + 0x400) & 4) {
    gDIMbossSequenceFlags |= DIMBOSS_SEQUENCE_FLAG_TONSIL_GUARD_ACTIVE;
  }
  if (*(s16 *)(runtime + 0x402) == 1) {
    ((void (*)(u8 *, int, int, int))*(code **)(*(int *)(*(int *)(tricky + 0x68)) + 0x28))(tricky, obj, 1, 2);
    ((GameObject *)obj)->unkE4 = 1;
  }
  else {
    ((GameObject *)obj)->unkE4 = 2;
  }
  *(int *)(runtime + 0x3e0) = *(int *)&((GameObject *)obj)->unkC0;
  *(int *)&((GameObject *)obj)->unkC0 = 0;
  ((void (*)(f32, int, int, f32, void *, void *))*(code **)(*(int *)gPlayerInterface + 8))
            (timeDelta, obj, updateRuntime, timeDelta, gDIMbossHitDetectAnimTable, gDIMbossAnimTable);
  *(int *)&((GameObject *)obj)->unkC0 = *(int *)(runtime + 0x3e0);
}
