#include "main/dll/dll_80220608_shared.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/andross.h"
#include "main/mapEventTypes.h"

typedef struct AndrossUpdateModelAlphaState {
    u8 pad0[0x68 - 0x0];
    f32 unk68;
    u8 pad6C[0x70 - 0x6C];
} AndrossUpdateModelAlphaState;


int andross_getExtraSize(void) { return 0xec; }

int andross_getObjectTypeId(void) { return 0; }

void andross_free(int obj)
{
    fn_8006CB24(obj);
    Rcp_DisableDistortionFilter();
}

void andross_hitDetect(void) {}

void andross_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E74DC);
}

void andross_setPartSignal(int obj, int signal)
{
    int state;

    if ((void *)obj == NULL) {
        return;
    }
    state = *(int *)&((GameObject *)obj)->extra;
    ((AndrossState *)state)->signalFlags |= signal;
}

#pragma scheduling off
int andross_updateModelAlpha(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    int i;
    f32 v;
    f32 alpha;
    int model;
    int op;

    *(f32 *)(state + 0x68) = lbl_803E74D4;
    v = ((AndrossState *)state)->fadeAlpha;
    model = *(int *)Obj_GetActiveModel(obj);
    alpha = lbl_803E74B4 * v;
    for (i = 0; i < *(u8 *)(model + 0xf8); i++) {
        op = ObjModel_GetRenderOp(model, i);
        *(s8 *)(op + 0x43) = alpha;
    }
    return 0;
}

#pragma peephole off
void andross_init(int obj, u8 *setup)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    int i;
    int model;

    ((AndrossState *)state)->homePosX = ((ObjPlacement *)setup)->posX;
    ((AndrossState *)state)->homePosY = ((ObjPlacement *)setup)->posY;
    ((AndrossState *)state)->homePosZ = ((ObjPlacement *)setup)->posZ;
    ((AndrossState *)state)->actionTimer = 0;
    ((AndrossState *)state)->actionState = 0;
    ((AndrossState *)state)->prevActionState = -1;
    ((AndrossState *)state)->animSpeed = lbl_803E7590;
    ((AndrossState *)state)->unkB6 = 5;
    ((AndrossState *)state)->fightPhase = 1;
    ((AndrossState *)state)->prevFightPhase = -1;
    ((AndrossState *)state)->unkA0 = -0x8000;
    *(s16 *)obj = -0x8000;
    ((AndrossState *)state)->spawnCooldown = lbl_803E7594;
    ((AndrossState *)state)->unkA8 = lbl_803E74D4;
    ((AndrossState *)state)->springStiffness = lbl_803E7598;
    ((AndrossState *)state)->springDamping = lbl_803E7530;
    ((AndrossState *)state)->unkBC = 1;
    ObjHits_SetTargetMask(obj, 4);
    ((GameObject *)obj)->animEventCallback = (void *)andross_updateModelAlpha;
    fn_8006CB50();
    model = *(int *)Obj_GetActiveModel(obj);
    for (i = 0; i < *(u8 *)(model + 0xf8); i++) {
        *(u8 *)(ObjModel_GetRenderOp(model, i) + 0x43) = 0;
    }
    GameBit_Set(0xd, 0);
    unlockLevel(0, 0, 1);
}

void fn_8023A87C(int p1, int p2)
{
    void *spawned;

    spawned = *(void **)(p2 + 0x10);
    if (spawned != NULL) {
        *(f32 *)((char *)spawned + 0x14) -= lbl_803E74D8;
        ((AndrossState *)p2)->effectLifetime -= framesThisStep;
        if (((AndrossState *)p2)->effectLifetime < 0) {
            fn_8022F558(((AndrossState *)p2)->effectHandle, 5);
            ((AndrossState *)p2)->effectLifetime = 0;
            ((AndrossState *)p2)->effectHandle = 0;
        }
    } else {
        f32 v = ((AndrossState *)p2)->spawnCooldown;
        f32 zero = lbl_803E74D4;
        if (v >= zero) {
            ((AndrossState *)p2)->spawnCooldown = v - timeDelta;
            if (((AndrossState *)p2)->spawnCooldown < zero)
                fn_80239DD8(p1, p2);
        } else if ((u32)GameBit_Get(0x12) != 0) {
            ((AndrossState *)p2)->spawnCooldown = (f32)(int)randomGetRange(1, 0x14);
            GameBit_Set(0x12, 0);
        }
    }
}

int fn_8023A6A4(int p1, f32 a, f32 b, f32 c)
{
    f32 val, ang;
    f32 dx, dy, dz, dist;
    int yaw;
    int result;
    f32 vel[3];

    result = 0;
    dx = *(f32 *)(p1 + 0xc0) - *(f32 *)(*(int *)p1 + 0xc);
    dy = *(f32 *)(p1 + 0xc4) - *(f32 *)(*(int *)p1 + 0x10);
    dz = *(f32 *)(p1 + 0xc8) - *(f32 *)(*(int *)p1 + 0x14);
    dist = sqrtf(dx * dx + dy * dy);
    yaw = (s16)getAngle(dx, dy);
    if ((s16)getAngle(dist, dz) > 0x2ee0 && dz > lbl_803DC4C0)
        result = 1;
    val = dist / b;
    if (val < -a)
        val = -a;
    else if (val > a)
        val = a;
    ang = lbl_803E74A0 * (f32)yaw / lbl_803E74A4;
    *(f32 *)(p1 + 0xd8) = val * mathSinf(ang);
    *(f32 *)(p1 + 0xdc) = val * mathCosf(ang);
    arwarwing_getVelocity((int)vel, *(int *)p1);
    *(f32 *)(p1 + 0xd8) -= vel[0] * lbl_803DC4C4;
    *(f32 *)(p1 + 0xdc) -= vel[1] * lbl_803DC4C4;
    *(f32 *)(p1 + 0xe0) = c;
    return result;
}

extern f32 lbl_8032C098[];
extern f32 lbl_803DC440;
extern f32 lbl_803DC444;
extern f32 lbl_803DC448;
extern f32 lbl_803DC454;
extern f32 lbl_803DC458;
extern f32 lbl_803DC45C;
extern f32 lbl_803DC468;
extern f32 lbl_803DC470;
extern f32 lbl_803DC474;
extern f32 lbl_803DC478;
extern f32 lbl_803DC47C;
extern f32 lbl_803DC480;
extern f32 lbl_803DC488;
extern f32 lbl_803DC490;
extern f32 lbl_803DC494;
extern f32 lbl_803DC498;
extern f32 lbl_803DC49C;
extern f32 lbl_803DC4A0;
extern f32 lbl_803DC4A4;
extern f32 lbl_803DC4A8;
extern f32 lbl_803DC4AC;
extern f32 lbl_803DC4B0;
extern f32 lbl_803DC4B4;
extern f32 lbl_803DC4B8;
extern f32 lbl_803DC4D0;
extern f32 lbl_803DC4D4;
extern f32 lbl_803DDDB8;
extern f32 lbl_803E74B8;
extern f32 lbl_803E74BC;
extern f32 lbl_803E74C0;
extern f32 lbl_803E74C4;
extern f32 lbl_803E74C8;
extern f32 lbl_803E74CC;
extern f32 lbl_803E74D0;
extern f32 lbl_803E74E0;
extern f32 lbl_803E74E4;
extern f32 lbl_803E74E8;
extern f32 lbl_803E74EC;
extern f32 lbl_803E74F0;
extern f32 lbl_803E74F4;
extern f32 lbl_803E74F8;
extern f32 lbl_803E74FC;
extern f32 lbl_803E7500;
extern f32 lbl_803E7504;
extern f32 lbl_803E7508;
extern f32 lbl_803E750C;
extern f32 lbl_803E7510;
extern f32 lbl_803E7514;
extern f32 lbl_803E7518;
extern f32 lbl_803E751C;
extern f32 lbl_803E7520;
extern f32 lbl_803E7524;
extern f32 lbl_803E7528;
extern f32 lbl_803E752C;
extern f32 lbl_803E7534;
extern f32 lbl_803E7538;
extern f32 lbl_803E753C;
extern f32 lbl_803E7578;
extern f32 lbl_803E757C;
extern f32 lbl_803E7580;
extern f32 lbl_803E7584;
extern f64 lbl_803E7540;
extern f64 lbl_803E7548;
extern f64 lbl_803E7550;
extern f64 lbl_803E7558;
extern f64 lbl_803E7560;
extern f64 lbl_803E7568;
extern f64 lbl_803E7570;
extern int animatedObjGetSeqId(int obj);
extern int lbl_8032C088[];
extern f32 lbl_8032C09C[];
extern f32 lbl_8032C0A0[];
extern f32 lbl_8032C0A4[];
extern f32 lbl_8032C0A8[];
extern f32 lbl_8032C0C8[];
extern f32 lbl_8032C0CC[];
extern f32 lbl_8032C0D0[];
extern f32 lbl_8032C0D8[];
extern f32 lbl_8032C0DC[];
extern f32 lbl_8032C0E0[];
extern f32 lbl_8032C0E4[];
extern f32 lbl_8032C0E8[];
extern f32 lbl_8032C0EC[];
extern f32 lbl_8032C0F0[];
extern int lbl_803DC430;
extern int lbl_803DC434;
extern int lbl_803DC438;
extern int lbl_803DC43C;
extern int lbl_803DC44C;
extern int lbl_803DC450;
extern int lbl_803DC460;
extern int lbl_803DC464;
extern int lbl_803DC46C;
extern int lbl_803DC484;
extern int lbl_803DC48C;
extern int lbl_803DC4EC;
extern s16 lbl_803DC4BC;
extern s16 lbl_803DC4BE;
extern s16 lbl_803DDDC8;
extern s16 lbl_803DDDCA;
extern f32 lbl_803DC4CC;
extern void turnOnDistortionFilter(f32 *pos, f32 a, f32 *b, f32 c);

typedef struct {
    u8 f80 : 1;
    u8 f40 : 1;
    u8 f20 : 1;
} AndrossFlagByte;

void andross_update(int obj)

{
  int *piVar14;
  u8 stateChanged;
  u8 moveChanged;
  int iVar12;
  u8 pathFlag;
  int iVar8;
  u32 uVar6;
  float fVar2;
  short sVar3;
  int iVar5;
  char cVar11;
  s16 uVar10;
  int *piVar7;
  int uVar9;
  u8 bVar13;
  u8 bVar15;
  f32 dVar16;
  f32 dVar17;
  f32 dVar18;
  f32 dVar19;
  float local_148;
  float local_144;
  float local_140;
  float local_13c;
  float local_138;
  float local_134;
  short local_130 [2];
  SunVec3 local_12c;
  SunVec3 local_120;
  SunVec3 local_114;
  SunVec3 local_108;
  SunVec3 local_fc;
  SunVec3 local_f0;
  SunVec3 local_e4;
  SunVec3 local_d8;
  SunVec3 local_cc;
  SunVec3 local_c0;
  SunVec3 local_b4;
  SunVec3 local_a8;
  SunVec3 local_9c;
  f32 local_90;
  f32 local_88;
  f32 local_80;
  f32 local_78;
  u32 uStack100;
  f32 local_50;
    piVar14 = ((GameObject *)obj)->extra;
  moveChanged = 0;
  stateChanged = 0;
  pathFlag = 0;
  if (*(u8 *)((int)piVar14 + 0xb6) != 0) {
    *(u8 *)((int)piVar14 + 0xb6) -= 1;
    goto LAB_8023ef14;
  }
  if (*(void * *)&((AndrossState *)piVar14)->handObjA == NULL) {
    iVar5 = ObjList_FindObjectById(0x47b78);
    ((AndrossState *)piVar14)->handObjA = iVar5;
  }
  if (*(void * *)&((AndrossState *)piVar14)->handObjB == NULL) {
    iVar5 = ObjList_FindObjectById(0x47b6a);
    ((AndrossState *)piVar14)->handObjB = iVar5;
  }
  if (*(void * *)&((AndrossState *)piVar14)->lightAnchorObj == NULL) {
    iVar5 = ObjList_FindObjectById(0x47dd9);
    ((AndrossState *)piVar14)->lightAnchorObj = iVar5;
  }
  if (*(void **)piVar14 == NULL) {
    iVar5 = getArwing();
    *piVar14 = iVar5;
    if (*(void **)piVar14 == NULL) goto LAB_8023ef14;
    ((AndrossState *)piVar14)->unk70 = *(f32 *)(*piVar14 + 0x14);
        arwarwing_setFlightHalfWidth(*piVar14,(f32)lbl_803DC438);
  }
  for (iVar8 = 0; (u8)iVar8 < 4; iVar8 = iVar8 + 1) {
    uVar6 = (u8)iVar8;
    if (*(void **)((int)piVar14 + uVar6 * 4 + 0x18) == NULL) {
      *(int *)((int)piVar14 + uVar6 * 4 + 0x18) = ObjList_FindObjectById(lbl_8032C088[uVar6]);
      if (*(void **)((int)piVar14 + uVar6 * 4 + 0x18) != NULL) {
        *(f32 *)(piVar14 + uVar6 * 3 + 10) = *(float *)(*(int *)((int)piVar14 + uVar6 * 4 + 0x18) + 0xc) - ((GameObject *)obj)->anim.localPosX;
        *(f32 *)(piVar14 + uVar6 * 3 + 0xb) = *(float *)(*(int *)((int)piVar14 + uVar6 * 4 + 0x18) + 0x10) - ((GameObject *)obj)->anim.localPosY;
        *(f32 *)(piVar14 + uVar6 * 3 + 0xc) = *(float *)(*(int *)((int)piVar14 + uVar6 * 4 + 0x18) + 0x14) - ((GameObject *)obj)->anim.localPosZ;
      }
    }
    else {
      *(float *)(*(int *)((int)piVar14 + uVar6 * 4 + 0x18) + 0xc) = ((GameObject *)obj)->anim.localPosX + *(f32 *)(piVar14 + uVar6 * 3 + 10)
      ;
      *(float *)(*(int *)((int)piVar14 + uVar6 * 4 + 0x18) + 0x10) =
           ((GameObject *)obj)->anim.localPosY + *(f32 *)(piVar14 + uVar6 * 3 + 0xb);
      *(float *)(*(int *)((int)piVar14 + uVar6 * 4 + 0x18) + 0x14) =
           ((GameObject *)obj)->anim.localPosZ + *(f32 *)(piVar14 + uVar6 * 3 + 0xc);
    }
  }
  iVar5 = ((AndrossState *)piVar14)->fightPhase;
  if (iVar5 != ((AndrossState *)piVar14)->prevFightPhase) {
    stateChanged = 1;
  }
  ((AndrossState *)piVar14)->prevFightPhase = iVar5;
  fVar2 = lbl_803E74D4;
  ((AndrossState *)piVar14)->unkD8 = lbl_803E74D4;
  ((AndrossState *)piVar14)->unkDC = fVar2;
  ((AndrossState *)piVar14)->unkE0 = fVar2;
  if ((-0x4000 < ((AndrossState *)piVar14)->unkA0) && (*(s16 *)obj < 0x4000)) {
    pathFlag = 1;
  }
  ObjPath_GetPointWorldPosition(obj,pathFlag,(f32 *)(piVar14 + 0x30),(f32 *)(piVar14 + 0x31),(f32 *)(piVar14 + 0x32),0);
  fVar2 = lbl_803E74E0;
  if (pathFlag == 1) {
    ((AndrossState *)piVar14)->cachedPosY = ((AndrossState *)piVar14)->cachedPosY + lbl_803E74E0;
    ((AndrossState *)piVar14)->cachedPosZ = ((AndrossState *)piVar14)->cachedPosZ + fVar2;
  }
  switch (((AndrossState *)piVar14)->fightPhase) {
  case 1:
        if (stateChanged) {
          if (((AndrossState *)piVar14)->unkBC != 0) {
            ((AndrossState *)piVar14)->unkBC = 0;
          }
          else {
            androsshand_setState(((AndrossState *)piVar14)->handObjA,2,1);
            androsshand_setState(((AndrossState *)piVar14)->handObjB,2,1);
          }
          *(undefined *)((int)piVar14 + 0xae) = 10;
          *(undefined *)((int)piVar14 + 0xaf) = 10;
          ((AndrossState *)piVar14)->unkB0 = 10;
        }
        if (((AndrossState *)piVar14)->actionPending != 0) {
          switch (((AndrossState *)piVar14)->actionState) {
          default:
          case 3:
          case 0x17:
            ((AndrossState *)piVar14)->actionState = 0;
            break;
          case 0:
            ((AndrossState *)piVar14)->actionState = 1;
            break;
          case 0x16:
            if (*(u8 *)(piVar14 + 0x2e) != 0) {
              ((AndrossState *)piVar14)->actionState = 0x17;
            }
            else {
              ((AndrossState *)piVar14)->actionState = 0;
            }
            break;
          }
          ((AndrossState *)piVar14)->actionPending = 0;
        }
    break;
  case 2:
      if ((stateChanged) &&
         (*(u8 *)((int)piVar14 + 0xad) = *(u8 *)((int)piVar14 + 0xad) & ~0x6,
         ((AndrossState *)piVar14)->actionState == 0x16)) {
        androsshand_setState(((AndrossState *)piVar14)->handObjA,1,1);
        androsshand_setState(((AndrossState *)piVar14)->handObjB,1,1);
      }
      if (((AndrossState *)piVar14)->actionPending != 0) {
        switch(((AndrossState *)piVar14)->actionState) {
        default:
          ((AndrossState *)piVar14)->actionState = 6;
          break;
        case 6:
          ((AndrossState *)piVar14)->actionState = 7;
          break;
        case 7:
          ((AndrossState *)piVar14)->actionState = 10;
          break;
        case 10:
          ((AndrossState *)piVar14)->actionState = 0x12;
          break;
        case 0x14:
          ((AndrossState *)piVar14)->actionState = 0xb;
          break;
        case 0x11:
          ((AndrossState *)piVar14)->actionState = 0x16;
          ((AndrossState *)piVar14)->unkA0 = 0x8000;
          ((AndrossState *)piVar14)->fightPhase = ((AndrossState *)piVar14)->fightPhase + -1;
        }
        ((AndrossState *)piVar14)->actionPending = 0;
      }
    break;
  case 3:
      if (stateChanged) {
        *(undefined *)((int)piVar14 + 0xae) = 0xf;
        *(undefined *)((int)piVar14 + 0xaf) = 0xf;
        ((AndrossState *)piVar14)->unkB0 = 0xf;
        ((AndrossState *)piVar14)->actionState = 0;
        *(undefined *)((int)piVar14 + 0xb7) = 0;
      }
      if (((AndrossState *)piVar14)->actionPending != 0) {
        switch (((AndrossState *)piVar14)->actionState) {
        default:
        case 0:
          ((AndrossState *)piVar14)->actionState = 1;
          break;
        case 3:
          ((AndrossState *)piVar14)->actionState = 4;
          break;
        case 4:
          *(char *)((int)piVar14 + 0xb7) = *(char *)((int)piVar14 + 0xb7) + '\x01';
          if (*(u8 *)((int)piVar14 + 0xb7) < 4) {
            ((AndrossState *)piVar14)->actionState = 0;
          }
          else {
            ((AndrossState *)piVar14)->fightPhase = ((AndrossState *)piVar14)->fightPhase + -1;
            ((AndrossState *)piVar14)->actionState = 0x16;
            ((AndrossState *)piVar14)->unkA0 = 0;
          }
          break;
        }
        ((AndrossState *)piVar14)->actionPending = 0;
      }
    break;
  case 4:
    if (((AndrossState *)piVar14)->actionPending != 0) {
      switch(((AndrossState *)piVar14)->actionState) {
      default:
        ((AndrossState *)piVar14)->actionState = 6;
        break;
      case 6:
        ((AndrossState *)piVar14)->actionState = 7;
        break;
      case 7:
        ((AndrossState *)piVar14)->actionState = 10;
        break;
      case 10:
        ((AndrossState *)piVar14)->actionState = 0x12;
        break;
      case 0x14:
        ((AndrossState *)piVar14)->actionState = 0xb;
        break;
      case 0xf:
        ((AndrossState *)piVar14)->actionState = 9;
        break;
      case 9:
        ((AndrossState *)piVar14)->actionState = 8;
        break;
      case 0x11:
        ((AndrossState *)piVar14)->actionState = 0x18;
      }
      ((AndrossState *)piVar14)->actionPending = 0;
    }
    break;
  case 5:
    if (stateChanged) {
      ((AndrossState *)piVar14)->actionState = 0xd;
      ((AndrossState *)piVar14)->actionToggle = 0;
    }
    if (((AndrossState *)piVar14)->actionPending != 0) {
      switch(((AndrossState *)piVar14)->actionState) {
      default:
        *(undefined *)((int)piVar14 + 0xb1) = 3;
      case 0xf:
        ((AndrossState *)piVar14)->actionState = 0x12;
        ((AndrossState *)piVar14)->actionToggle = 0;
        break;
      case 0x14:
        switch (((AndrossState *)piVar14)->actionToggle) {
        case 0:
          ((AndrossState *)piVar14)->actionState = 0x15;
          break;
        case 1:
          ((AndrossState *)piVar14)->actionState = 0xb;
          break;
        }
        ((AndrossState *)piVar14)->actionToggle = ((AndrossState *)piVar14)->actionToggle ^ 1;
        break;
      case 0x15:
        ((AndrossState *)piVar14)->actionState = 0x12;
        break;
      case 0x11:
        ((AndrossState *)piVar14)->actionState = 0x18;
        break;
      case 0x19:
        ((AndrossState *)piVar14)->fightPhase = 6;
        break;
      case 0x1a:
        ((AndrossState *)piVar14)->actionState = 0x1b;
      }
      ((AndrossState *)piVar14)->actionPending = 0;
    }
    break;
  case 6:
    if (stateChanged) {
      ((AndrossState *)piVar14)->actionState = 0x1c;
      ((AndrossState *)piVar14)->actionToggle = 0;
    }
    break;
  }
  iVar5 = ((AndrossState *)piVar14)->actionState;
  if (iVar5 != ((AndrossState *)piVar14)->prevActionState) {
    moveChanged = 1;
  }
  ((AndrossState *)piVar14)->prevActionState = iVar5;
  switch(((AndrossState *)piVar14)->actionState) {
  case 0:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C098[0];
      if (((AndrossState *)piVar14)->fightPhase == 1) {
        ((AndrossState *)piVar14)->durationTimer = lbl_803E74E4;
      }
      else {
        ((AndrossState *)piVar14)->durationTimer = lbl_803E74E8;
      }
    }
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E74EC) ? lbl_803E74EC : ((dVar17 > lbl_803E74F0) ? lbl_803E74F0 : dVar17);
    dVar17 = (dVar16 < lbl_803E74F4) ? lbl_803E74F4 : ((dVar16 > lbl_803E74F8) ? lbl_803E74F8 : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74CC * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    ((AndrossState *)piVar14)->durationTimer = ((AndrossState *)piVar14)->durationTimer - timeDelta;
    if (((AndrossState *)piVar14)->durationTimer < lbl_803E74D4) {
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    if ((u32)*(u8 *)((int)piVar14 + 0xae) + (u32)*(u8 *)((int)piVar14 + 0xaf) +
        (u32)((AndrossState *)piVar14)->unkB0 == 0) {
      ((AndrossState *)piVar14)->fightPhase = ((AndrossState *)piVar14)->fightPhase + 1;
      ((AndrossState *)piVar14)->actionState = 5;
      ((AndrossState *)piVar14)->actionPending = 0;
      GameBit_Set(0xd,0);
    }
    break;
  case 1:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0xc,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0C8[0];
    }
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E74EC) ? lbl_803E74EC : ((dVar17 > lbl_803E74F0) ? lbl_803E74F0 : dVar17);
    dVar17 = (dVar16 < lbl_803E74F4) ? lbl_803E74F4 : ((dVar16 > lbl_803E74F8) ? lbl_803E74F8 : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74CC * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E74DC) {
      ((AndrossState *)piVar14)->actionState = 2;
      ((AndrossState *)piVar14)->actionPending = 0;
    }
    if ((u32)*(u8 *)((int)piVar14 + 0xae) + (u32)*(u8 *)((int)piVar14 + 0xaf) +
        (u32)((AndrossState *)piVar14)->unkB0 == 0) {
      ((AndrossState *)piVar14)->fightPhase = ((AndrossState *)piVar14)->fightPhase + 1;
      ((AndrossState *)piVar14)->actionState = 5;
      ((AndrossState *)piVar14)->actionPending = 0;
      GameBit_Set(0xd,0);
    }
    break;
  case 2:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0xe,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0D0[0];
      ((AndrossState *)piVar14)->durationTimer = lbl_803E74F0;
      ((AndrossState *)piVar14)->actionTimer = 0xffff;
    }
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E74EC) ? lbl_803E74EC : ((dVar17 > lbl_803E74F0) ? lbl_803E74F0 : dVar17);
    dVar17 = (dVar16 < lbl_803E74F4) ? lbl_803E74F4 : ((dVar16 > lbl_803E74F8) ? lbl_803E74F8 : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74CC * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    Sfx_KeepAliveLoopedObjectSound(obj,0x467);
    ((AndrossState *)piVar14)->actionTimer -= framesThisStep;
    if (((AndrossState *)piVar14)->actionTimer < 0) {
      fn_8023A268(obj,(int)piVar14,0);
      ((AndrossState *)piVar14)->actionTimer = (short)lbl_803DC43C;
    }
    ((AndrossState *)piVar14)->durationTimer = ((AndrossState *)piVar14)->durationTimer - timeDelta;
    if (((AndrossState *)piVar14)->durationTimer < lbl_803E74D4) {
      ((AndrossState *)piVar14)->actionState = 3;
      ((AndrossState *)piVar14)->actionPending = 0;
    }
    if ((u32)*(u8 *)((int)piVar14 + 0xae) + (u32)*(u8 *)((int)piVar14 + 0xaf) +
        (u32)((AndrossState *)piVar14)->unkB0 == 0) {
      ((AndrossState *)piVar14)->fightPhase = ((AndrossState *)piVar14)->fightPhase + 1;
      ((AndrossState *)piVar14)->actionState = 5;
      ((AndrossState *)piVar14)->actionPending = 0;
      GameBit_Set(0xd,0);
    }
    break;
  case 3:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0xd,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0CC[0];
    }
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E74EC) ? lbl_803E74EC : ((dVar17 > lbl_803E74F0) ? lbl_803E74F0 : dVar17);
    dVar17 = (dVar16 < lbl_803E7500) ? lbl_803E7500 : ((dVar16 > lbl_803E74CC) ? lbl_803E74CC : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74CC * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E74DC) {
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    break;
  case 4:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C098[0];
      GameBit_Set(0xd,1);
      ((AndrossState *)piVar14)->durationTimer = lbl_803E7504;
    }
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E74EC) ? lbl_803E74EC : ((dVar17 > lbl_803E74F0) ? lbl_803E74F0 : dVar17);
    dVar17 = (dVar16 < lbl_803E7500) ? lbl_803E7500 : ((dVar16 > lbl_803E74CC) ? lbl_803E74CC : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74CC * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    ((AndrossState *)piVar14)->durationTimer = ((AndrossState *)piVar14)->durationTimer - timeDelta;
    if (((AndrossState *)piVar14)->durationTimer < lbl_803E74D4) {
      ((AndrossState *)piVar14)->actionPending = 1;
      GameBit_Set(0xd,0);
    }
    if ((u32)*(u8 *)((int)piVar14 + 0xae) + (u32)*(u8 *)((int)piVar14 + 0xaf) +
        (u32)((AndrossState *)piVar14)->unkB0 == 0) {
      ((AndrossState *)piVar14)->fightPhase = ((AndrossState *)piVar14)->fightPhase + 1;
      ((AndrossState *)piVar14)->actionState = 5;
      ((AndrossState *)piVar14)->actionPending = 0;
      GameBit_Set(0xd,0);
    }
    break;
  case 0x15:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C098[0];
      GameBit_Set(0xd,1);
      ((AndrossState *)piVar14)->durationTimer = lbl_803E7504;
    }
    for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
      if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
        goto LAB_8023bb18;
      }
    }
    *(s16 *)((int)piVar14 + 0xa6) -= framesThisStep;
    if (*(short *)((int)piVar14 + 0xa6) < 1) {
      iVar12 = randomGetRange(0,5);
      GameBit_Set(iVar12 + 0x108,1);
      *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
    }
LAB_8023bb18:
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E74EC) ? lbl_803E74EC : ((dVar17 > lbl_803E74F0) ? lbl_803E74F0 : dVar17);
    dVar17 = (dVar16 < lbl_803E7500) ? lbl_803E7500 : ((dVar16 > lbl_803E74CC) ? lbl_803E74CC : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74CC * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    ((AndrossState *)piVar14)->durationTimer = ((AndrossState *)piVar14)->durationTimer - timeDelta;
    if (((AndrossState *)piVar14)->durationTimer < lbl_803E74D4) {
      ((AndrossState *)piVar14)->actionPending = 1;
      GameBit_Set(0xd,0);
    }
    break;
  case 6:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C098[0];
      androsshand_setState(((AndrossState *)piVar14)->handObjB,4,0);
    }
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E7508) ? lbl_803E7508 : ((dVar17 > lbl_803E750C) ? lbl_803E750C : dVar17);
    dVar17 = (dVar16 < lbl_803E74F4) ? lbl_803E74F4 : ((dVar16 > lbl_803E74F8) ? lbl_803E74F8 : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74E8 * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    bVar15 = 0;
    iVar5 = *(int *)&((GameObject *)obj)->extra;
    bVar13 = ((AndrossState *)iVar5)->signalFlags;
    if ((bVar13 & 1) != 0) {
      *(u8 *)(iVar5 + 0xad) = bVar13 & ~1;
      bVar15 = 1;
    }
    if (bVar15 != 0) {
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    break;
  case 7:
    if (moveChanged) {
      androsshand_setState(((AndrossState *)piVar14)->handObjA,4,0);
    }
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E7508) ? lbl_803E7508 : ((dVar17 > lbl_803E750C) ? lbl_803E750C : dVar17);
    dVar17 = (dVar16 < lbl_803E74F4) ? lbl_803E74F4 : ((dVar16 > lbl_803E74F8) ? lbl_803E74F8 : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74E8 * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    bVar15 = 0;
    iVar5 = *(int *)&((GameObject *)obj)->extra;
    bVar13 = ((AndrossState *)iVar5)->signalFlags;
    if ((bVar13 & 1) != 0) {
      *(u8 *)(iVar5 + 0xad) = bVar13 & ~1;
      bVar15 = 1;
    }
    if (bVar15 != 0) {
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    break;
  case 9:
    if (moveChanged) {
      androsshand_setState(((AndrossState *)piVar14)->handObjA,6,0);
    }
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E74EC) ? lbl_803E74EC : ((dVar17 > lbl_803E74F0) ? lbl_803E74F0 : dVar17);
    dVar17 = (dVar16 < lbl_803E7500) ? lbl_803E7500 : ((dVar16 > lbl_803E74CC) ? lbl_803E74CC : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74CC * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    bVar15 = 0;
    iVar5 = *(int *)&((GameObject *)obj)->extra;
    bVar13 = ((AndrossState *)iVar5)->signalFlags;
    if ((bVar13 & 1) != 0) {
      *(u8 *)(iVar5 + 0xad) = bVar13 & ~1;
      bVar15 = 1;
    }
    if (bVar15 != 0) {
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    break;
  case 8:
    if (moveChanged) {
      androsshand_setState(((AndrossState *)piVar14)->handObjB,6,0);
    }
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E74EC) ? lbl_803E74EC : ((dVar17 > lbl_803E74F0) ? lbl_803E74F0 : dVar17);
    dVar17 = (dVar16 < lbl_803E7500) ? lbl_803E7500 : ((dVar16 > lbl_803E74CC) ? lbl_803E74CC : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74CC * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    bVar15 = 0;
    iVar5 = *(int *)&((GameObject *)obj)->extra;
    bVar13 = ((AndrossState *)iVar5)->signalFlags;
    if ((bVar13 & 1) != 0) {
      *(u8 *)(iVar5 + 0xad) = bVar13 & ~1;
      bVar15 = 1;
    }
    if (bVar15 != 0) {
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    break;
  case 10:
    if ((*(u8 *)((int)piVar14 + 0xad) & 6) == 6) {
      ((AndrossState *)piVar14)->fightPhase = ((AndrossState *)piVar14)->fightPhase + 1;
      if (((AndrossState *)piVar14)->fightPhase < 5) {
        iVar12 = randomGetRange(0,1);
        if (iVar12 == 0) {
          uVar9 = 0x472;
        }
        else {
          uVar9 = 0x471;
        }
        Sfx_PlayFromObject(obj,uVar9);
        ((AndrossState *)piVar14)->actionState = 0x16;
        ((AndrossState *)piVar14)->unkA0 = 0x8000;
      }
    }
    else {
      lbl_803DDDCA += lbl_803DC4BC;
      lbl_803DDDC8 += lbl_803DC4BE;
      dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
      dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
      dVar19 = (dVar17 < lbl_803E7508) ? lbl_803E7508 : ((dVar17 > lbl_803E750C) ? lbl_803E750C : dVar17);
      dVar17 = (dVar16 < lbl_803E74F4) ? lbl_803E74F4 : ((dVar16 > lbl_803E74F8) ? lbl_803E74F8 : dVar16);
            dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA))
                                            / lbl_803E74A4));
      ((AndrossState *)piVar14)->targetPosX = (lbl_803E74E8 * dVar16 +
                       (float)(((AndrossState *)piVar14)->homePosX + dVar19));
            dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8))
                                            / lbl_803E74A4));
      ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                       (float)(((AndrossState *)piVar14)->homePosY + dVar17));
      ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
      if (moveChanged) {
        androsshand_setState(((AndrossState *)piVar14)->handObjA,5,0);
        androsshand_setState(((AndrossState *)piVar14)->handObjB,5,0);
      }
      bVar15 = 0;
      iVar5 = *(int *)&((GameObject *)obj)->extra;
      bVar13 = *(u8 *)(iVar5 + 0xad);
      if ((bVar13 & 1) != 0) {
        ((AndrossState *)iVar5)->signalFlags = bVar13 & ~1;
        bVar15 = 1;
      }
      if (bVar15 != 0) {
        ((AndrossState *)piVar14)->actionPending = 1;
      }
    }
    break;
  case 0xb:
  case 0xd:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,1,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C09C[0];
      if (((AndrossState *)piVar14)->fightPhase < 5) {
        androsshand_setState(((AndrossState *)piVar14)->handObjA,0,0);
        androsshand_setState(((AndrossState *)piVar14)->handObjB,0,0);
      }
      else {
        androsshand_setState(((AndrossState *)piVar14)->handObjA,9,1);
        androsshand_setState(((AndrossState *)piVar14)->handObjB,9,1);
        *(u8 *)((int)piVar14 + 0xad) = *(u8 *)((int)piVar14 + 0xad) | 6;
      }
    }
    if ((((AndrossState *)piVar14)->fightPhase == 5) && (((AndrossState *)piVar14)->actionState == 0xb)) {
      for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
        if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
          *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023c584;
        }
      }
      *(s16 *)((int)piVar14 + 0xa6) -= framesThisStep;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = randomGetRange(0,5);
        GameBit_Set(iVar12 + 0x108,1);
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023c584:
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E7510) ? lbl_803E7510 : ((dVar17 > lbl_803E74FC) ? lbl_803E74FC : dVar17);
    dVar17 = (dVar16 < lbl_803E74F4) ? lbl_803E74F4 : ((dVar16 > lbl_803E74F8) ? lbl_803E74F8 : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74FC * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E7514 * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E74DC) {
      switch (((AndrossState *)piVar14)->actionState) {
      default:
      case 0xb:
      case 0xc:
        ((AndrossState *)piVar14)->actionState = 0xc;
        break;
      case 0xd:
        ((AndrossState *)piVar14)->actionState = 0xe;
        break;
      }
    }
    fVar2 = lbl_803E74B8 * ((GameObject *)obj)->anim.currentMoveProgress;
    if (fVar2 < lbl_803E74B8) {
      dVar19 = -(lbl_803E74C0 * (lbl_803E74C4 * fVar2) - lbl_803E74BC);
      if (fVar2 < lbl_803E74C8) {
        lbl_803DDDB8 = lbl_803DC4D4;
      }
    }
    else {
      dVar19 = lbl_803E74CC;
    }
    lbl_803DDDB8 += lbl_803DC4D0;
    if (lbl_803DDDB8 > lbl_803E74D0) {
      lbl_803DDDB8 -= lbl_803E74D0;
    }
    turnOnDistortionFilter((f32 *)(piVar14 + 0x30),dVar19,&lbl_803DC4CC,lbl_803DDDB8);
    break;
  case 0xe:
    fVar2 = lbl_803E74B8 * ((GameObject *)obj)->anim.currentMoveProgress + lbl_803E74B8;
    if (fVar2 < lbl_803E74B8) {
      dVar19 = -(lbl_803E74C0 * (lbl_803E74C4 * fVar2) - lbl_803E74BC);
      if (fVar2 < lbl_803E74C8) {
        lbl_803DDDB8 = lbl_803DC4D4;
      }
    }
    else {
      dVar19 = lbl_803E74CC;
    }
    lbl_803DDDB8 += lbl_803DC4D0;
    if (lbl_803DDDB8 > lbl_803E74D0) {
      lbl_803DDDB8 -= lbl_803E74D0;
    }
    turnOnDistortionFilter((f32 *)(piVar14 + 0x30),dVar19,&lbl_803DC4CC,lbl_803DDDB8);
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,2,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0A0[0];
      *(undefined *)((int)piVar14 + 0xb1) = 0;
      GameBit_Set(0x10,0);
      ((AndrossState *)piVar14)->actionTimer = (short)lbl_803DC44C;
      ((AndrossState *)piVar14)->durationTimer = lbl_803E74D4;
    }
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E74EC) ? lbl_803E74EC : ((dVar17 > lbl_803E74F0) ? lbl_803E74F0 : dVar17);
    dVar17 = (dVar16 < lbl_803E7508) ? lbl_803E7508 : ((dVar16 > lbl_803E750C) ? lbl_803E750C : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74FC * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E7514 * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    fn_8023A6A4((int)piVar14,lbl_803DC440,lbl_803DC444,lbl_803DC448);
    Sfx_KeepAliveLoopedObjectSound(obj,0x466);
    if ((((AndrossState *)piVar14)->actionTimer != 0) &&
       (((AndrossState *)piVar14)->actionTimer -= framesThisStep,
       ((AndrossState *)piVar14)->actionTimer < 1)) {
      ((AndrossState *)piVar14)->actionTimer = 0;
      GameBit_Set(0xf,1);
    }
    ((AndrossState *)piVar14)->durationTimer = ((AndrossState *)piVar14)->durationTimer - timeDelta;
    if (((AndrossState *)piVar14)->durationTimer < lbl_803E74D4) {
      fn_80239FCC(obj,(int)piVar14);
            ((AndrossState *)piVar14)->durationTimer = ((AndrossState *)piVar14)->durationTimer + (f32)(lbl_803DC450);
    }
    fn_80239EAC(obj,(int)piVar14);
    if ((u32)GameBit_Get(0x10) != 0) {
      GameBit_Set(0x10,0);
      ((AndrossState *)piVar14)->actionState = 0x1a;
      lbl_803DDDB8 = lbl_803DC4D4;
      lbl_803DDDB8 += lbl_803DC4D0;
      if (lbl_803DDDB8 > lbl_803E74D0) {
        lbl_803DDDB8 -= lbl_803E74D0;
      }
      turnOnDistortionFilter((f32 *)(piVar14 + 0x30),lbl_803E74BC,&lbl_803DC4CC,lbl_803DDDB8);
      Rcp_DisableDistortionFilter();
    }
    break;
  case 0xc:
    fVar2 = lbl_803E74B8 * ((GameObject *)obj)->anim.currentMoveProgress + lbl_803E74B8;
    if (fVar2 < lbl_803E74B8) {
      dVar19 = -(lbl_803E74C0 * (lbl_803E74C4 * fVar2) - lbl_803E74BC);
      if (fVar2 < lbl_803E74C8) {
        lbl_803DDDB8 = lbl_803DC4D4;
      }
    }
    else {
      dVar19 = lbl_803E74CC;
    }
    lbl_803DDDB8 += lbl_803DC4D0;
    if (lbl_803DDDB8 > lbl_803E74D0) {
      lbl_803DDDB8 -= lbl_803E74D0;
    }
    turnOnDistortionFilter((f32 *)(piVar14 + 0x30),dVar19,&lbl_803DC4CC,lbl_803DDDB8);
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,2,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0A0[0];
      if (((AndrossState *)piVar14)->fightPhase < 5) {
        *(undefined *)((int)piVar14 + 0xb1) = 1;
      }
      ((AndrossState *)piVar14)->actionTimer = (short)lbl_803DC460;
      ((AndrossState *)piVar14)->durationTimer = lbl_803E74D4;
    }
    Sfx_KeepAliveLoopedObjectSound(obj,0x466);
    if (((AndrossState *)piVar14)->fightPhase == 5) {
      for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
        if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
          *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023cbdc;
        }
      }
      *(s16 *)((int)piVar14 + 0xa6) -= framesThisStep;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = randomGetRange(0,5);
        GameBit_Set(iVar12 + 0x108,1);
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023cbdc:
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E74F4) ? lbl_803E74F4 : ((dVar17 > lbl_803E74F8) ? lbl_803E74F8 : dVar17);
    dVar17 = (dVar16 < lbl_803E7510) ? lbl_803E7510 : ((dVar16 > lbl_803E74FC) ? lbl_803E74FC : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74FC * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E7514 * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    cVar11 = fn_8023A6A4((int)piVar14,lbl_803DC454,lbl_803DC458,lbl_803DC45C);
    if (cVar11 != '\0') {
      ((AndrossState *)piVar14)->actionState = 0xf;
      lbl_803DDDB8 = lbl_803DC4D4;
      lbl_803DDDB8 += lbl_803DC4D0;
      if (lbl_803DDDB8 > lbl_803E74D0) {
        lbl_803DDDB8 -= lbl_803E74D0;
      }
      turnOnDistortionFilter((f32 *)(piVar14 + 0x30),lbl_803E74BC,&lbl_803DC4CC,lbl_803DDDB8);
      Rcp_DisableDistortionFilter();
    }
    ((AndrossState *)piVar14)->durationTimer = ((AndrossState *)piVar14)->durationTimer - timeDelta;
    if (((AndrossState *)piVar14)->durationTimer < lbl_803E74D4) {
      fn_80239FCC(obj,(int)piVar14);
            ((AndrossState *)piVar14)->durationTimer = ((AndrossState *)piVar14)->durationTimer + (f32)(lbl_803DC464);
    }
    fn_80239EAC(obj,(int)piVar14);
    if (*(u8 *)((int)piVar14 + 0xb5) != 0) {
      if (((AndrossState *)piVar14)->fightPhase == 5) {
        ((AndrossState *)piVar14)->actionState = 0x19;
      }
      else {
        ((AndrossState *)piVar14)->actionState = 0xf;
      }
      lbl_803DDDB8 = lbl_803DC4D4;
      lbl_803DDDB8 += lbl_803DC4D0;
      if (lbl_803DDDB8 > lbl_803E74D0) {
        lbl_803DDDB8 -= lbl_803E74D0;
      }
      turnOnDistortionFilter((f32 *)(piVar14 + 0x30),lbl_803E74BC,&lbl_803DC4CC,lbl_803DDDB8);
      Rcp_DisableDistortionFilter();
    }
    else {
      if (*(float *)(*piVar14 + 0x14) > ((AndrossState *)piVar14)->cachedPosZ) {
        ((AndrossState *)piVar14)->actionState = 0x10;
        *(undefined *)(piVar14 + 0x2e) = 1;
        *(f32 *)(*piVar14 + 0x14) = ((AndrossState *)piVar14)->cachedPosZ;
        ((AndrossState *)piVar14)->unkE0 = lbl_803E74D4;
        lbl_803DDDB8 = lbl_803DC4D4;
        lbl_803DDDB8 += lbl_803DC4D0;
        if (lbl_803DDDB8 > lbl_803E74D0) {
          lbl_803DDDB8 -= lbl_803E74D0;
        }
        turnOnDistortionFilter((f32 *)(piVar14 + 0x30),lbl_803E74BC,&lbl_803DC4CC,lbl_803DDDB8);
        Rcp_DisableDistortionFilter();
        break;
      }
    }
    ((AndrossState *)piVar14)->actionTimer -= framesThisStep;
    if (((AndrossState *)piVar14)->actionTimer < 0) {
      ((AndrossState *)piVar14)->actionState = 0xf;
      lbl_803DDDB8 = lbl_803DC4D4;
      lbl_803DDDB8 += lbl_803DC4D0;
      if (lbl_803DDDB8 > lbl_803E74D0) {
        lbl_803DDDB8 -= lbl_803E74D0;
      }
      turnOnDistortionFilter((f32 *)(piVar14 + 0x30),lbl_803E74BC,&lbl_803DC4CC,lbl_803DDDB8);
      Rcp_DisableDistortionFilter();
    }
    break;
  case 0xf:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0x10,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0D8[0];
    }
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E7500) ? lbl_803E7500 : ((dVar17 > lbl_803E74CC) ? lbl_803E74CC : dVar17);
    dVar17 = (dVar16 < lbl_803E74F4) ? lbl_803E74F4 : ((dVar16 > lbl_803E74F8) ? lbl_803E74F8 : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74E8 * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E74DC) {
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    break;
  case 0x10:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0x10,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_803E7518;
    }
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar18 = lbl_803E74D4;
    dVar19 = (dVar17 < dVar18) ? dVar18 : ((dVar17 > dVar18) ? dVar18 : dVar17);
    dVar18 = lbl_803E74D4;
    dVar17 = (dVar16 < dVar18) ? dVar18 : ((dVar16 > dVar18) ? dVar18 : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74D4 * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74D4 * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    iVar12 = *piVar14;
    local_e4.x = (((AndrossState *)piVar14)->cachedPosX - *(float *)&((AndrossState *)iVar12)->lightAnchorObj) * lbl_803DC468;
    local_e4.y = (((AndrossState *)piVar14)->cachedPosY - *(float *)&((AndrossState *)iVar12)->effectHandle) * lbl_803DC468;
    local_e4.z = (((AndrossState *)piVar14)->cachedPosZ - *(float *)&((AndrossState *)iVar12)->unk14) * lbl_803DC468;
    local_d8 = local_e4;
    arwarwing_setVelocity(iVar12,(int)&local_d8);
    fVar2 = -(lbl_803E74B0 * timeDelta - ((AndrossState *)piVar14)->unkA8);
    if (fVar2 < lbl_803E74EC) {
      fVar2 = lbl_803E74EC;
    }
    ((AndrossState *)piVar14)->unkA8 = fVar2;
    if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E74DC) {
      *(s16 *)(*piVar14 + 6) = *(s16 *)(*piVar14 + 6) | 0x4000;
      ((AndrossState *)piVar14)->actionState = 0x11;
    }
    break;
  case 0x11:
    if (moveChanged) {
      Sfx_PlayFromObject(obj,0x468);
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0x15,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0EC[0];
      arwarwing_addShield(*piVar14,0xfffffffc);
    }
    fVar2 = -(lbl_803E74B0 * timeDelta - ((AndrossState *)piVar14)->unkA8);
    if (fVar2 < lbl_803E74EC) {
      fVar2 = lbl_803E74EC;
    }
    ((AndrossState *)piVar14)->unkA8 = fVar2;
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar18 = lbl_803E74D4;
    dVar19 = (dVar17 < dVar18) ? dVar18 : ((dVar17 > dVar18) ? dVar18 : dVar17);
    dVar18 = lbl_803E74D4;
    dVar17 = (dVar16 < dVar18) ? dVar18 : ((dVar16 > dVar18) ? dVar18 : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74D4 * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74D4 * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E74DC) {
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    break;
  case 0x12:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0x12,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0E0[0];
      androsshand_setState(((AndrossState *)piVar14)->handObjA,0,0);
      androsshand_setState(((AndrossState *)piVar14)->handObjB,0,0);
      if ((((AndrossState *)piVar14)->fightPhase == 5) && (((AndrossState *)piVar14)->actionToggle != 0)) {
        GameBit_Set(0xe,1);
      }
    }
    ((AndrossState *)piVar14)->fadeAlpha = ((AndrossState *)piVar14)->fadeAlpha - lbl_803E751C;
    fVar2 = ((AndrossState *)piVar14)->fadeAlpha;
    fVar2 = (lbl_803E74D4 <= fVar2) ? fVar2 : lbl_803E74D4;
    ((AndrossState *)piVar14)->fadeAlpha = fVar2;
    dVar19 = ((AndrossState *)piVar14)->fadeAlpha;
    iVar8 = *(int *)Obj_GetActiveModel(obj);
    fVar2 = lbl_803E74B4 * dVar19;
    for (iVar12 = 0; iVar12 < (int)(u32)*(u8 *)(iVar8 + 0xf8); iVar12 = iVar12 + 1) {
      iVar5 = ObjModel_GetRenderOp(iVar8,iVar12);
      ((AndrossState *)iVar5)->unk43 = fVar2;
    }
    if ((((AndrossState *)piVar14)->fightPhase == 5) && (((AndrossState *)piVar14)->actionToggle == 0)) {
      for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
        if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
          *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023d59c;
        }
      }
      *(s16 *)((int)piVar14 + 0xa6) -= framesThisStep;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = randomGetRange(0,5);
        GameBit_Set(iVar12 + 0x108,1);
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023d59c:
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E74EC) ? lbl_803E74EC : ((dVar17 > lbl_803E74F0) ? lbl_803E74F0 : dVar17);
    dVar17 = (dVar16 < lbl_803E74F4) ? lbl_803E74F4 : ((dVar16 > lbl_803E74F8) ? lbl_803E74F8 : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74E8 * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E74DC) {
      ((AndrossState *)piVar14)->actionState = 0x13;
    }
    break;
  case 0x13:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0x13,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0E4[0];
      if (((AndrossState *)piVar14)->fightPhase == 5) {
        ((AndrossState *)piVar14)->durationTimer = lbl_803E74A8;
      }
      else {
        ((AndrossState *)piVar14)->durationTimer = lbl_803E74F0;
      }
      ((AndrossState *)piVar14)->actionTimer = 0xffff;
    }
    Sfx_KeepAliveLoopedObjectSound(obj,0x469);
    if ((((AndrossState *)piVar14)->fightPhase == 5) && (((AndrossState *)piVar14)->actionToggle == 0)) {
      for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
        if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
          *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023d7cc;
        }
      }
      *(s16 *)((int)piVar14 + 0xa6) -= framesThisStep;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = randomGetRange(0,5);
        GameBit_Set(iVar12 + 0x108,1);
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023d7cc:
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E7520) ? lbl_803E7520 : ((dVar17 > lbl_803E74A8) ? lbl_803E74A8 : dVar17);
    dVar17 = (dVar16 < lbl_803E7524) ? lbl_803E7524 : ((dVar16 > lbl_803E7528) ? lbl_803E7528 : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74E8 * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    ((AndrossState *)piVar14)->actionTimer -= framesThisStep;
    iVar12 = (int)((AndrossState *)piVar14)->durationTimer;
    ((AndrossState *)piVar14)->durationTimer = ((AndrossState *)piVar14)->durationTimer - (f32)framesThisStep;
    if (((AndrossState *)piVar14)->fightPhase == 5) {
      local_130[0] = 300;
      local_130[1] = 600;
    }
    else {
      local_130[0] = 0x122;
      local_130[1] = 0x28;
    }
    for (iVar8 = 0; (u8)iVar8 < 2; iVar8 = iVar8 + 1) {
      if ((((((AndrossState *)piVar14)->unk14 == 0) && (((AndrossState *)piVar14)->actionTimer <= local_130[(u8)iVar8])) &&
          (local_130[(u8)iVar8] < (short)iVar12)) && (cVar11 = Obj_IsLoadingLocked(), cVar11 != '\0')) {
        iVar5 = Obj_AllocObjectSetup(0x24,0x819);
        *(f32 *)&((AndrossState *)iVar5)->handObjB = ((AndrossState *)piVar14)->cachedPosX;
        *(f32 *)&((AndrossState *)iVar5)->lightAnchorObj = ((AndrossState *)piVar14)->cachedPosY;
        *(f32 *)&((AndrossState *)iVar5)->effectHandle = ((AndrossState *)piVar14)->cachedPosZ;
        *(undefined *)(iVar5 + 4) = 1;
        *(undefined *)(iVar5 + 5) = 1;
        ((AndrossState *)iVar5)->unk20 = 0xffff;
        iVar5 = loadObjectAtObject(obj);
        ((AndrossState *)piVar14)->unk14 = iVar5;
        if (((AndrossState *)piVar14)->unk14 != 0) {
          ((GameObject *)((AndrossState *)piVar14)->unk14)->anim.alpha = 0xff;
          *(undefined *)(((AndrossState *)piVar14)->unk14 + 0x37) = 0xff;
          ((AndrossState *)piVar14)->spawnedObjLifetime = lbl_803DC4EC;
        }
      }
    }
    if (((AndrossState *)piVar14)->actionTimer < 0) {
      fn_8023A168(obj,(int)piVar14);
      ((AndrossState *)piVar14)->actionTimer = (short)lbl_803DC46C;
    }
    if (((AndrossState *)piVar14)->durationTimer < lbl_803E74D4) {
      ((AndrossState *)piVar14)->actionState = 0x14;
    }
    break;
  case 0x14:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0x14,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0E8[0];
    }
    if ((((AndrossState *)piVar14)->fightPhase == 5) && (((AndrossState *)piVar14)->actionToggle == 0)) {
      for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
        if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
          *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
          goto LAB_8023db24;
        }
      }
      *(s16 *)((int)piVar14 + 0xa6) -= framesThisStep;
      if (*(short *)((int)piVar14 + 0xa6) < 1) {
        iVar12 = randomGetRange(0,5);
        GameBit_Set(iVar12 + 0x108,1);
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
      }
    }
LAB_8023db24:
    lbl_803DDDCA += lbl_803DC4BC;
    lbl_803DDDC8 += lbl_803DC4BE;
    dVar17 = (*(float *)(*piVar14 + 0xc) - ((AndrossState *)piVar14)->homePosX);
    dVar16 = (*(float *)(*piVar14 + 0x10) - ((AndrossState *)piVar14)->homePosY);
    dVar19 = (dVar17 < lbl_803E74EC) ? lbl_803E74EC : ((dVar17 > lbl_803E74F0) ? lbl_803E74F0 : dVar17);
    dVar17 = (dVar16 < lbl_803E752C) ? lbl_803E752C : ((dVar16 > lbl_803E74E8) ? lbl_803E74E8 : dVar16);
        dVar16 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDCA)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosX = (lbl_803E74CC * dVar16 +
                     (float)(((AndrossState *)piVar14)->homePosX + dVar19));
        dVar19 = mathSinf(((lbl_803E74A0 * (f32)(lbl_803DDDC8)) /
                                          lbl_803E74A4));
    ((AndrossState *)piVar14)->targetPosY = (lbl_803E74FC * dVar19 +
                     (float)(((AndrossState *)piVar14)->homePosY + dVar17));
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E74DC) {
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    break;
  case 0x19:
  case 0x1a:
    if (moveChanged) {
      Sfx_PlayFromObject(obj,0x4a6);
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,4,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0A8[0];
    }
    if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E74DC) {
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    break;
  case 0x1b:
    if (moveChanged) {
      GameBit_Set(0x10,0);
      ((AndrossState *)piVar14)->actionTimer = 0x1e;
      arwarwing_resetFlightState(*piVar14);
      *(f32 *)(*piVar14 + 0x14) = ((AndrossState *)piVar14)->unk70;
      ((AndrossState *)piVar14)->unkA8 = lbl_803E74D4;
    }
    ((AndrossState *)piVar14)->targetPosX = ((AndrossState *)piVar14)->homePosX;
    ((AndrossState *)piVar14)->targetPosY = ((AndrossState *)piVar14)->homePosY;
    ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
    if (((u32)GameBit_Get(0x10) != 0) &&
       (sVar3 = ((AndrossState *)piVar14)->actionTimer, ((AndrossState *)piVar14)->actionTimer = sVar3 + -1, sVar3 == 0)) {
      GameBit_Set(0x10,0);
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    break;
  case 0x1c:
    if (moveChanged) {
      androssbrain_setState(((AndrossState *)piVar14)->lightAnchorObj,1,0);
      ObjHits_DisableObject(obj);
      ((AndrossState *)piVar14)->actionTimer = 0x3c;
      ((AndrossState *)piVar14)->durationTimer = lbl_803E74D8;
      ((AndrossState *)piVar14)->targetPosX = ((AndrossState *)piVar14)->homePosX;
      ((AndrossState *)piVar14)->targetPosY = ((AndrossState *)piVar14)->homePosY;
      ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ;
      fVar2 = lbl_803E74D4;
      ((GameObject *)obj)->anim.velocityX = lbl_803E74D4;
      ((GameObject *)obj)->anim.velocityY = fVar2;
      ((GameObject *)obj)->anim.velocityZ = fVar2;
      ((AndrossState *)piVar14)->springStiffness = lbl_803E74C8;
      ((AndrossState *)piVar14)->springDamping = lbl_803E7530;
    }
    ((AndrossState *)piVar14)->fadeAlpha = ((AndrossState *)piVar14)->fadeAlpha + lbl_803E751C;
    fVar2 = ((AndrossState *)piVar14)->fadeAlpha;
    fVar2 = (lbl_803E7534 >= fVar2) ? fVar2 : lbl_803E7534;
    ((AndrossState *)piVar14)->fadeAlpha = fVar2;
    for (iVar12 = 0; (u8)iVar12 < 6; iVar12 = iVar12 + 1) {
      if ((u32)GameBit_Get((u8)iVar12 + 0x108) != 0) {
        *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
        goto LAB_8023de5c;
      }
    }
    *(s16 *)((int)piVar14 + 0xa6) -= framesThisStep;
    if (*(short *)((int)piVar14 + 0xa6) < 1) {
      iVar12 = randomGetRange(0,5);
      GameBit_Set(iVar12 + 0x108,1);
      *(s16 *)((int)piVar14 + 0xa6) = 0x3c;
    }
LAB_8023de5c:
    ((AndrossState *)piVar14)->actionTimer -= framesThisStep;
    if (((AndrossState *)piVar14)->actionTimer < 0) {
      ((AndrossState *)piVar14)->durationTimer = ((AndrossState *)piVar14)->durationTimer - lbl_803E74DC;
      if (((AndrossState *)piVar14)->durationTimer < lbl_803E74D4) {
        *(char *)&((AndrossState *)piVar14)->actionToggle = *(char *)&((AndrossState *)piVar14)->actionToggle + '\x01';
        if (((AndrossState *)piVar14)->actionToggle > 3) {
          ((AndrossState *)piVar14)->fightPhase = 5;
          ((AndrossState *)piVar14)->prevFightPhase = 5;
          ((AndrossState *)piVar14)->actionToggle = 0;
          ((AndrossState *)piVar14)->actionState = 0x12;
          androssbrain_setState(((AndrossState *)piVar14)->lightAnchorObj,0,0);
          ObjHits_EnableObject(obj);
        }
        else {
          ((AndrossState *)piVar14)->actionState = 0x1d;
        }
      }
      else {
        uVar10 = randomGetRange(0x14,0x1e);
        ((AndrossState *)piVar14)->actionTimer = uVar10;
        uVar6 = randomGetRange((int)-lbl_803DC470,(int)lbl_803DC470);
                ((AndrossState *)piVar14)->targetPosX = ((AndrossState *)piVar14)->homePosX + (f32)(int)uVar6;
        uStack100 = randomGetRange((int)-lbl_803DC474,(int)lbl_803DC474);
        ((AndrossState *)piVar14)->targetPosY = ((AndrossState *)piVar14)->homePosY + (f32)(int)uStack100;
        uVar6 = randomGetRange((int)-lbl_803DC478,(int)lbl_803DC478);
                ((AndrossState *)piVar14)->targetPosZ = ((AndrossState *)piVar14)->homePosZ + (f32)(int)uVar6;
      }
    }
    if ((*(u8 *)((int)piVar14 + 0xad) & 8) != 0) {
      arwingHudSetVisible(2);
      GameBit_Set(1,1);
      GameBit_Set(0x4b1,1);
      ((AndrossState *)piVar14)->actionState = 0x1e;
      unlockLevel(0,0,1);
      uVar9 = mapGetDirIdx(0xb);
      mapUnload(uVar9,0x20000000);
      Music_Trigger(0xf3,0);
    }
    dVar19 = ((AndrossState *)piVar14)->fadeAlpha;
    iVar8 = *(int *)Obj_GetActiveModel(obj);
    fVar2 = lbl_803E74B4 * dVar19;
    for (iVar12 = 0; iVar12 < (int)(u32)*(u8 *)(iVar8 + 0xf8); iVar12 = iVar12 + 1) {
      iVar5 = ObjModel_GetRenderOp(iVar8,iVar12);
      ((AndrossState *)iVar5)->unk43 = fVar2;
    }
    break;
  case 0x1d:
    if (moveChanged) {
      androssbrain_setState(((AndrossState *)piVar14)->lightAnchorObj,1,0);
      ObjHits_DisableObject(obj);
      ((AndrossState *)piVar14)->actionTimer = (short)lbl_803DC484;
      ((AndrossState *)piVar14)->targetPosX = *(f32 *)(*piVar14 + 0xc);
      ((AndrossState *)piVar14)->targetPosY = *(float *)(*piVar14 + 0x10) + lbl_803DC47C;
      ((AndrossState *)piVar14)->targetPosZ = *(float *)(*piVar14 + 0x14) + lbl_803DC480;
      fVar2 = lbl_803E74D4;
      ((GameObject *)obj)->anim.velocityX = lbl_803E74D4;
      ((GameObject *)obj)->anim.velocityY = fVar2;
      ((GameObject *)obj)->anim.velocityZ = fVar2;
      iVar12 = randomGetRange(0,1);
      if (iVar12 == 0) {
        uVar9 = 0x472;
      }
      else {
        uVar9 = 0x471;
      }
      Sfx_PlayFromObject(obj,uVar9);
    }
    ((AndrossState *)piVar14)->actionTimer -= framesThisStep;
    if (((AndrossState *)piVar14)->actionTimer < 0) {
      ((AndrossState *)piVar14)->actionState = 0x1c;
    }
    break;
  case 0x16:
    if (moveChanged) {
      iVar12 = randomGetRange(0,1);
      if (iVar12 == 0) {
        uVar9 = 0x472;
      }
      else {
        uVar9 = 0x471;
      }
      Sfx_PlayFromObject(obj,uVar9);
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C098[0];
    }
    if (*(u8 *)(piVar14 + 0x2e) != 0) {
      iVar12 = *piVar14;
      local_fc.x = (((AndrossState *)piVar14)->cachedPosX - *(float *)&((AndrossState *)iVar12)->lightAnchorObj) * lbl_803DC488;
      local_fc.y = (((AndrossState *)piVar14)->cachedPosY - *(float *)&((AndrossState *)iVar12)->effectHandle) * lbl_803DC488;
      local_fc.z = (((AndrossState *)piVar14)->cachedPosZ - *(float *)&((AndrossState *)iVar12)->unk14) * lbl_803DC488;
      local_f0 = local_fc;
      arwarwing_setVelocity(iVar12,(int)&local_f0);
      fVar2 = -(lbl_803E753C * timeDelta - ((AndrossState *)piVar14)->unkA8);
      if (fVar2 < lbl_803E7538) {
        fVar2 = lbl_803E7538;
      }
      ((AndrossState *)piVar14)->unkA8 = fVar2;
    }
    sVar3 = ((AndrossState *)piVar14)->unkA0 - *(s16 *)obj;
    if (0x8000 < sVar3) {
      sVar3 = sVar3 + 1;
    }
    if (sVar3 < -0x8000) {
      sVar3 = sVar3 + -1;
    }
    iVar12 = (int)sVar3;
    if (iVar12 < 0) {
      iVar12 = -iVar12;
    }
    if (iVar12 < 2000) {
      cVar11 = *(char *)(*(int *)(((AndrossState *)piVar14)->handObjA + 0xb8) + 0x23);
      if ((((cVar11 != '\x02') && (cVar11 != '\x01')) &&
          (cVar11 = *(char *)(*(int *)(((AndrossState *)piVar14)->handObjB + 0xb8) + 0x23), cVar11 != '\x02')) &&
         (cVar11 != '\x01')) {
        ((AndrossState *)piVar14)->actionPending = 1;
      }
    }
    break;
  case 5:
    iVar12 = *(int *)(((AndrossState *)piVar14)->handObjA + 0xb8);
    iVar5 = *(int *)(((AndrossState *)piVar14)->handObjB + 0xb8);
    if (moveChanged) {
      Sfx_PlayFromObject(obj,0x470);
      iVar8 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0x16,lbl_803E74D4,0);
      *(f32 *)(iVar8 + 100) = lbl_8032C0F0[0];
      ((AndrossFlagByte *)&((AndrossState *)piVar14)->soundEventFlags)->f80 = 0;
      ((AndrossFlagByte *)&((AndrossState *)piVar14)->soundEventFlags)->f40 = 0;
    }
    dVar19 = ((GameObject *)obj)->anim.currentMoveProgress;
    if (dVar19 < lbl_803E7540) {
      dVar19 = mathSinf(((lbl_803E74A0 *
                                             (float)(lbl_803E7548 *
                                                    lbl_803E7550 * (dVar19 / lbl_803E7540))) /
                                            lbl_803E74A4));
      ((AndrossState *)piVar14)->targetPosZ = (lbl_803E74A8 * dVar19 + ((AndrossState *)piVar14)->homePosZ);
    }
    else {
      dVar19 = mathSinf(((lbl_803E74A0 *
                                             (float)(lbl_803E7548 *
                                                    (lbl_803E7558 *
                                                     ((dVar19 - lbl_803E7540) / lbl_803E7560)
                                                    + lbl_803E7550))) / lbl_803E74A4));
            ((AndrossState *)piVar14)->targetPosZ = ((f32)(lbl_803DC48C) * dVar19 +
                       ((AndrossState *)piVar14)->homePosZ);
    }
    if ((((GameObject *)obj)->anim.currentMoveProgress > lbl_803E7568) &&
       ((((AndrossState *)piVar14)->soundEventFlags >> 6 & 1) == 0)) {
      iVar8 = randomGetRange(0,1);
      if (iVar8 == 0) {
        uVar9 = 0x472;
      }
      else {
        uVar9 = 0x471;
      }
      Sfx_PlayFromObject(obj,uVar9);
      ((AndrossFlagByte *)&((AndrossState *)piVar14)->soundEventFlags)->f40 = 1;
    }
    if ((((GameObject *)obj)->anim.currentMoveProgress > lbl_803E7570) && (((AndrossFlagByte *)&((AndrossState *)piVar14)->soundEventFlags)->f80 == 0)) {
      Sfx_PlayFromObject(obj,0x46d);
      ((AndrossFlagByte *)&((AndrossState *)piVar14)->soundEventFlags)->f80 = 1;
    }
    cVar11 = *(char *)&((AndrossState *)iVar12)->unk23;
    if ((((cVar11 != '\x02') && (cVar11 != '\x01')) &&
        (cVar11 = *(char *)&((AndrossState *)iVar5)->unk23, cVar11 != '\x02')) && (cVar11 != '\x01')) {
      if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E74DC) {
        ((AndrossState *)piVar14)->actionPending = 1;
      }
      else if (((GameObject *)obj)->anim.currentMoveProgress > lbl_803E7568) {
        ((AndrossState *)piVar14)->unkA0 = 0;
          androsshand_setState(((AndrossState *)piVar14)->handObjA,1,(u8)((((AndrossState *)piVar14)->fightPhase == 4) + 1));
        androsshand_setState(((AndrossState *)piVar14)->handObjB,1,(u8)((((AndrossState *)piVar14)->fightPhase == 4) + 1));
        *(u8 *)((int)piVar14 + 0xad) = *(u8 *)((int)piVar14 + 0xad) & ~0x6;
      }
    }
    break;
  case 0x17:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,3,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0A4[0];
      ((AndrossState *)piVar14)->unkE4 = lbl_803E74D4;
      ((AndrossFlagByte *)&((AndrossState *)piVar14)->soundEventFlags)->f20 = 0;
    }
    ((AndrossState *)piVar14)->unkE4 = ((AndrossState *)piVar14)->unkE4 + timeDelta;
    if ((lbl_803E7578 < ((AndrossState *)piVar14)->unkE4) && ((((AndrossState *)piVar14)->soundEventFlags >> 5 & 1) == 0)) {
      Sfx_PlayFromObject(obj,0x46f);
      ((AndrossFlagByte *)&((AndrossState *)piVar14)->soundEventFlags)->f20 = 1;
    }
    if (((GameObject *)obj)->anim.currentMoveProgress <= lbl_803DC490) {
      ((AndrossState *)piVar14)->cachedPosX = ((GameObject *)obj)->anim.localPosX;
      ((AndrossState *)piVar14)->cachedPosY = ((GameObject *)obj)->anim.localPosY - lbl_803E757C;
      ((AndrossState *)piVar14)->cachedPosZ = ((GameObject *)obj)->anim.localPosZ - lbl_803E7580;
      iVar12 = *piVar14;
      local_114.x = (((AndrossState *)piVar14)->cachedPosX - *(float *)&((AndrossState *)iVar12)->lightAnchorObj) * lbl_803DC494;
      local_114.y = (((AndrossState *)piVar14)->cachedPosY - *(float *)&((AndrossState *)iVar12)->effectHandle) * lbl_803DC494;
      local_114.z = (((AndrossState *)piVar14)->cachedPosZ - *(float *)&((AndrossState *)iVar12)->unk14) * lbl_803DC494;
      local_108 = local_114;
      arwarwing_setVelocity(iVar12,(int)&local_108);

    }
    else {
      dVar19 = (((AndrossState *)piVar14)->unk70 - *(float *)(*piVar14 + 0x14));
      fVar2 = lbl_803E753C * timeDelta + ((AndrossState *)piVar14)->unkA8;
      if (lbl_803E74D4 < fVar2) {
        fVar2 = lbl_803E74D4;
      }
      ((AndrossState *)piVar14)->unkA8 = fVar2;
      *(undefined *)(piVar14 + 0x2e) = 0;
      *(s16 *)(*piVar14 + 6) = *(s16 *)(*piVar14 + 6) & ~0x4000;
      sVar3 = arwarwing_getRotY(*piVar14);
            iVar12 = (int)(dVar19 * lbl_803DC49C + (f32)(sVar3));
      arwarwing_setRotY(*piVar14,iVar12);
      local_9c.x = lbl_803E74D4;
      local_9c.y = lbl_803E74D4;
      local_9c.z = (float)(dVar19 * lbl_803DC498);
      local_b4 = local_9c;
      arwarwing_setVelocity(*piVar14,(int)&local_b4);
    }
    if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E74DC) {
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    break;
  case 0x18:
    if (moveChanged) {
      iVar12 = *(int *)&((GameObject *)obj)->extra;
      ObjAnim_SetCurrentMove(obj,0x11,lbl_803E74D4,0);
      ((AndrossState *)iVar12)->animSpeed = lbl_8032C0DC[0];
      ((AndrossFlagByte *)&((AndrossState *)piVar14)->soundEventFlags)->f20 = 0;
    }
    if (((GameObject *)obj)->anim.currentMoveProgress <= lbl_803DC4A0) {
      iVar12 = *piVar14;
      local_12c.x = (((AndrossState *)piVar14)->cachedPosX - *(float *)&((AndrossState *)iVar12)->lightAnchorObj) * lbl_803DC4A4;
      local_12c.y = (((AndrossState *)piVar14)->cachedPosY - *(float *)&((AndrossState *)iVar12)->effectHandle) * lbl_803DC4A4;
      local_12c.z = (((AndrossState *)piVar14)->cachedPosZ - *(float *)&((AndrossState *)iVar12)->unk14) * lbl_803DC4A4;
      local_120 = local_12c;
      arwarwing_setVelocity(iVar12,(int)&local_120);

    }
    else {
      dVar19 = (((AndrossState *)piVar14)->unk70 - *(float *)(*piVar14 + 0x14));
      fVar2 = lbl_803E7514 * timeDelta + ((AndrossState *)piVar14)->unkA8;
      if (lbl_803E74D4 < fVar2) {
        fVar2 = lbl_803E74D4;
      }
      ((AndrossState *)piVar14)->unkA8 = fVar2;
      *(undefined *)(piVar14 + 0x2e) = 0;
      *(s16 *)(*piVar14 + 6) = *(s16 *)(*piVar14 + 6) & ~0x4000;
      sVar3 = arwarwing_getRotY(*piVar14);
            iVar12 = (int)(dVar19 * lbl_803DC4AC + (f32)(sVar3));
      arwarwing_setRotY(*piVar14,iVar12);
      local_a8.x = lbl_803E74D4;
      local_a8.y = lbl_803E74D4;
      local_a8.z = (float)(dVar19 * lbl_803DC4A8);
      local_c0 = local_a8;
      arwarwing_setVelocity(*piVar14,(int)&local_c0);
      if ((((AndrossState *)piVar14)->soundEventFlags >> 5 & 1) == 0) {
        Sfx_PlayFromObject(obj,0x46f);
        ((AndrossFlagByte *)&((AndrossState *)piVar14)->soundEventFlags)->f20 = 1;
      }
    }
    if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E74DC) {
      ((AndrossState *)piVar14)->actionPending = 1;
    }
    break;
  case 0x1e:
    iVar12 = GameBit_Get(2);
    if (((iVar12 != 0) || (iVar12 = GameBit_Get(3), iVar12 != 0)) ||
       (iVar12 = GameBit_Get(4), iVar12 != 0)) {
      GameBit_Set(0x405,0);
      (*gMapEventInterface)->setMode(0xb, 7);
      unlockLevel(0,0,1);
      loadMapAndParent(mapGetDirIdx(0xb));
      uVar9 = mapGetDirIdx(0xb);
      lockLevel(uVar9,1);
      warpToMap(0x4e,0);
      ((AndrossState *)piVar14)->fadeAlpha = lbl_803E74D4;
      ((AndrossState *)piVar14)->actionState = 0x1f;
    }
  }
  local_134 = lbl_803E7584 + ((AndrossState *)piVar14)->unkA8;
  (*gCameraInterface)->releaseAction(&local_134, 4);
  ((GameObject *)obj)->anim.velocityX =
       ((AndrossState *)piVar14)->springStiffness * (((AndrossState *)piVar14)->targetPosX - ((GameObject *)obj)->anim.localPosX) +
       ((GameObject *)obj)->anim.velocityX;
  ((GameObject *)obj)->anim.velocityY =
       ((AndrossState *)piVar14)->springStiffness * (((AndrossState *)piVar14)->targetPosY - ((GameObject *)obj)->anim.localPosY) +
       ((GameObject *)obj)->anim.velocityY;
  ((GameObject *)obj)->anim.velocityZ =
       ((AndrossState *)piVar14)->springStiffness * (((AndrossState *)piVar14)->targetPosZ - ((GameObject *)obj)->anim.localPosZ) +
       ((GameObject *)obj)->anim.velocityZ;
  ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * ((AndrossState *)piVar14)->springDamping;
  ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY * ((AndrossState *)piVar14)->springDamping;
  ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * ((AndrossState *)piVar14)->springDamping;
  ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.localPosX + ((GameObject *)obj)->anim.velocityX;
  ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY + ((GameObject *)obj)->anim.velocityY;
  ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.localPosZ + ((GameObject *)obj)->anim.velocityZ;
  if (lbl_803E74D4 == ((AndrossState *)piVar14)->unkE0) {
    if (*(u8 *)(piVar14 + 0x2e) != 0) {
      fn_8023A6A4((int)piVar14,lbl_803DC4B4,lbl_803DC4B8,lbl_803E74D4);
    }
    else {
      ((AndrossState *)piVar14)->unkE0 = lbl_803DC4B0 * (((AndrossState *)piVar14)->unk70 - *(float *)(*piVar14 + 0x14));
    }
  }
  if (*(void **)(*piVar14 + 0xc0) == NULL) {
    local_cc = *(SunVec3 *)(piVar14 + 0x36);
    arwarwing_addVelocity(*piVar14,(int)&local_cc);
  }
  sVar3 = ((AndrossState *)piVar14)->unkA0 - *(s16 *)obj;
  if (0x8000 < sVar3) {
    sVar3 = sVar3 + 1;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  *(short *)((int)piVar14 + 0xa2) =
       *(short *)((int)piVar14 + 0xa2) +
       (short)(((int)sVar3 / lbl_803DC430 - (int)*(short *)((int)piVar14 + 0xa2)) / lbl_803DC434);
  ((AndrossState *)piVar14)->unkA4 =
       ((AndrossState *)piVar14)->unkA4 +
       (short)((-(int)((GameObject *)obj)->anim.rotY / lbl_803DC430 - (int)((AndrossState *)piVar14)->unkA4) / lbl_803DC434);
  *(s16 *)obj = *(s16 *)obj + *(short *)((int)piVar14 + 0xa2);
  ((GameObject *)obj)->anim.rotY = ((GameObject *)obj)->anim.rotY + ((AndrossState *)piVar14)->unkA4;
  ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj,((AndrossState *)piVar14)->animSpeed,timeDelta,0);
  fn_8023A3E4(obj,(int)piVar14);
  fn_8023A87C(obj,(int)piVar14);
  iVar12 = ((AndrossState *)piVar14)->unk14;
  if (iVar12 != 0) {
    *(float *)&((AndrossState *)iVar12)->unk14 = *(float *)&((AndrossState *)iVar12)->unk14 - lbl_803E74D8;
    ((AndrossState *)piVar14)->spawnedObjLifetime = ((AndrossState *)piVar14)->spawnedObjLifetime - (u32)framesThisStep;
    if (((AndrossState *)piVar14)->spawnedObjLifetime < 0) {
      Obj_FreeObject(((AndrossState *)piVar14)->unk14);
      ((AndrossState *)piVar14)->spawnedObjLifetime = 0;
      ((AndrossState *)piVar14)->unk14 = 0;
    }
  }
  if (((AndrossState *)piVar14)->fightPhase < 6) {
    local_138 = lbl_803E7490;
    iVar12 = ObjList_FindNearestObjectByDefNo(obj,0x7e5,&local_138);
    if ((u32)iVar12 != 0) {
      if (*(void **)&((AndrossState *)iVar12)->cachedPosX != NULL) {
        iVar12 = *(int *)&((AndrossState *)iVar12)->cachedPosX;
      }
      if ((((AndrossState *)iVar12)->unk44 != 0x10) ||
         (iVar5 = animatedObjGetSeqId(((AndrossState *)iVar12)->unkB8), iVar5 != 0x598)) {
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 8) = ((GameObject *)obj)->anim.localPosX;
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 0xc) = ((GameObject *)obj)->anim.localPosY;
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 0x10) = ((GameObject *)obj)->anim.localPosZ;
      }
    }
    local_13c = lbl_803E7490;
    iVar12 = ObjList_FindNearestObjectByDefNo(obj,0x1e,&local_13c);
    if ((u32)iVar12 != 0) {
      if (*(void **)&((AndrossState *)iVar12)->cachedPosX != NULL) {
        iVar12 = *(int *)&((AndrossState *)iVar12)->cachedPosX;
      }
      if ((((AndrossState *)iVar12)->unk44 != 0x10) ||
         (iVar5 = animatedObjGetSeqId(((AndrossState *)iVar12)->unkB8), iVar5 != 0x598)) {
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 8) = ((GameObject *)obj)->anim.localPosX;
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 0xc) = ((GameObject *)obj)->anim.localPosY;
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 0x10) = ((GameObject *)obj)->anim.localPosZ;
      }
    }
    local_140 = lbl_803E7490;
    iVar12 = ObjList_FindNearestObjectByDefNo(obj,0x76f,&local_140);
    if ((u32)iVar12 != 0) {
      if (*(void **)&((AndrossState *)iVar12)->cachedPosX != NULL) {
        iVar12 = *(int *)&((AndrossState *)iVar12)->cachedPosX;
      }
      if ((((AndrossState *)iVar12)->unk44 != 0x10) ||
         (iVar5 = animatedObjGetSeqId(((AndrossState *)iVar12)->unkB8), iVar5 != 0x598)) {
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 8) = ((GameObject *)obj)->anim.localPosX;
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 0xc) = ((GameObject *)obj)->anim.localPosY;
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 0x10) = ((GameObject *)obj)->anim.localPosZ;
      }
    }
    local_144 = lbl_803E7490;
    iVar12 = ObjList_FindNearestObjectByDefNo(obj,0x814,&local_144);
    if ((u32)iVar12 != 0) {
      if (*(void **)&((AndrossState *)iVar12)->cachedPosX != NULL) {
        iVar12 = *(int *)&((AndrossState *)iVar12)->cachedPosX;
      }
      if ((((AndrossState *)iVar12)->unk44 != 0x10) ||
         (iVar5 = animatedObjGetSeqId(((AndrossState *)iVar12)->unkB8), iVar5 != 0x598)) {
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 8) = ((GameObject *)obj)->anim.localPosX;
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 0xc) = ((GameObject *)obj)->anim.localPosY;
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 0x10) = ((GameObject *)obj)->anim.localPosZ;
      }
    }
    local_148 = lbl_803E7490;
    iVar12 = ObjList_FindNearestObjectByDefNo(obj,0x6cf,&local_148);
    if ((u32)iVar12 != 0) {
      if (*(void **)&((AndrossState *)iVar12)->cachedPosX != NULL) {
        iVar12 = *(int *)&((AndrossState *)iVar12)->cachedPosX;
      }
      if ((((AndrossState *)iVar12)->unk44 != 0x10) ||
         (iVar5 = animatedObjGetSeqId(((AndrossState *)iVar12)->unkB8), iVar5 != 0x598)) {
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 8) = ((GameObject *)obj)->anim.localPosX;
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 0xc) = ((GameObject *)obj)->anim.localPosY;
        *(f32 *)(((AndrossState *)iVar12)->targetPosPtr + 0x10) = ((GameObject *)obj)->anim.localPosZ;
      }
    }
  }
LAB_8023ef14:
  return;
}


