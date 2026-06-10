#include "main/dll/cfguardian_state.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/cfguardian.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"

typedef struct DoorObjectDef {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    u8 unk1C;
    u8 unk1D;
    u8 pad1E[0x20 - 0x1E];
    u8 unk20;
    u8 unk21;
    s16 unk22;
    u8 pad24[0x28 - 0x24];
} DoorObjectDef;


typedef struct LockDoorLockPlacement {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
    u8 unk20;
    u8 unk21;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} LockDoorLockPlacement;


typedef struct PressureswitchfbPlacement {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    u8 unk1E;
    u8 pad1F[0x20 - 0x1F];
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} PressureswitchfbPlacement;


typedef struct DoorPlacement {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    u8 unk1E;
    u8 pad1F[0x20 - 0x1F];
    s16 unk20;
    s16 unk22;
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} DoorPlacement;


typedef struct DoorlockPlacement {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    s16 unk22;
    s16 unk24;
    s16 unk26;
} DoorlockPlacement;


typedef struct DoorState {
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1E - 0x19];
    s16 unk1E;
} DoorState;


extern bool FUN_800067f8();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_8001771c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjGroup_FindNearestObject();
extern undefined4 ObjGroup_AddObject();
extern int FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80135814();
extern undefined4 FUN_8017b130();
extern uint FUN_80286830();
extern uint FUN_8028683c();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286888();
extern int FUN_80294c0c();

extern ObjectTriggerInterface **gObjectTriggerInterface;
extern f64 DOUBLE_803e4408;
extern f64 DOUBLE_803e4428;
extern f32 timeDelta;
extern f32 lbl_803DC074;
extern f32 lbl_803E43F0;
extern f32 lbl_803E43F4;
extern f32 lbl_803E43F8;
extern f32 lbl_803E43FC;
extern f32 lbl_803E4400;
extern f32 lbl_803E4410;
extern f32 lbl_803E4418;
extern f32 lbl_803E441C;
extern f32 lbl_803E4420;

/*
 * --INFO--
 *
 * Function: pressureswitchfb_update
 * EN v1.0 Address: 0x8017ADB4
 * EN v1.0 Size: 1540b
 * EN v1.1 Address: 0x8017B2F8
 * EN v1.1 Size: 1604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct {
    u8 pad[4];
    u16 type;
    u16 arg;
    f32 w;
    f32 x;
    f32 y;
    f32 z;
} FxArgs;

typedef struct {
    u8 active : 1;
    u8 playerOnly : 1;
    u8 released : 1;
    u8 latched : 1;
    u8 rest : 4;
} SwitchFlags;

extern void *Obj_GetPlayerObject(void);
extern int fn_80295C5C(void *player);
extern void *getTrickyObject(void);
extern f32 Vec_distance(f32 *a, f32 *b);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern EffectInterface **gPartfxInterface;
extern int *objFindTexture(int *obj, int a, int b);
extern u32 GameBit_Get(int eventId);
extern int GameBit_Set(int eventId, int value);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern f32 lbl_803E3758;
extern f32 lbl_803E375C;
extern f32 lbl_803E3760;
extern f32 lbl_803E3764;
extern f32 lbl_803E3768;

void pressureswitchfb_update(int obj)
{
  uint nearest;
  int off;
  uint other;
  int def;
  char *state;
  int i;
  int tmp;
  uint j;
  int isTarget;
  uint ju;
  int base;
  int *tex;
  f32 target;
  f32 cur;
  int slots2;
  u8 found;
  uint j2;
  uint ju2;
  uint o;
  int base2;
  f32 nearDist;
  FxArgs fx;

  def = *(int *)&((GameObject *)obj)->anim.placementData;
  state = ((GameObject *)obj)->extra;
  if ((((SwitchFlags *)(state + 0x84))->active) != 0) {
    if ((((SwitchFlags *)(state + 0x84))->released) == 0) {
      *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    } else {
      *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
    }
  } else {
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
  }
  if ((((PressureswitchfbPlacement *)def)->unk20 == -1) || (GameBit_Get(((PressureswitchfbPlacement *)def)->unk20) != 0)) {
    u8 c = *state;
    *state = c - 1;
    if ((s8)(c - 1) < 0) {
      *state = 0;
    }
    nearDist = lbl_803E3758;
    nearest = (uint)ObjGroup_FindNearestObject(5, obj, &nearDist);
    if (nearest != 0) {
      *state = 5;
    }
    if (*(s8 *)(*(int *)(obj + 0x58) + 0x10f) > 0) {
      for (i = 0, off = 0; i < *(s8 *)(*(int *)(obj + 0x58) + 0x10f); i++) {
        other = *(uint *)(*(int *)(obj + 0x58) + off + 0x100);
        if ((((GameObject *)other)->anim.classId == 1) || (((GameObject *)other)->anim.classId == 2) ||
            (((GameObject *)other)->anim.seqId == 0x754) || (((GameObject *)other)->anim.seqId == 0x6d)) {
          isTarget = 1;
        } else {
          isTarget = 0;
        }
        if (isTarget && (other != nearest)) {
          if (((GameObject *)other)->anim.localPosY - ((GameObject *)obj)->anim.localPosY > (f32)(u32)*(u8 *)(def + 0x1d)) {
            tmp = *(int *)&((GameObject *)obj)->extra;
            j = 0;
            if ((((SwitchFlags *)(tmp + 0x84))->playerOnly) != 0) {
              if (other == (uint)Obj_GetPlayerObject()) {
                goto do_insert;
              }
              goto skip_insert;
            }
do_insert:
            while ((*(uint *)(tmp + (j & 0xff) * 4 + 4) != 0) && ((j & 0xff) != 9)) {
              j++;
            }
            ju = j & 0xff;
            *(uint *)(tmp + ju * 4 + 4) = other;
            base = tmp + ju * 8;
            *(f32 *)(base + 0x2c) = ((GameObject *)other)->anim.localPosX;
            *(f32 *)(base + 0x30) = ((GameObject *)other)->anim.localPosZ;
skip_insert: ;
          }
        }
        off += 4;
      }
    }
    slots2 = *(int *)&((GameObject *)obj)->extra;
    found = 0;
    for (j2 = 0; (j2 & 0xff) < 10; j2++) {
      ju2 = j2 & 0xff;
      o = *(uint *)(slots2 + ju2 * 4 + 4);
      if (o != 0) {
        base2 = slots2 + ju2 * 8;
        if ((*(f32 *)(base2 + 0x2c) == ((GameObject *)o)->anim.localPosX) &&
            (*(f32 *)(base2 + 0x30) == ((GameObject *)o)->anim.localPosZ)) {
          found = 1;
        } else {
          *(int *)(slots2 + ju2 * 4 + 4) = 0;
        }
      }
    }
    if (found) {
      *state = 5;
    }
    i = 0;
    if ((*state != 0) && ((((SwitchFlags *)(state + 0x84))->latched) == 0)) {
      if ((((SwitchFlags *)(state + 0x84))->active) != 0) {
        if (fn_80295C5C(Obj_GetPlayerObject()) != 0) {
          ((SwitchFlags *)(state + 0x84))->released = 0;
        }
      }
      if ((((SwitchFlags *)(state + 0x84))->released) == 0) {
        target = ((CfGuardianState *)state)->unk7C - (f32)(u32)*(u8 *)(def + 0x1c);
        cur = ((GameObject *)obj)->anim.localPosY;
        if (cur < target) {
          ((GameObject *)obj)->anim.localPosY = ((CfGuardianState *)state)->unk80 * timeDelta + cur;
          if (((GameObject *)obj)->anim.localPosY > target) {
            ((GameObject *)obj)->anim.localPosY = target;
          }
          GameBit_Set(((PressureswitchfbPlacement *)def)->unk1A, 1);
          if ((((SwitchFlags *)(state + 0x84))->active) != 0) {
            tex = (int *)objFindTexture((int *)obj, 0, 0);
            if (tex != NULL) {
              *tex = 0x100;
            }
            ((SwitchFlags *)(state + 0x84))->latched = 1;
          }
        } else {
          ((GameObject *)obj)->anim.localPosY = -(((CfGuardianState *)state)->unk80 * timeDelta - cur);
          if (((GameObject *)obj)->anim.localPosY < target) {
            ((GameObject *)obj)->anim.localPosY = target;
            GameBit_Set(((PressureswitchfbPlacement *)def)->unk1A, 1);
            if ((((SwitchFlags *)(state + 0x84))->active) != 0) {
              tex = (int *)objFindTexture((int *)obj, 0, 0);
              if (tex != NULL) {
                *tex = 0x100;
              }
              ((SwitchFlags *)(state + 0x84))->latched = 1;
            }
          } else {
            i = 1;
          }
        }
      } else {
        ((GameObject *)obj)->anim.localPosY = ((CfGuardianState *)state)->unk80 * timeDelta + ((GameObject *)obj)->anim.localPosY;
        if (((GameObject *)obj)->anim.localPosY > ((CfGuardianState *)state)->unk7C) {
          ((GameObject *)obj)->anim.localPosY = ((CfGuardianState *)state)->unk7C;
        } else {
          i = 1;
        }
      }
    } else {
      if ((((SwitchFlags *)(state + 0x84))->latched) == 0) {
        cur = ((GameObject *)obj)->anim.localPosY;
        if (cur < ((CfGuardianState *)state)->unk7C) {
          ((GameObject *)obj)->anim.localPosY = ((CfGuardianState *)state)->unk80 * timeDelta + cur;
          if (((GameObject *)obj)->anim.localPosY > ((CfGuardianState *)state)->unk7C) {
            ((GameObject *)obj)->anim.localPosY = ((CfGuardianState *)state)->unk7C;
            GameBit_Set(((PressureswitchfbPlacement *)def)->unk1A, 0);
          } else {
            i = 1;
          }
        }
      } else {
        if (GameBit_Get(((PressureswitchfbPlacement *)def)->unk1A) == 0) {
          tex = (int *)objFindTexture((int *)obj, 0, 0);
          if (tex != NULL) {
            *tex = 0;
          }
          ((SwitchFlags *)(state + 0x84))->latched = 0;
          ((SwitchFlags *)(state + 0x84))->released = 1;
        }
      }
    }
    if (((((GameObject *)obj)->objectFlags & 0x800) != 0) && ((((SwitchFlags *)(state + 0x84))->latched) == 0) &&
        ((((SwitchFlags *)(state + 0x84))->active) != 0)) {
      tmp = (int)Obj_GetPlayerObject();
      if (Vec_distance(&((GameObject *)obj)->anim.worldPosX, (f32 *)(tmp + 0x18)) < lbl_803E375C) {
        fx.x = lbl_803E3760;
        fx.y = lbl_803E3764;
        fx.z = lbl_803E3760;
        fx.w = lbl_803E3768;
        fx.arg = 0x12;
        fx.type = 10;
        tmp = 0;
        do {
          (*gPartfxInterface)->spawnObject((void *)obj, 0x7c3, &fx, 2, -1, NULL);
          tmp++;
        } while (tmp < 3);
      }
    }
    if ((s8)i != 0) {
      Sfx_PlayFromObject(obj, SFXms_baddie_beamin);
    } else {
      Sfx_StopObjectChannel(obj, 8);
    }
    if (((((PressureswitchfbPlacement *)def)->unk1E != 0) && ((tmp = (int)getTrickyObject()) != 0)) &&
        (GameBit_Get(((PressureswitchfbPlacement *)def)->unk1A) == 0)) {
      *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
      if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0) {
        (*(code *)(*(int *)(*(int *)(tmp + 0x68)) + 0x28))(tmp, obj, 1, 3);
      }
    }
  }
}

/*
 * --INFO--
 *
 * Function: FUN_8017b3b8
 * EN v1.0 Address: 0x8017B3B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017B93C
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017b3b8(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017b3bc
 * EN v1.0 Address: 0x8017B3BC
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x8017BB20
 * EN v1.1 Size: 796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_8017b3bc(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
  uint uVar1;
  undefined4 *puVar2;
  uint uVar3;
  uint uVar4;
  bool bVar5;
  int iVar6;
  int iVar7;
  ushort *puVar8;
  
  uVar1 = FUN_8028683c();
  puVar8 = *(ushort **)&((GameObject *)uVar1)->extra;
  iVar7 = *(int *)&((GameObject *)uVar1)->anim.placementData;
  if (((GameObject *)uVar1)->anim.alpha == 0) {
    ObjHits_DisableObject(uVar1);
  }
  if (*(char *)(*(int *)&((GameObject *)uVar1)->anim.modelInstance + 0x59) != '\0') {
    if (((*(byte *)(puVar8 + 3) & 1) != 0) &&
       (puVar2 = (undefined4 *)FUN_80039520(uVar1,0), puVar2 != (undefined4 *)0x0)) {
      *puVar2 = 0x100;
    }
    if (((*(byte *)(puVar8 + 3) & 2) != 0) &&
       (puVar2 = (undefined4 *)FUN_80039520(uVar1,1), puVar2 != (undefined4 *)0x0)) {
      *puVar2 = 0x100;
    }
  }
  if (*(char *)(puVar8 + 2) == '\0') {
    uVar3 = FUN_80017690((int)*(short *)(iVar7 + 0x18));
    bVar5 = false;
    if (((int)*(short *)(iVar7 + 0x22) == 0xffffffff) ||
       (uVar4 = FUN_80017690((int)*(short *)(iVar7 + 0x22)), uVar4 != 0)) {
      bVar5 = true;
    }
    if ((uVar3 != 0) && ((*(byte *)(puVar8 + 3) & 1) == 0)) {
      if (*(char *)(*(int *)&((GameObject *)uVar1)->anim.modelInstance + 0x59) != '\0') {
        FUN_80006824(uVar1,SFXen_weetinkoneshot);
      }
      *(byte *)(puVar8 + 3) = *(byte *)(puVar8 + 3) | 1;
    }
    if ((bVar5) && ((*(byte *)(puVar8 + 3) & 2) == 0)) {
      if (*(char *)(*(int *)&((GameObject *)uVar1)->anim.modelInstance + 0x59) != '\0') {
        FUN_80006824(uVar1,SFXen_weetinkoneshot);
      }
      *(byte *)(puVar8 + 3) = *(byte *)(puVar8 + 3) | 2;
    }
    if (*(char *)(puVar8 + 3) == '\x03') {
      *(undefined *)(puVar8 + 2) = 2;
      if (*puVar8 != 0) {
        FUN_80006824(uVar1,*puVar8);
      }
    }
  }
  else if ((*(char *)(puVar8 + 2) == '\x01') &&
          (uVar3 = FUN_80017690((int)*(short *)(iVar7 + 0x18)), uVar3 == 0)) {
    *(undefined *)(puVar8 + 2) = 3;
    if (*puVar8 != 0) {
      FUN_80006824(uVar1,*puVar8);
    }
  }
  if (*(char *)(puVar8 + 2) == '\x02') {
    for (iVar6 = 0; iVar6 < animUpdate->eventCount; iVar6 = iVar6 + 1) {
      if (animUpdate->eventIds[iVar6] == 2) {
        *(undefined *)(puVar8 + 2) = 1;
        if ((int)*(short *)(iVar7 + 0x1a) != 0xffffffff) {
          FUN_80017698((int)*(short *)(iVar7 + 0x1a),1);
        }
        if ((*puVar8 != 0) && (bVar5 = FUN_800067f8(uVar1,*puVar8), bVar5)) {
          FUN_80006810(uVar1,*puVar8);
        }
        if (puVar8[1] != 0) {
          FUN_80006824(uVar1,puVar8[1]);
        }
      }
    }
  }
  else if (*(char *)(puVar8 + 2) == '\x03') {
    for (iVar6 = 0; iVar6 < animUpdate->eventCount; iVar6 = iVar6 + 1) {
      if (animUpdate->eventIds[iVar6] == 1) {
        *(undefined *)(puVar8 + 2) = 0;
        *(undefined *)(puVar8 + 3) = 0;
        if ((int)*(short *)(iVar7 + 0x1a) != 0xffffffff) {
          FUN_80017698((int)*(short *)(iVar7 + 0x1a),0);
        }
        if ((*puVar8 != 0) && (bVar5 = FUN_800067f8(uVar1,*puVar8), bVar5)) {
          FUN_80006810(uVar1,*puVar8);
        }
        if (puVar8[1] != 0) {
          FUN_80006824(uVar1,puVar8[1]);
        }
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017b6bc
 * EN v1.0 Address: 0x8017B6BC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8017BE3C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void FUN_8017b6bc(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017b6dc
 * EN v1.0 Address: 0x8017B6DC
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x8017BE60
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_8017b6dc(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)&((GameObject *)param_1)->extra;
  iVar2 = *(int *)&((GameObject *)param_1)->anim.placementData;
  if (*(char *)(iVar3 + 5) != '\0') {
    if ((*(short *)(iVar2 + 0x1c) == 0) || (*(char *)(iVar3 + 4) == '\0')) {
      uVar1 = 0xffffffff;
    }
    else {
      uVar1 = *(byte *)(iVar2 + 0x20) & 0x7f;
      (*gObjectTriggerInterface)->preempt(param_1, *(s16 *)(iVar2 + 0x1c));
    }
    if (*(char *)(iVar2 + 0x1e) != -1) {
      (*gObjectTriggerInterface)->runSequence((int)*(char *)(iVar2 + 0x1e), (void *)param_1, uVar1);
    }
    *(undefined *)(iVar3 + 5) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017b7a8
 * EN v1.0 Address: 0x8017B7A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017BF24
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void FUN_8017b7a8(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8017b7ac
 * EN v1.0 Address: 0x8017B7AC
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x8017C0F4
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_8017b7ac(int param_1)
{
  uint uVar1;
  int iVar2;
  
  uVar1 = FUN_80017690((int)*(short *)(*(int *)&((GameObject *)param_1)->anim.placementData + 0x1e));
  if (uVar1 != 0) {
    iVar2 = FUN_80039520(param_1,0);
    if (iVar2 != 0) {
      *(short *)(iVar2 + 8) = *(short *)(iVar2 + 8) + (short)((int)lbl_803DC074 << 3);
      if (0x131e < (int)*(short *)(iVar2 + 8) + (int)lbl_803DC074 * 8) {
        *(undefined2 *)(iVar2 + 8) = 0x131f;
      }
      FUN_80135814();
    }
    ObjHits_EnableObject(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017b858
 * EN v1.0 Address: 0x8017B858
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x8017C1B4
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017b858(undefined2 *param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x26);
  iVar1 = FUN_80039520((int)param_1,0);
  if (iVar1 != 0) {
    *(undefined2 *)(iVar1 + 8) = 0x800;
  }
  *param_1 = (short)((int)*(char *)(iVar3 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  ObjHits_DisableObject((int)param_1);
  uVar2 = FUN_80017690((int)*(short *)(iVar3 + 0x1e));
  if (uVar2 != 0) {
    ObjHits_EnableObject((int)param_1);
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void mmp_bridge_free(void) {}
void mmp_bridge_render(void) {}
void mmp_bridge_hitDetect(void) {}
void mmp_bridge_release(void) {}
void mmp_bridge_initialise(void) {}

extern f32 lbl_803E3778;
extern void pressureswitchfb_updateStateMode(int obj, int p2, int stateParam);
__declspec(section ".sdata") extern char lbl_803DBD90[];
extern void fn_80137948(char *fmt, ...);

typedef struct PressureSwitchFbFlags {
    u8 usePressedTexture : 1;
    u8 startPressed : 1;
    u8 canRelease : 1;
    u8 autoPress : 1;
    u8 unused4 : 1;
    u8 unused5 : 1;
    u8 unused6 : 1;
    u8 unused7 : 1;
} PressureSwitchFbFlags;

void pressureswitchfb_init(u8* obj, u8* params) {
    ObjAnimComponent *objAnim;
    u8* sub;
    int *tex;
    f32 defaultOffset;
    PressureSwitchFbFlags *flags;

    objAnim = (ObjAnimComponent *)obj;
    sub = ((GameObject *)obj)->extra;
    flags = (PressureSwitchFbFlags *)(sub + 0x84);
    *(s16*)obj = (s16)(params[0x18] << 8);
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x6000);
    objAnim->bankIndex = (s8)params[0x19];
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
        objAnim->bankIndex = 0;
    }
    defaultOffset = lbl_803E3778;
    ((CfGuardianState *)sub)->unk80 = defaultOffset;
    if (((GameObject *)obj)->anim.seqId == 0x77b) {
        flags->usePressedTexture = 1;
        flags->startPressed = 1;
        flags->canRelease = 1;
        ((CfGuardianState *)sub)->unk80 = defaultOffset;
    }
    ((CfGuardianState *)sub)->unk7C = *(f32*)(params + 0xc);
    if (GameBit_Get(*(s16*)(params + 0x1a)) != 0) {
        s16 model;
        ((GameObject *)obj)->anim.localPosY = ((CfGuardianState *)sub)->unk7C - (f32)(u32)params[0x1c];
        sub[0] = 0x1e;
        flags->canRelease = 0;
        model = ((GameObject *)obj)->anim.seqId;
        if (model != 0x19f) {
            if (model != 0x26c) {
                if (model != 0x274) {
                    if (model != 0x545) {
                        flags->autoPress = 1;
                    }
                }
            }
        }
        if (flags->usePressedTexture) {
            tex = objFindTexture((int*)obj, 0, 0);
            if (tex != NULL) {
                *tex = 0x100;
            }
        }
    }
    ObjGroup_AddObject(obj, 0x53);
    ((CfGuardianState *)sub)->unk4 = 0;
    ((CfGuardianState *)sub)->unk8 = 0;
    ((CfGuardianState *)sub)->unkC = 0;
    ((CfGuardianState *)sub)->unk10 = 0;
    ((CfGuardianState *)sub)->unk14 = 0;
    ((CfGuardianState *)sub)->unk18 = 0;
    ((CfGuardianState *)sub)->unk1C = 0;
    ((CfGuardianState *)sub)->unk20 = 0;
    ((CfGuardianState *)sub)->unk24 = 0;
    ((CfGuardianState *)sub)->unk28 = 0;
    ((GameObject *)obj)->animEventCallback = (void *)pressureswitchfb_updateStateMode;
}

/* 8b "li r3, N; blr" returners. */
int Door_getExtraSize(void) { return 0x8; }
int mmp_bridge_getExtraSize(void) { return 0x0; }
int mmp_bridge_getObjectTypeId(void) { return 0x0; }
int doorlock_getExtraSize(void) { return 0x1; }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3780;
extern void objRenderFn_8003b8f4(f32);
void Door_render(void) { objRenderFn_8003b8f4(lbl_803E3780); }

/* ObjGroup_RemoveObject(x, N) wrappers. */
void doorlock_free(int x) { ObjGroup_RemoveObject(x, 0xf); }

void mmp_bridge_init(int *obj) {
    int *state = *(int **)&((GameObject *)obj)->anim.placementData;
    int *tex = objFindTexture(obj, 0, 0);
    if (tex != NULL) {
        *(s16 *)((char *)tex + 8) = 0x800;
    }
    *(s16 *)obj = (s16)(*(s8 *)((char *)state + 0x18) << 8);
    ((GameObject *)obj)->objectFlags |= 0x6000;
    ObjHits_DisableObject((int)obj);
    if (GameBit_Get(*(s16 *)((char *)state + 0x1e)) != 0) {
        ObjHits_EnableObject((int)obj);
    }
}

extern f32 lbl_803E3798;
extern void objRenderFn_80041018(int *obj);
void doorlock_render(int *obj, int p2, int p3, int p4, int p5, s8 visible) {
    if (visible != 0) {
        if (obj[0xf8/4] == 0) {
            goto render_basic;
        }
    }
    if (obj[0xf8/4] == 0) {
        return;
    }
    objRenderFn_80041018(obj);
    return;

render_basic:
    ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3798);
}

int Door_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
extern f32 lbl_803E3784;
extern f32 lbl_803E3788;
extern f32 lbl_803E3790;
void Door_init(int *obj, u8 *def) {
    u8 *state = ((GameObject *)obj)->extra;
    state[5] = 1;
    *(s16 *)obj = (s16)(def[0x1f] << 8);
    ((GameObject *)obj)->animEventCallback = (void *)Door_SeqFn;
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x2000);
    ((GameObject *)obj)->anim.rootMotionScale = ((f32)(u32)((DoorObjectDef *)def)->unk21 - lbl_803E3790) * lbl_803E3784;
    if (((GameObject *)obj)->anim.rootMotionScale == lbl_803E3788) {
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E3780;
    }
    ((GameObject *)obj)->anim.rootMotionScale = ((GameObject *)obj)->anim.rootMotionScale * *(f32 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 4);
    if (((DoorObjectDef *)def)->unk1A != -1) {
        state[4] = (u8)GameBit_Get(((DoorObjectDef *)def)->unk1A);
    } else {
        state[4] = 0;
    }
    state[6] = 0;
    if (GameBit_Get(((DoorObjectDef *)def)->unk18) != 0) state[6] = (u8)(state[6] | 1);
    if (GameBit_Get(((DoorObjectDef *)def)->unk22) != 0) state[6] = (u8)(state[6] | 2);
    {
        s16 model = ((GameObject *)obj)->anim.seqId;
        switch (model) {
        case 1101: {
            s32 subtype = ((GameObject *)obj)->anim.mapEventSlot;
            if ((subtype < 35 && subtype >= 31) || (subtype < 43 && subtype >= 40)) {
                *(s16 *)state = 832;
                *(s16 *)&((CfGuardianState *)state)->unk2 = 833;
            } else {
                *(s16 *)state = 1154;
                *(s16 *)&((CfGuardianState *)state)->unk2 = 1155;
            }
            break;
        }
        case 358:
            *(s16 *)state = 275;
            *(s16 *)&((CfGuardianState *)state)->unk2 = 504;
            break;
        }
    }
}

void Door_update(int obj)
{
  int state;
  int def;
  int triggerArg;
  int triggerId;

  state = *(int *)&((GameObject *)obj)->extra;
  def = *(int *)&((GameObject *)obj)->anim.placementData;
  if (*(u8 *)(state + 5) != 0) {
    triggerId = ((DoorPlacement *)def)->unk1C;
    if ((triggerId != 0) && (*(u8 *)(state + 4) != 0)) {
      triggerArg = *(u8 *)(def + 0x20) & 0x7f;
      (*gObjectTriggerInterface)->preempt(obj, triggerId);
    }
    else {
      triggerArg = -1;
    }
    if (*(s8 *)&((DoorPlacement *)def)->unk1E != -1) {
      (*gObjectTriggerInterface)->runSequence((int)*(s8 *)&((DoorPlacement *)def)->unk1E, (void *)obj, triggerArg);
    }
    *(u8 *)(state + 5) = 0;
  }
}

void mmp_bridge_update(int *obj)
{
  int *tex;
  int frame;

  if (GameBit_Get(*(s16 *)((char *)obj[0x4c / 4] + 0x1e)) != 0) {
    tex = objFindTexture(obj,0,0);
    if (tex != NULL) {
      frame = *(s16 *)((char *)tex + 8) + ((int)timeDelta << 3);
      *(s16 *)((char *)tex + 8) = (s16)frame;
      frame = *(s16 *)((char *)tex + 8) + ((int)timeDelta << 3);
      if (frame >= 0x131f) {
        *(s16 *)((char *)tex + 8) = 0x131f;
      }
      fn_80137948(lbl_803DBD90,(int)*(s16 *)((char *)tex + 8));
    }
    ObjHits_EnableObject((int)obj);
  }
}

extern int Sfx_IsPlayingFromObject(int obj, int sfxId);
extern int Sfx_StopFromObject(int obj, int sfxId);
extern int ObjTrigger_IsSetById(int obj, int id);
extern int ObjTrigger_IsSet(int obj);
extern void buttonDisable(int index, int mask);

/*
 * --INFO--
 *
 * Function: Door_SeqFn
 * EN v1.0 Address: 0x8017B5C8
 * EN v1.0 Size: 788b
 */
int Door_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
  int i;
  int state;
  int def;
  int opened;
  int closeReady;
  int *tex;
  int ret;

  state = *(int *)&((GameObject *)obj)->extra;
  def = *(int *)&((GameObject *)obj)->anim.placementData;
  if (((GameObject *)obj)->anim.alpha == 0) {
    ObjHits_DisableObject(obj);
  }
  if (*(u8 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x59) != 0) {
    if ((*(u8 *)(state + 6) & 1) != 0) {
      tex = (int *)objFindTexture((int *)obj, 0, 0);
      if (tex != NULL) {
        *tex = 0x100;
      }
    }
    if ((*(u8 *)(state + 6) & 2) != 0) {
      tex = (int *)objFindTexture((int *)obj, 1, 0);
      if (tex != NULL) {
        *tex = 0x100;
      }
    }
  }
  if (*(u8 *)(state + 4) == 0) {
    opened = GameBit_Get(((DoorPlacement *)def)->unk18);
    closeReady = 0;
    if ((((DoorPlacement *)def)->unk22 == -1) || (GameBit_Get(((DoorPlacement *)def)->unk22) != 0)) {
      closeReady = 1;
    }
    if ((opened != 0) && ((*(u8 *)(state + 6) & 1) == 0)) {
      if (*(u8 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x59) != 0) {
        Sfx_PlayFromObject(obj, 0x4b);
      }
      *(u8 *)(state + 6) |= 1;
    }
    if ((closeReady != 0) && ((*(u8 *)(state + 6) & 2) == 0)) {
      if (*(u8 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x59) != 0) {
        Sfx_PlayFromObject(obj, 0x4b);
      }
      *(u8 *)(state + 6) |= 2;
    }
    if (*(u8 *)(state + 6) == 3) {
      *(u8 *)(state + 4) = 2;
      if (*(u16 *)state != 0) {
        Sfx_PlayFromObject(obj, *(u16 *)state);
      }
    }
  } else if (*(u8 *)(state + 4) == 1) {
    if (GameBit_Get(((DoorPlacement *)def)->unk18) == 0) {
      *(u8 *)(state + 4) = 3;
      if (*(u16 *)state != 0) {
        Sfx_PlayFromObject(obj, *(u16 *)state);
      }
    }
  }
  if (*(u8 *)(state + 4) == 2) {
    for (i = 0; i < animUpdate->eventCount; i++) {
      if (animUpdate->eventIds[i] == 2) {
        *(u8 *)(state + 4) = 1;
        if (((DoorPlacement *)def)->unk1A != -1) {
          GameBit_Set(((DoorPlacement *)def)->unk1A, 1);
        }
        if ((*(u16 *)state != 0) && (Sfx_IsPlayingFromObject(obj, *(u16 *)state) != 0)) {
          Sfx_StopFromObject(obj, *(u16 *)state);
        }
        if (((CfGuardianState *)state)->unk2 != 0) {
          Sfx_PlayFromObject(obj, ((CfGuardianState *)state)->unk2);
        }
      }
    }
  } else if (*(u8 *)(state + 4) == 3) {
    for (i = 0; i < animUpdate->eventCount; i++) {
      if (animUpdate->eventIds[i] == 1) {
        *(u8 *)(state + 4) = 0;
        *(u8 *)(state + 6) = 0;
        if (((DoorPlacement *)def)->unk1A != -1) {
          GameBit_Set(((DoorPlacement *)def)->unk1A, 0);
        }
        if ((*(u16 *)state != 0) && (Sfx_IsPlayingFromObject(obj, *(u16 *)state) != 0)) {
          Sfx_StopFromObject(obj, *(u16 *)state);
        }
        if (((CfGuardianState *)state)->unk2 != 0) {
          Sfx_PlayFromObject(obj, ((CfGuardianState *)state)->unk2);
        }
      }
    }
  }
  ret = 0;
  if ((*(u8 *)(state + 4) != 2) && (*(u8 *)(state + 4) != 3)) {
    ret = 1;
  }
  return ret;
}

/*
 * --INFO--
 *
 * Function: Lock_DoorLock_SeqFn
 * EN v1.0 Address: 0x8017BCF8
 * EN v1.0 Size: 180b
 */
int Lock_DoorLock_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
  int def;

  def = *(int *)&((GameObject *)obj)->anim.placementData;
  if (animUpdate->triggerCommand != 0) {
    if (((*(u8 *)(def + 0x1b) & 4) != 0) && (animUpdate->triggerCommand == 1)) {
      GameBit_Set(((LockDoorLockPlacement *)def)->unk1C, 1);
    }
    if ((animUpdate->triggerCommand == 2) && (((LockDoorLockPlacement *)def)->unk24 != 0)) {
      (*gObjectTriggerInterface)->yield((ObjSeqState *)animUpdate, ((LockDoorLockPlacement *)def)->unk24);
    }
    animUpdate->triggerCommand = 0;
  }
  ((GameObject *)obj)->unkF8 = 0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: doorlock_update
 * EN v1.0 Address: 0x8017BE28
 * EN v1.0 Size: 848b
 */
void doorlock_update(int obj)
{
  int state;
  int def;
  int flags;
  u8 b;

  state = *(int *)&((GameObject *)obj)->extra;
  def = *(int *)&((GameObject *)obj)->anim.placementData;
  if (((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0) && (GameBit_Get(0x930) == 0)) {
    buttonDisable(0, 0x100);
    (*gObjectTriggerInterface)->setRunSequenceWorldSpace(obj, 0);
    (*gObjectTriggerInterface)->runSequence(1, (void *)obj, -1);
    GameBit_Set(0x930, 1);
  } else {
    *(u8 *)state = GameBit_Get(((DoorlockPlacement *)def)->unk1C);
    if ((*(u8 *)(def + 0x1b) & 1) != 0) {
      if (*(u8 *)state != 0) {
        ((GameObject *)obj)->anim.alpha = 0;
      }
    } else if ((((DoorlockPlacement *)def)->unk26 & 1) != 0) {
      if (*(u8 *)state != 0) {
        ((GameObject *)obj)->unkF8 = 0;
      } else {
        ((GameObject *)obj)->unkF8 = 1;
      }
    }
    if (*(u8 *)state == 0) {
      *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
      *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x10;
      if ((((DoorlockPlacement *)def)->unk22 != -1) && (GameBit_Get(((DoorlockPlacement *)def)->unk22) == 0)) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
        if ((*(u8 *)(def + 0x1b) & 0x10) != 0) {
          *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        }
      }
      if ((((DoorlockPlacement *)def)->unk1E != -1) && (GameBit_Get(((DoorlockPlacement *)def)->unk1E) == 0)) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
      }
      if (((((DoorlockPlacement *)def)->unk1E != -1) && (ObjTrigger_IsSetById(obj, ((DoorlockPlacement *)def)->unk1E) != 0)) ||
          ((((DoorlockPlacement *)def)->unk1E == -1) && (ObjTrigger_IsSet(obj) != 0))) {
        if (*(s8 *)(def + 0x20) != -1) {
          (*gObjectTriggerInterface)->runSequence((int)*(s8 *)(def + 0x20), (void *)obj, -1);
        }
        if ((*(u8 *)(def + 0x1b) & 4) == 0) {
          GameBit_Set(((DoorlockPlacement *)def)->unk1C, 1);
        }
        if ((*(u8 *)(def + 0x1b) & 8) != 0) {
          GameBit_Set(((DoorlockPlacement *)def)->unk22, 0);
        } else {
          *(u8 *)state = 1;
          ((GameObject *)obj)->unkF4 = 1;
        }
        buttonDisable(0, 0x100);
      }
    } else {
      if (((GameObject *)obj)->unkF4 == 0) {
        if ((*(s8 *)(def + 0x20) != -1) && (((DoorlockPlacement *)def)->unk24 != 0)) {
          (*gObjectTriggerInterface)->preempt(obj, ((DoorlockPlacement *)def)->unk24);
          flags = 1;
          b = *(u8 *)(def + 0x1b);
          if ((b & 0x20) != 0) {
            flags |= 2;
          }
          if ((b & 0x40) != 0) {
            flags |= 4;
          }
          if ((b & 0x80) != 0) {
            flags |= 8;
          }
          (*gObjectTriggerInterface)->runSequence((int)*(s8 *)(def + 0x20), (void *)obj, flags);
        }
        ((GameObject *)obj)->unkF4 = 1;
      }
      *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    }
    if (((((ObjAnimComponent *)obj)->modelInstance->flags & 1) != 0) && (*(void **)(obj + 0x74) != NULL)) {
      objRenderFn_80041018((int *)obj);
    }
  }
}
