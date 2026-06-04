#include "ghidra_import.h"
#include "main/dll/cfguardian.h"

#define SFXen_weetinkoneshot 75
#define SFXms_baddie_beamin 97

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

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
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
#pragma scheduling off
#pragma peephole off
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
extern int *gPartfxInterface;
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

  def = *(int *)(obj + 0x4c);
  state = *(char **)(obj + 0xb8);
  if ((((SwitchFlags *)(state + 0x84))->active) != 0) {
    if ((((SwitchFlags *)(state + 0x84))->released) == 0) {
      *(u8 *)(obj + 0xaf) |= 8;
    } else {
      *(u8 *)(obj + 0xaf) &= ~8;
    }
  } else {
    *(u8 *)(obj + 0xaf) |= 8;
  }
  if ((*(s16 *)(def + 0x20) == -1) || (GameBit_Get(*(s16 *)(def + 0x20)) != 0)) {
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
        if ((*(s16 *)(other + 0x44) == 1) || (*(s16 *)(other + 0x44) == 2) ||
            (*(s16 *)(other + 0x46) == 0x754) || (*(s16 *)(other + 0x46) == 0x6d)) {
          isTarget = 1;
        } else {
          isTarget = 0;
        }
        if (isTarget && (other != nearest)) {
          if (*(f32 *)(other + 0x10) - *(f32 *)(obj + 0x10) > (f32)(u32)*(u8 *)(def + 0x1d)) {
            tmp = *(int *)(obj + 0xb8);
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
            *(f32 *)(base + 0x2c) = *(f32 *)(other + 0xc);
            *(f32 *)(base + 0x30) = *(f32 *)(other + 0x14);
skip_insert: ;
          }
        }
        off += 4;
      }
    }
    slots2 = *(int *)(obj + 0xb8);
    found = 0;
    for (j2 = 0; (j2 & 0xff) < 10; j2++) {
      ju2 = j2 & 0xff;
      o = *(uint *)(slots2 + ju2 * 4 + 4);
      if (o != 0) {
        base2 = slots2 + ju2 * 8;
        if ((*(f32 *)(base2 + 0x2c) == *(f32 *)(o + 0xc)) &&
            (*(f32 *)(base2 + 0x30) == *(f32 *)(o + 0x14))) {
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
        target = *(f32 *)(state + 0x7c) - (f32)(u32)*(u8 *)(def + 0x1c);
        cur = *(f32 *)(obj + 0x10);
        if (cur < target) {
          *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x80) * timeDelta + cur;
          if (*(f32 *)(obj + 0x10) > target) {
            *(f32 *)(obj + 0x10) = target;
          }
          GameBit_Set(*(s16 *)(def + 0x1a), 1);
          if ((((SwitchFlags *)(state + 0x84))->active) != 0) {
            tex = (int *)objFindTexture((int *)obj, 0, 0);
            if (tex != NULL) {
              *tex = 0x100;
            }
            ((SwitchFlags *)(state + 0x84))->latched = 1;
          }
        } else {
          *(f32 *)(obj + 0x10) = -(*(f32 *)(state + 0x80) * timeDelta - cur);
          if (*(f32 *)(obj + 0x10) < target) {
            *(f32 *)(obj + 0x10) = target;
            GameBit_Set(*(s16 *)(def + 0x1a), 1);
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
        *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x80) * timeDelta + *(f32 *)(obj + 0x10);
        if (*(f32 *)(obj + 0x10) > *(f32 *)(state + 0x7c)) {
          *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x7c);
        } else {
          i = 1;
        }
      }
    } else {
      if ((((SwitchFlags *)(state + 0x84))->latched) == 0) {
        cur = *(f32 *)(obj + 0x10);
        if (cur < *(f32 *)(state + 0x7c)) {
          *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x80) * timeDelta + cur;
          if (*(f32 *)(obj + 0x10) > *(f32 *)(state + 0x7c)) {
            *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x7c);
            GameBit_Set(*(s16 *)(def + 0x1a), 0);
          } else {
            i = 1;
          }
        }
      } else {
        if (GameBit_Get(*(s16 *)(def + 0x1a)) == 0) {
          tex = (int *)objFindTexture((int *)obj, 0, 0);
          if (tex != NULL) {
            *tex = 0;
          }
          ((SwitchFlags *)(state + 0x84))->latched = 0;
          ((SwitchFlags *)(state + 0x84))->released = 1;
        }
      }
    }
    if (((*(u16 *)(obj + 0xb0) & 0x800) != 0) && ((((SwitchFlags *)(state + 0x84))->latched) == 0) &&
        ((((SwitchFlags *)(state + 0x84))->active) != 0)) {
      tmp = (int)Obj_GetPlayerObject();
      if (Vec_distance((f32 *)(obj + 0x18), (f32 *)(tmp + 0x18)) < lbl_803E375C) {
        fx.x = lbl_803E3760;
        fx.y = lbl_803E3764;
        fx.z = lbl_803E3760;
        fx.w = lbl_803E3768;
        fx.arg = 0x12;
        fx.type = 10;
        tmp = 0;
        do {
          (*(code *)(*gPartfxInterface + 8))(obj, 0x7c3, &fx, 2, -1, 0);
          tmp++;
        } while (tmp < 3);
      }
    }
    if ((s8)i != 0) {
      Sfx_PlayFromObject(obj, SFXms_baddie_beamin);
    } else {
      Sfx_StopObjectChannel(obj, 8);
    }
    if (((*(u8 *)(def + 0x1e) != 0) && ((tmp = (int)getTrickyObject()) != 0)) &&
        (GameBit_Get(*(s16 *)(def + 0x1a)) == 0)) {
      *(u8 *)(obj + 0xaf) &= ~8;
      if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
        (*(code *)(*(int *)(*(int *)(tmp + 0x68)) + 0x28))(tmp, obj, 1, 3);
      }
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

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
void FUN_8017b3bc(undefined4 param_1,undefined4 param_2,int param_3)
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
  puVar8 = *(ushort **)(uVar1 + 0xb8);
  iVar7 = *(int *)(uVar1 + 0x4c);
  if (*(char *)(uVar1 + 0x36) == '\0') {
    ObjHits_DisableObject(uVar1);
  }
  if (*(char *)(*(int *)(uVar1 + 0x50) + 0x59) != '\0') {
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
      if (*(char *)(*(int *)(uVar1 + 0x50) + 0x59) != '\0') {
        FUN_80006824(uVar1,SFXen_weetinkoneshot);
      }
      *(byte *)(puVar8 + 3) = *(byte *)(puVar8 + 3) | 1;
    }
    if ((bVar5) && ((*(byte *)(puVar8 + 3) & 2) == 0)) {
      if (*(char *)(*(int *)(uVar1 + 0x50) + 0x59) != '\0') {
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
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
      if (*(char *)(param_3 + iVar6 + 0x81) == '\x02') {
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
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
      if (*(char *)(param_3 + iVar6 + 0x81) == '\x01') {
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
void FUN_8017b6dc(int param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*(char *)(iVar3 + 5) != '\0') {
    if ((*(short *)(iVar2 + 0x1c) == 0) || (*(char *)(iVar3 + 4) == '\0')) {
      uVar1 = 0xffffffff;
    }
    else {
      uVar1 = *(byte *)(iVar2 + 0x20) & 0x7f;
      (**(code **)(*DAT_803dd6d4 + 0x54))();
    }
    if (*(char *)(iVar2 + 0x1e) != -1) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar2 + 0x1e),param_1,uVar1);
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
void FUN_8017b7ac(int param_1)
{
  uint uVar1;
  int iVar2;
  
  uVar1 = FUN_80017690((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e));
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
void mmp_bridge_free(void) {}
void mmp_bridge_render(void) {}
void mmp_bridge_hitDetect(void) {}
void mmp_bridge_release(void) {}
void mmp_bridge_initialise(void) {}

extern f32 lbl_803E3778;
extern void pressureswitchfb_updateStateMode(int obj, int p2, int stateParam);
extern int *objFindTexture(int *obj, int a, int b);
extern u32 GameBit_Get(int eventId);
extern int *gObjectTriggerInterface;
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

#pragma scheduling off
#pragma peephole off
void pressureswitchfb_init(u8* obj, u8* params) {
    u8* sub;
    int *tex;
    f32 defaultOffset;
    PressureSwitchFbFlags *flags;

    sub = *(u8**)(obj + 0xb8);
    flags = (PressureSwitchFbFlags *)(sub + 0x84);
    *(s16*)obj = (s16)(params[0x18] << 8);
    *(u16*)(obj + 0xb0) = (u16)(*(u16*)(obj + 0xb0) | 0x6000);
    *(s8 *)(obj + 0xad) = (s8)params[0x19];
    if (*(s8 *)(obj + 0xad) >= *(s8*)(*(int*)(obj + 0x50) + 0x55)) {
        obj[0xad] = 0;
    }
    defaultOffset = lbl_803E3778;
    *(f32*)(sub + 0x80) = defaultOffset;
    if (*(s16*)(obj + 0x46) == 0x77b) {
        flags->usePressedTexture = 1;
        flags->startPressed = 1;
        flags->canRelease = 1;
        *(f32*)(sub + 0x80) = defaultOffset;
    }
    *(f32*)(sub + 0x7c) = *(f32*)(params + 0xc);
    if (GameBit_Get(*(s16*)(params + 0x1a)) != 0) {
        s16 model;
        *(f32*)(obj + 0x10) = *(f32*)(sub + 0x7c) - (f32)(u32)params[0x1c];
        sub[0] = 0x1e;
        flags->canRelease = 0;
        model = *(s16*)(obj + 0x46);
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
    *(int*)(sub + 4) = 0;
    *(int*)(sub + 8) = 0;
    *(int*)(sub + 0xc) = 0;
    *(int*)(sub + 0x10) = 0;
    *(int*)(sub + 0x14) = 0;
    *(int*)(sub + 0x18) = 0;
    *(int*)(sub + 0x1c) = 0;
    *(int*)(sub + 0x20) = 0;
    *(int*)(sub + 0x24) = 0;
    *(int*)(sub + 0x28) = 0;
    *(void**)(obj + 0xbc) = (void*)&pressureswitchfb_updateStateMode;
}
#pragma peephole reset
#pragma scheduling reset

/* 8b "li r3, N; blr" returners. */
int Door_getExtraSize(void) { return 0x8; }
int mmp_bridge_getExtraSize(void) { return 0x0; }
int mmp_bridge_getObjectTypeId(void) { return 0x0; }
int doorlock_getExtraSize(void) { return 0x1; }

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3780;
extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
void Door_render(void) { objRenderFn_8003b8f4(lbl_803E3780); }
#pragma peephole reset
#pragma scheduling reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void doorlock_free(int x) { ObjGroup_RemoveObject(x, 0xf); }
#pragma peephole reset
#pragma scheduling reset

extern int *objFindTexture(int *obj, int a, int b);
extern u32 GameBit_Get(int eventId);
#pragma scheduling off
#pragma peephole off
void mmp_bridge_init(int *obj) {
    int *state = *(int **)((char *)obj + 0x4c);
    int *tex = objFindTexture(obj, 0, 0);
    if (tex != NULL) {
        *(s16 *)((char *)tex + 8) = 0x800;
    }
    *(s16 *)obj = (s16)(*(s8 *)((char *)state + 0x18) << 8);
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
    ObjHits_DisableObject((int)obj);
    if (GameBit_Get(*(s16 *)((char *)state + 0x1e)) != 0) {
        ObjHits_EnableObject((int)obj);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E3798;
extern void objRenderFn_80041018(int *obj);
#pragma scheduling off
#pragma peephole off
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
#pragma peephole reset

int Door_SeqFn(int obj, int p2, int seq);
extern f32 lbl_803E3780;
extern f32 lbl_803E3784;
extern f32 lbl_803E3788;
extern f32 lbl_803E3790;
#pragma scheduling off
#pragma peephole off
void Door_init(int *obj, u8 *def) {
    u8 *state = *(u8 **)((char *)obj + 0xb8);
    state[5] = 1;
    *(s16 *)obj = (s16)(def[0x1f] << 8);
    *(int *)((char *)obj + 0xbc) = (int)Door_SeqFn;
    *(u16 *)((char *)obj + 0xb0) = (u16)(*(u16 *)((char *)obj + 0xb0) | 0x2000);
    *(f32 *)((char *)obj + 8) = ((f32)(u32)*(u8 *)((char *)def + 0x21) - lbl_803E3790) * lbl_803E3784;
    if (*(f32 *)((char *)obj + 8) == lbl_803E3788) {
        *(f32 *)((char *)obj + 8) = lbl_803E3780;
    }
    *(f32 *)((char *)obj + 8) = *(f32 *)((char *)obj + 8) * *(f32 *)(*(int *)((char *)obj + 0x50) + 4);
    if (*(s16 *)(def + 0x1a) != -1) {
        state[4] = (u8)GameBit_Get(*(s16 *)(def + 0x1a));
    } else {
        state[4] = 0;
    }
    state[6] = 0;
    if (GameBit_Get(*(s16 *)(def + 0x18)) != 0) state[6] = (u8)(state[6] | 1);
    if (GameBit_Get(*(s16 *)(def + 0x22)) != 0) state[6] = (u8)(state[6] | 2);
    {
        s16 model = *(s16 *)((char *)obj + 0x46);
        if (model == 1101) {
            s32 subtype = (s32)*(s8 *)((char *)obj + 0xac);
            if ((subtype >= 31 && subtype < 35) || (subtype >= 40 && subtype < 43)) {
                *(s16 *)state = 832;
                *(s16 *)(state + 2) = 833;
            } else {
                *(s16 *)state = 1154;
                *(s16 *)(state + 2) = 1155;
            }
        } else if (model == 358) {
            *(s16 *)state = 275;
            *(s16 *)(state + 2) = 504;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Door_update(int obj)
{
  int state;
  int def;
  int triggerArg;
  int triggerId;

  state = *(int *)(obj + 0xb8);
  def = *(int *)(obj + 0x4c);
  if (*(u8 *)(state + 5) != 0) {
    triggerId = *(s16 *)(def + 0x1c);
    if ((triggerId != 0) && (*(u8 *)(state + 4) != 0)) {
      triggerArg = *(u8 *)(def + 0x20) & 0x7f;
      (*(code *)(*gObjectTriggerInterface + 0x54))(obj,triggerId);
    }
    else {
      triggerArg = -1;
    }
    if (*(s8 *)(def + 0x1e) != -1) {
      (*(code *)(*gObjectTriggerInterface + 0x48))((int)*(s8 *)(def + 0x1e),obj,triggerArg);
    }
    *(u8 *)(state + 5) = 0;
  }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
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
#pragma peephole reset
#pragma scheduling reset

extern int Sfx_PlayFromObject(int obj, int sfxId);
extern int Sfx_IsPlayingFromObject(int obj, int sfxId);
extern int Sfx_StopFromObject(int obj, int sfxId);
extern int GameBit_Set(int eventId, int value);
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
#pragma scheduling off
#pragma peephole off
int Door_SeqFn(int obj, int p2, int seq)
{
  int state;
  int def;
  int opened;
  int closeReady;
  int i;
  int *tex;
  int ret;

  state = *(int *)(obj + 0xb8);
  def = *(int *)(obj + 0x4c);
  if (*(u8 *)(obj + 0x36) == 0) {
    ObjHits_DisableObject(obj);
  }
  if (*(u8 *)(*(int *)(obj + 0x50) + 0x59) != 0) {
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
    opened = GameBit_Get(*(s16 *)(def + 0x18));
    closeReady = 0;
    if ((*(s16 *)(def + 0x22) == -1) || (GameBit_Get(*(s16 *)(def + 0x22)) != 0)) {
      closeReady = 1;
    }
    if ((opened != 0) && ((*(u8 *)(state + 6) & 1) == 0)) {
      if (*(u8 *)(*(int *)(obj + 0x50) + 0x59) != 0) {
        Sfx_PlayFromObject(obj, 0x4b);
      }
      *(u8 *)(state + 6) |= 1;
    }
    if ((closeReady != 0) && ((*(u8 *)(state + 6) & 2) == 0)) {
      if (*(u8 *)(*(int *)(obj + 0x50) + 0x59) != 0) {
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
    if (GameBit_Get(*(s16 *)(def + 0x18)) == 0) {
      *(u8 *)(state + 4) = 3;
      if (*(u16 *)state != 0) {
        Sfx_PlayFromObject(obj, *(u16 *)state);
      }
    }
  }
  if (*(u8 *)(state + 4) == 2) {
    for (i = 0; i < *(u8 *)(seq + 0x8b); i++) {
      if (*(u8 *)(seq + i + 0x81) == 2) {
        *(u8 *)(state + 4) = 1;
        if (*(s16 *)(def + 0x1a) != -1) {
          GameBit_Set(*(s16 *)(def + 0x1a), 1);
        }
        if ((*(u16 *)state != 0) && (Sfx_IsPlayingFromObject(obj, *(u16 *)state) != 0)) {
          Sfx_StopFromObject(obj, *(u16 *)state);
        }
        if (*(u16 *)(state + 2) != 0) {
          Sfx_PlayFromObject(obj, *(u16 *)(state + 2));
        }
      }
    }
  } else if (*(u8 *)(state + 4) == 3) {
    for (i = 0; i < *(u8 *)(seq + 0x8b); i++) {
      if (*(u8 *)(seq + i + 0x81) == 1) {
        *(u8 *)(state + 4) = 0;
        *(u8 *)(state + 6) = 0;
        if (*(s16 *)(def + 0x1a) != -1) {
          GameBit_Set(*(s16 *)(def + 0x1a), 0);
        }
        if ((*(u16 *)state != 0) && (Sfx_IsPlayingFromObject(obj, *(u16 *)state) != 0)) {
          Sfx_StopFromObject(obj, *(u16 *)state);
        }
        if (*(u16 *)(state + 2) != 0) {
          Sfx_PlayFromObject(obj, *(u16 *)(state + 2));
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
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: Lock_DoorLock_SeqFn
 * EN v1.0 Address: 0x8017BCF8
 * EN v1.0 Size: 180b
 */
#pragma scheduling off
#pragma peephole off
int Lock_DoorLock_SeqFn(int obj, int p2, int seq)
{
  int def;

  def = *(int *)(obj + 0x4c);
  if (*(u8 *)(seq + 0x80) != 0) {
    if (((*(u8 *)(def + 0x1b) & 4) != 0) && (*(u8 *)(seq + 0x80) == 1)) {
      GameBit_Set(*(s16 *)(def + 0x1c), 1);
    }
    if ((*(u8 *)(seq + 0x80) == 2) && (*(s16 *)(def + 0x24) != 0)) {
      (*(code *)(*gObjectTriggerInterface + 0x58))(seq);
    }
    *(u8 *)(seq + 0x80) = 0;
  }
  *(int *)(obj + 0xf8) = 0;
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: doorlock_update
 * EN v1.0 Address: 0x8017BE28
 * EN v1.0 Size: 848b
 */
#pragma scheduling off
#pragma peephole off
void doorlock_update(int obj)
{
  int state;
  int def;
  int flags;
  u8 b;

  state = *(int *)(obj + 0xb8);
  def = *(int *)(obj + 0x4c);
  if (((*(u8 *)(obj + 0xaf) & 4) != 0) && (GameBit_Get(0x930) == 0)) {
    buttonDisable(0, 0x100);
    (*(code *)(*gObjectTriggerInterface + 0x84))(obj, 0);
    (*(code *)(*gObjectTriggerInterface + 0x48))(1, obj, -1);
    GameBit_Set(0x930, 1);
  } else {
    *(u8 *)state = GameBit_Get(*(s16 *)(def + 0x1c));
    if ((*(u8 *)(def + 0x1b) & 1) != 0) {
      if (*(u8 *)state != 0) {
        *(u8 *)(obj + 0x36) = 0;
      }
    } else if ((*(s16 *)(def + 0x26) & 1) != 0) {
      if (*(u8 *)state != 0) {
        *(int *)(obj + 0xf8) = 0;
      } else {
        *(int *)(obj + 0xf8) = 1;
      }
    }
    if (*(u8 *)state == 0) {
      *(u8 *)(obj + 0xaf) &= ~8;
      *(u8 *)(obj + 0xaf) &= ~0x10;
      if ((*(s16 *)(def + 0x22) != -1) && (GameBit_Get(*(s16 *)(def + 0x22)) == 0)) {
        *(u8 *)(obj + 0xaf) |= 0x10;
        if ((*(u8 *)(def + 0x1b) & 0x10) != 0) {
          *(u8 *)(obj + 0xaf) |= 8;
        }
      }
      if ((*(s16 *)(def + 0x1e) != -1) && (GameBit_Get(*(s16 *)(def + 0x1e)) == 0)) {
        *(u8 *)(obj + 0xaf) |= 0x10;
      }
      if (((*(s16 *)(def + 0x1e) != -1) && (ObjTrigger_IsSetById(obj, *(s16 *)(def + 0x1e)) != 0)) ||
          ((*(s16 *)(def + 0x1e) == -1) && (ObjTrigger_IsSet(obj) != 0))) {
        if (*(s8 *)(def + 0x20) != -1) {
          (*(code *)(*gObjectTriggerInterface + 0x48))((int)*(s8 *)(def + 0x20), obj, -1);
        }
        if ((*(u8 *)(def + 0x1b) & 4) == 0) {
          GameBit_Set(*(s16 *)(def + 0x1c), 1);
        }
        if ((*(u8 *)(def + 0x1b) & 8) != 0) {
          GameBit_Set(*(s16 *)(def + 0x22), 0);
        } else {
          *(u8 *)state = 1;
          *(int *)(obj + 0xf4) = 1;
        }
        buttonDisable(0, 0x100);
      }
    } else {
      if (*(int *)(obj + 0xf4) == 0) {
        if ((*(s8 *)(def + 0x20) != -1) && (*(s16 *)(def + 0x24) != 0)) {
          (*(code *)(*gObjectTriggerInterface + 0x54))(obj);
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
          (*(code *)(*gObjectTriggerInterface + 0x48))((int)*(s8 *)(def + 0x20), obj, flags);
        }
        *(int *)(obj + 0xf4) = 1;
      }
      *(u8 *)(obj + 0xaf) |= 8;
    }
    if (((*(u32 *)(*(int *)(obj + 0x50) + 0x44) & 1) != 0) && (*(int *)(obj + 0x74) != 0)) {
      objRenderFn_80041018((int *)obj);
    }
  }
}
#pragma peephole reset
#pragma scheduling reset
