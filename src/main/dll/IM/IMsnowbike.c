#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
#include "main/dll/IM/IMsnowbike.h"
#include "main/dll/SC/SCtotemlogpuz.h"

typedef struct ShLevelcontrolState {
    u8 pad0[0x5 - 0x0];
    u8 unk5;
    u8 pad6[0xC - 0x6];
    f32 unkC;
    s16 unk10;
    s16 unk12;
    u8 pad14[0x18 - 0x14];
} ShLevelcontrolState;


extern u32 GameBit_Get(u32 id);
extern void GameBit_Set(u32 id, u32 value);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int Obj_GetPlayerObject(void);
extern void buttonDisable(int a, int b);
extern void padClearAnalogInputY(int a);
extern void padClearAnalogInputX(int a);
extern void gameTextShow(int a);
extern void fn_80088870(void *a, void *b, void *c, void *d);
extern void envFxActFn_800887f8(int a);
extern void skyFn_80088e54(int a, f32 b);
extern void getEnvfxAct(int a, int b, int c, int d);
extern void getEnvfxActImmediately(int a, int b, int c, int d);
extern void SH_LevelControl_setMusic(uint *param_1);
extern void SH_LevelControl_runBloopEvent(int param_1, uint *param_2);
extern void SH_LevelControl_doThornTailEvents(int param_1, uint *param_2);
extern void SH_LevelControl_doEarlyScenes(int param_1, uint *param_2);
extern void objRenderFn_8003b8f4(f32);

extern MapEventInterface **gMapEventInterface;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern f32 lbl_803E54B4;
extern f32 lbl_803E54C8;
extern f32 timeDelta;
extern u8 lbl_80327618[0x104];

/*
 * --INFO--
 *
 * Function: sh_levelcontrol_update
 * EN v1.0 Address: 0x801D8D20
 * EN v1.0 Size: 2452b
 * EN v1.1 Address: 0x801D90F0
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sh_levelcontrol_update(int obj)
{
  uint *state;
  uint val;
  uint val2;
  uint val3;
  u8 animEvt;
  u8 *base = lbl_80327618;

  state = ((GameObject *)obj)->extra;
  if (*(f32 *)((int)state + 0xc) > lbl_803E54B4) {
    gameTextShow(0x3f6);
    *(f32 *)((int)state + 0xc) = *(f32 *)((int)state + 0xc) - timeDelta;
    if (*(f32 *)((int)state + 0xc) < *(f32 *)&lbl_803E54B4) {
      *(f32 *)((int)state + 0xc) = lbl_803E54B4;
    }
  }
  SH_LevelControl_setMusic(state);
  val = GameBit_Get(0x3aa);
  if (val != 0) {
    if (((GameObject *)obj)->anim.mapEventSlot == 8) {
      animEvt = (*gMapEventInterface)->getAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1d);
      if (animEvt == '\0') {
        (*gMapEventInterface)->setAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1d, 1);
      }
    }
    else {
      animEvt = (*gMapEventInterface)->getAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1d);
      if (animEvt != '\0') {
        (*gMapEventInterface)->setAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1d, 0);
      }
    }
  }
  val = GameBit_Get(0x3b8);
  if (val != 0) {
    animEvt = (*gMapEventInterface)->getAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1c);
    if (animEvt == '\0') {
      (*gMapEventInterface)->setAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1c, 1);
    }
  }
  else {
    animEvt = (*gMapEventInterface)->getAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1c);
    if (animEvt != '\0') {
      (*gMapEventInterface)->setAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1c, 0);
    }
  }
  val = GameBit_Get(999);
  if ((val != 0) &&
     (animEvt = (*gMapEventInterface)->getAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1b),
     animEvt == '\0')) {
    (*gMapEventInterface)->setAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1b, 1);
  }
  val = GameBit_Get(0x11);
  if (val != 0) {
    animEvt = (*gMapEventInterface)->getAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1a);
    if (animEvt == '\0') {
      (*gMapEventInterface)->setAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1a, 1);
    }
  }
  else {
    animEvt = (*gMapEventInterface)->getAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1a);
    if (animEvt != '\0') {
      (*gMapEventInterface)->setAnimEvent((int)((GameObject *)obj)->anim.mapEventSlot, 0x1a, 0);
    }
  }
  switch (*(undefined *)((int)state + 5)) {
  case 1:
    SH_LevelControl_doEarlyScenes(obj, state);
    break;
  case 2:
    val = GameBit_Get(0xbf);
    if ((val != 0) && (val3 = GameBit_Get(0xc2), val3 < 6)) {
      if (*(short *)((int)state + 0x12) != 0xdb) {
        *(undefined2 *)((int)state + 0x12) = 0xdb;
        GameBit_Set(0xc0, 1);
        *state = *state & 0xfffffffd;
      }
    }
    else {
      val = GameBit_Get(0xc2);
      if ((val == 6) && (*(short *)((int)state + 0x12) != 0xcc)) {
        *(undefined2 *)((int)state + 0x12) = 0xcc;
        GameBit_Set(0xc0, 1);
        *state = *state & 0xfffffffd;
      }
    }
    val = GameBit_Get(0xc2);
    val2 = GameBit_Get(0x66d);
    if ((val2 + val == 6) && (val = GameBit_Get(0xe5b), val == 0)) {
      Sfx_PlayFromObject(obj, SFXmn_sml_trex_fstep);
      GameBit_Set(0xe5b, 1);
    }
    break;
  case 3:
    SH_LevelControl_doThornTailEvents(obj, state);
    break;
  case 4:
    if (*(short *)((int)state + 0x12) != 0xcc) {
      *(undefined2 *)((int)state + 0x12) = 0xcc;
      GameBit_Set(0xc0, 1);
      *state = *state & 0xfffffffd;
    }
    if (*(byte *)(state + 1) >= 2) {
      val = GameBit_Get(0xdff);
      if (val == 0) {
        padClearAnalogInputX(0);
        padClearAnalogInputY(0);
        buttonDisable(0, 0x100);
        buttonDisable(0, 0x200);
        buttonDisable(0, 0x1000);
        val = Obj_GetPlayerObject();
        if ((*(ushort *)(val + 0xb0) & 0x1000) == 0) {
          (*gObjectTriggerInterface)->runSequence(7, (void *)obj, 0xffffffff);
          GameBit_Set(0xdff, 1);
        }
      }
      else {
        val = GameBit_Get(0xede);
        if (val == 0) {
          GameBit_Set(0xede, 1);
          GameBit_Set(0x9d5, 1);
        }
      }
    }
    else {
      *(byte *)(state + 1) += 1;
    }
    break;
  case 5:
    val = GameBit_Get(0x23c);
    if (val != 0) {
      if (*(short *)((int)state + 0x12) != 0xcc) {
        *(undefined2 *)((int)state + 0x12) = 0xcc;
        GameBit_Set(0xc0, 1);
        *state = *state & 0xfffffffd;
      }
    }
    else if (*(short *)((int)state + 0x12) == 0xcc) {
      *(s16 *)((int)state + 0x12) = -1;
    }
    val = GameBit_Get(0x90);
    if (((val != 0) && (val = GameBit_Get(0xeb3), val == 0)) &&
       (val = Obj_GetPlayerObject(), (*(ushort *)(val + 0xb0) & 0x1000) == 0)) {
      GameBit_Set(0xeb3, 1);
    }
    break;
  case 6:
    SH_LevelControl_runBloopEvent(obj, state);
    break;
  case 7:
    val = GameBit_Get(0x1a0);
    if (val != 0) {
      if (*(short *)((int)state + 0x12) != 0xcc) {
        *(undefined2 *)((int)state + 0x12) = 0xcc;
        GameBit_Set(0xc0, 1);
        *state = *state & 0xfffffffd;
      }
    }
    else if (*(short *)((int)state + 0x12) == 0xcc) {
      *(s16 *)((int)state + 0x12) = -1;
    }
    if (*(byte *)(state + 1) >= 2) {
      val = GameBit_Get(0x177);
      if (val == 0) {
        padClearAnalogInputX(0);
        padClearAnalogInputY(0);
        buttonDisable(0, 0x100);
        buttonDisable(0, 0x200);
        buttonDisable(0, 0x1000);
        val = Obj_GetPlayerObject();
        if ((*(ushort *)(val + 0xb0) & 0x1000) == 0) {
          (*gObjectTriggerInterface)->runSequence(4, (void *)obj, 0xffffffff);
          GameBit_Set(0x177, 1);
        }
      }
    }
    else {
      *(byte *)(state + 1) += 1;
    }
    break;
  case 8:
    if (*(short *)((int)state + 0x12) != 0xcc) {
      *(undefined2 *)((int)state + 0x12) = 0xcc;
      GameBit_Set(0xc0, 1);
      *state = *state & 0xfffffffd;
    }
    val = GameBit_Get(0x19c);
    if ((val != 0) && (val = GameBit_Get(0xf3e), val == 0)) {
      GameBit_Set(0xf3e, 1);
      val = GameBit_Get(0xc64);
      if (val == 0) {
        GameBit_Set(0x9d5, 1);
      }
    }
  }
  val = GameBit_Get(0xd36);
  if (val != 0) {
    if (((GameObject *)obj)->unkF8 != 2) {
      ((GameObject *)obj)->unkF8 = 2;
      envFxActFn_800887f8(0);
      if (((GameObject *)obj)->unkF4 == 2) {
        getEnvfxActImmediately(0, 0, 0x1bf, 0);
        getEnvfxActImmediately(0, 0, 0x231, 0);
        getEnvfxActImmediately(0, 0, 0x232, 0);
        getEnvfxActImmediately(0, 0, 0x244, 0);
      }
      else {
        getEnvfxAct(0, 0, 0x1bf, 0);
        getEnvfxAct(0, 0, 0x231, 0);
        getEnvfxAct(0, 0, 0x232, 0);
        getEnvfxAct(0, 0, 0x244, 0);
      }
    }
  }
  else {
    val = GameBit_Get(0xd35);
    if (val != 0) {
      if (((GameObject *)obj)->unkF8 != 1) {
        ((GameObject *)obj)->unkF8 = 1;
        if (((GameObject *)obj)->unkF4 == 2) {
          envFxActFn_800887f8(0);
          getEnvfxActImmediately(0, 0, 0x1bf, 0);
          getEnvfxActImmediately(0, 0, 0x1be, 0);
          getEnvfxActImmediately(0, 0, 0x1c0, 0);
          getEnvfxActImmediately(0, 0, 0x244, 0);
        }
        else {
          envFxActFn_800887f8(0);
          getEnvfxAct(0, 0, 0x1bf, 0);
          getEnvfxAct(0, 0, 0x1be, 0);
          getEnvfxAct(0, 0, 0x1c0, 0);
          getEnvfxAct(0, 0, 0x244, 0);
        }
      }
    }
    else if (((GameObject *)obj)->unkF8 != 0) {
      ((GameObject *)obj)->unkF8 = 0;
      if (((GameObject *)obj)->unkF4 == 2) {
        fn_80088870(&base[0x5c], &base[0x24], &base[0x94], &base[0xcc]);
        envFxActFn_800887f8(0x3f);
        getEnvfxActImmediately(0, 0, 0x244, 0);
        skyFn_80088e54(0, lbl_803E54B4);
      }
      else {
        fn_80088870(&base[0x5c], &base[0x24], &base[0x94], &base[0xcc]);
        envFxActFn_800887f8(0x1f);
        getEnvfxAct(0, 0, 0x244, 0);
      }
    }
  }
  mapUnloadFn_801d7c94((void *)obj, state);
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void warpstonelift_free(void) {}
void warpstonelift_hitDetect(void) {}
void warpstonelift_release(void) {}
void warpstonelift_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int warpstonelift_getExtraSize(void) { return 0x1; }
int warpstonelift_getObjectTypeId(void) { return 0x0; }
int sh_staff_getExtraSize(void) { return 0x74; }

extern s32 lbl_803DC058[2];
extern void fn_8002B6D8(int obj, int p2, int p3, int p4, int p5, int p6);
extern void Music_Trigger(int track, int param);
extern int getSaveGameLoadStatus(void);
extern void timeOfDayFn_80055000(void);
extern f32 lbl_803E54C0;
extern s16 lbl_80327618_ids[];

void sh_levelcontrol_init(int obj) {
    int *state = ((GameObject *)obj)->extra;
    int i;
    s16 *bitIds;
    u32 v;

    ((GameObject *)obj)->animEventCallback = (void *)SH_LevelControl_SeqFn;
    v = (u32)((GameObject *)obj)->objectFlags | 0x4000;
    ((GameObject *)obj)->objectFlags = (u16)v;
    ((GameObject *)obj)->unkF8 = 3;

    if (getSaveGameLoadStatus() != 0) {
        ((GameObject *)obj)->unkF4 = 2;
    } else {
        ((GameObject *)obj)->unkF4 = 1;
    }

    ((ShLevelcontrolState *)state)->unk10 = -1;
    ((ShLevelcontrolState *)state)->unkC = lbl_803E54C0;

    if (GameBit_Get(0x611) != 0) {
        *(int *)state |= 0x40;
    }

    ((ShLevelcontrolState *)state)->unk5 = (*gMapEventInterface)->getMode((int)((GameObject *)obj)->anim.mapEventSlot);

    ((ShLevelcontrolState *)state)->unk12 = -1;
    Music_Trigger(34, 0);
    Music_Trigger(49, 0);
    Music_Trigger(178, 0);
    Music_Trigger(196, 0);
    Music_Trigger(166, 0);
    Music_Trigger(172, 0);
    Music_Trigger(168, 0);
    GameBit_Set(3213, 1);

    if (GameBit_Get(319) == 0) {
        bitIds = lbl_80327618_ids;
        for (i = 0; i < 18; i++) {
            GameBit_Set(*bitIds, 0);
            bitIds++;
        }
    }
    timeOfDayFn_80055000();
}
void warpstonelift_init(int obj, s8 *def) {
    int *state = ((GameObject *)obj)->extra;
    int i;
    *(s16 *)obj = (s16)((s32)def[0x18] << 8);
    ((GameObject *)obj)->unkF4 = 0;
    for (i = 0; i < 2; i++) {
        if (GameBit_Get(lbl_803DC058[i]) != 0) {
            *(u8 *)state = (u8)(i + 1);
        }
    }
    switch (*(u8 *)state) {
    case 0:
    case 2:
        fn_8002B6D8((int)obj, 0, 0, 0, 0, 3);
        break;
    case 1:
        fn_8002B6D8((int)obj, 0, 0, 0, 0, 4);
        break;
    }
}

extern void getYButtonItem(s16 *out);
extern int cMenuGetSelectedItem(void);
extern int ObjTrigger_IsSetById(int obj, int id);
extern int ObjTrigger_IsSet(int obj);

void warpstonelift_update(u8 *obj) {
    u8 *state = ((GameObject *)obj)->extra;
    int off;
    char *p;
    int found = 0;
    int count;
    int i;
    s16 item;

    p = *(char **)(obj + 0x58);
    count = *(s8 *)(p + 0x10F);
    if (count > 0) {
        off = 0;
        for (i = 0; i < count; i++) {
            char *o = *(char **)((int)p + (off + 0x100));
            if (*(s16 *)(o + 0x44) == 1) {
                found = 1;
            }
            off += 4;
        }
    }
    if (found) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x8;
        switch (*state) {
        case 0:
        case 1:
            getYButtonItem(&item);
            if ((GameBit_Get(0xC7C) != 0 && cMenuGetSelectedItem() != -1) || item == 0xC7C) {
                fn_8002B6D8((int)obj, 0, 0, 0, 0, 4);
            } else {
                fn_8002B6D8((int)obj, 0, 0, 0, 0, 2);
            }
            if (ObjTrigger_IsSetById((int)obj, 0xC7C) != 0) {
                GameBit_Set(0x886, 1);
                GameBit_Set(0xC7D, 1);
                *state = 2;
                fn_8002B6D8((int)obj, 0, 0, 0, 0, 3);
            } else if (ObjTrigger_IsSet((int)obj) != 0) {
                GameBit_Set(0xC7E, 1);
            }
            break;
        case 2:
            if (ObjTrigger_IsSet((int)obj) != 0) {
                GameBit_Set(0x886, 1);
            }
            break;
        }
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x8;
    }
}

/* render-with-objRenderFn_8003b8f4 pattern. */
void warpstonelift_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E54C8); }

void sh_staff_free(int *obj, int p2) {
    int *state = ((GameObject *)obj)->extra;
    char *p;
    int idx;

    if (p2 != 0) return;

    for (idx = 0; idx < 8; idx += 4) {
        int *child;
        p = (char *)state + idx * 5;
        child = *(int **)(p + 56);
        if (child != NULL) {
            *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
        }
        child = *(int **)(p + 60);
        if (child != NULL) {
            *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
        }
        child = *(int **)(p + 64);
        if (child != NULL) {
            *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
        }
        child = *(int **)(p + 68);
        if (child != NULL) {
            *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
        }
        child = *(int **)(p + 72);
        if (child != NULL) {
            *(s16 *)((char *)child + 6) = (s16)(*(s16 *)((char *)child + 6) | 0x4000);
        }
        p += 20;
    }
}
