#include "ghidra_import.h"
#include "main/dll/screenOverlay.h"

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void ObjHitbox_SetSphereRadius(int obj, short radius);
extern int ObjHits_GetPriorityHit(int obj, int *outArr, int *outA, uint *outB);
extern void Sfx_PlayFromObject(int obj, int soundId);
extern void *objFindTexture(int obj, int a, int b);
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, float arg);
extern int seqStreamLookupFn_8007fff8(void *table, int mode, int seq);
extern void fn_8003B608(u32 a, u32 b, u32 c);

extern u8 framesThisStep;
extern f32 timeDelta;
extern undefined4 lbl_80321008;
extern f32 lbl_803E3700;
extern f32 lbl_803E3704;
extern f32 lbl_803E3708;
extern f64 lbl_803E3710;
extern f32 lbl_803E3718;
extern f64 lbl_803E3720;
extern f32 lbl_803E3728;
extern f32 lbl_803E3730;
extern f32 lbl_803E3734;
extern f32 lbl_803E3738;
extern f32 lbl_803E373C;
extern f64 lbl_803E3740;
extern f64 lbl_803E3748;

/*
 * --INFO--
 *
 * Function: ProjectileSwitch_render
 * EN v1.0 Address: 0x8017A38C
 * EN v1.0 Size: 140b
 */
void ProjectileSwitch_render(int obj, int p2, int p3, int p4, int p5, char flag)
{
  int state = *(int *)(obj + 0x4c);
  if ((int)(signed char)flag != 0) {
    if ((*(u8 *)(state + 0x23) & 1) != 0) {
      fn_8003B608(*(u8 *)(state + 0x20), *(u8 *)(state + 0x21), *(u8 *)(state + 0x22));
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E3700);
  }
}

/*
 * --INFO--
 *
 * Function: ProjectileSwitch_hitDetect
 * EN v1.0 Address: 0x8017A418
 * EN v1.0 Size: 460b
 */
void ProjectileSwitch_hitDetect(int obj)
{
  int state2;
  int state;
  int hitId;
  int hit;
  int hitObj;
  void *tex;
  int isSpecial;

  state2 = *(int *)(obj + 0x4c);
  state = *(int *)(obj + 0xb8);
  hitId = ObjHits_GetPriorityHit(obj, &hitObj, (int *)0x0, (uint *)0x0);
  if (hitId != 0xe && hitId != 0xf) return;

  isSpecial = 0;
  if (*(short *)(hitObj + 0x46) == 0x14b) {
    if ((*(u8 *)(*(int *)(hitObj + 0x54) + 0xad) & 2) != 0) {
      isSpecial = 1;
    }
  }
  if (isSpecial != 0) return;

  if (*(u8 *)state != 0) {
    /* deactivate */
    if ((*(u8 *)(state2 + 0x1e) & 3) != 1) return;
    state = *(int *)(obj + 0xb8);
    if ((int)(signed char)*(u8 *)(obj + 0xac) == 0x2c) {
      Sfx_PlayFromObject(obj, 0x109);
    } else {
      Sfx_PlayFromObject(obj, 0x63);
    }
    tex = objFindTexture(obj, 0, 0);
    if (tex != 0) {
      *(int *)tex = 0;
    }
    *(u8 *)state = 0;
    GameBit_Set((int)*(short *)(state + 2), 0);
  } else {
    /* activate */
    state = *(int *)(obj + 0xb8);
    if ((int)(signed char)*(u8 *)(obj + 0xac) == 0x2c) {
      Sfx_PlayFromObject(obj, 0x109);
    } else {
      Sfx_PlayFromObject(obj, 0x62);
    }
    tex = objFindTexture(obj, 0, 0);
    if (tex != 0) {
      *(int *)tex = 0x100;
    }
    *(u8 *)state = 1;
    GameBit_Set((int)*(short *)(state + 2), 1);
    if ((*(u8 *)(state2 + 0x1e) & 3) == 2) {
      *(float *)(state + 4) =
          lbl_803E3704 * lbl_803E3708 *
          (float)((double)(int)(*(short *)(state2 + 0x1a) ^ 0x80000000) - lbl_803E3710);
    }
  }
}

/*
 * --INFO--
 *
 * Function: ProjectileSwitch_update
 * EN v1.0 Address: 0x8017A5E4
 * EN v1.0 Size: 280b
 */
void ProjectileSwitch_update(int obj)
{
  int state;
  int state2;
  void *tex;

  state = *(int *)(obj + 0xb8);
  if (*(u8 *)state != 0) {
    if (GameBit_Get((int)*(short *)(state + 2)) == 0) {
      state2 = *(int *)(obj + 0xb8);
      tex = objFindTexture(obj, 0, 0);
      if (tex != 0) *(int *)tex = 0;
      *(u8 *)state2 = 0;
    }
  } else {
    if (GameBit_Get((int)*(short *)(state + 2)) != 0) {
      state2 = *(int *)(obj + 0xb8);
      tex = objFindTexture(obj, 0, 0);
      if (tex != 0) *(int *)tex = 0x100;
      *(u8 *)state2 = 1;
    }
  }
  if (lbl_803E3718 < *(float *)(state + 4)) {
    *(float *)(state + 4) =
        *(float *)(state + 4) - (float)((double)(int)framesThisStep - lbl_803E3720);
    if (*(float *)(state + 4) <= lbl_803E3718) {
      *(float *)(state + 4) = lbl_803E3718;
      GameBit_Set((int)*(short *)(state + 2), 0);
    }
  }
}

/*
 * --INFO--
 *
 * Function: ProjectileSwitch_init
 * EN v1.0 Address: 0x8017A6FC
 * EN v1.0 Size: 488b
 */
void ProjectileSwitch_init(int obj, u8 *initData)
{
  int state;
  int linkObj;
  int linkSub;
  void *tex;

  state = *(int *)(obj + 0xb8);
  *(short *)obj = (short)((int)(signed char)initData[0x1f] << 8);
  *(short *)(obj + 2) = (short)((int)(signed char)initData[0x1c] << 8);
  if (initData[0x1d] == 0) {
    *(float *)(obj + 8) = *(float *)(*(int *)(obj + 0x50) + 4);
  } else {
    *(float *)(obj + 8) =
        ((float)((double)(int)initData[0x1d] - lbl_803E3720) *
         *(float *)(*(int *)(obj + 0x50) + 4)) * lbl_803E3728;
  }
  ObjHitbox_SetSphereRadius(
      obj, (short)(((int)initData[0x1d] * (int)*(u8 *)(*(int *)(obj + 0x50) + 0x62)) >> 6));
  *(u8 *)(obj + 0xad) = (u8)((int)(signed char)initData[0x1e] >> 2);
  if ((int)(signed char)*(u8 *)(obj + 0xad) >=
      (int)(signed char)*(u8 *)(*(int *)(obj + 0x50) + 0x55)) {
    *(u8 *)(obj + 0xad) = 0;
  }

  linkObj = *(int *)(obj + 0x30);
  if (linkObj != 0) {
    linkSub = *(int *)(linkObj + 0x4c);
    if (linkSub != 0) {
      *(short *)(state + 2) =
          (short)seqStreamLookupFn_8007fff8(&lbl_80321008, 2, *(int *)(linkSub + 0x14));
    } else {
      *(short *)(state + 2) = -1;
    }
  } else {
    *(short *)(state + 2) = *(short *)(initData + 0x18);
  }
  *(u8 *)state = (u8)GameBit_Get((int)*(short *)(state + 2));
  if (*(u8 *)state != 0) {
    state = *(int *)(obj + 0xb8);
    tex = objFindTexture(obj, 0, 0);
    if (tex != 0) *(int *)tex = 0x100;
    *(u8 *)state = 1;
  } else {
    state = *(int *)(obj + 0xb8);
    tex = objFindTexture(obj, 0, 0);
    if (tex != 0) *(int *)tex = 0;
    *(u8 *)state = 0;
  }
  if ((initData[0x23] & 1) == 0) {
    *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x4000);
  }
}

/* Trivial 4b 0-arg blr leaves. */
void ProjectileSwitch_release(void) {}
void ProjectileSwitch_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int InvisibleHitSwitch_getExtraSize(void) { return 0xc; }

/*
 * --INFO--
 *
 * Function: InvisibleHitSwitch_update
 * EN v1.0 Address: 0x8017A8F4
 * EN v1.0 Size: 556b
 */
void InvisibleHitSwitch_update(int obj)
{
  int state2;
  int state;
  int hitId;

  state2 = *(int *)(obj + 0x4c);
  state = *(int *)(obj + 0xb8);
  if (*(u8 *)state != 0) {
    if (GameBit_Get((int)*(short *)(state2 + 0x18)) == 0) {
      *(u8 *)state = 0;
    }
  } else {
    if (GameBit_Get((int)*(short *)(state2 + 0x18)) != 0) {
      *(u8 *)state = 1;
    }
  }

  if (lbl_803E3730 < *(float *)(state + 4)) {
    *(float *)(state + 4) =
        *(float *)(state + 4) - (float)((double)(int)framesThisStep - lbl_803E3740);
    if (*(float *)(state + 4) <= lbl_803E3730) {
      *(float *)(state + 4) = lbl_803E3730;
      GameBit_Set((int)*(short *)(state2 + 0x18), 0);
      return;
    }
    return;
  }

  if (*(float *)(state + 8) != lbl_803E3730) {
    *(float *)(state + 8) = *(float *)(state + 8) - timeDelta;
    if (*(float *)(state + 8) < lbl_803E3734) {
      hitId = ObjHits_GetPriorityHit(obj, 0, 0, 0);
      if ((int)*(u8 *)(state + 1) == hitId) {
        *(float *)(state + 8) = lbl_803E3730;
        *(u8 *)state = 1;
        GameBit_Set((int)*(short *)(state2 + 0x18), 1);
      } else if (lbl_803E3730 < *(float *)(state + 8)) {
        /* nothing */
      } else {
        *(float *)(state + 8) = lbl_803E3730;
      }
    }
  } else {
    hitId = ObjHits_GetPriorityHit(obj, 0, 0, 0);
    if ((int)*(u8 *)(state + 1) != hitId) return;
    if (*(u8 *)state != 0) {
      if ((*(u8 *)(state2 + 0x1e) & 3) != 1) return;
      *(u8 *)state = 0;
      GameBit_Set((int)*(short *)(state2 + 0x18), 0);
    } else {
      if ((*(u8 *)(state2 + 0x1e) & 3) == 3) {
        *(float *)(state + 8) = lbl_803E3738;
        return;
      }
      *(u8 *)state = 1;
      GameBit_Set((int)*(short *)(state2 + 0x18), 1);
      if ((*(u8 *)(state2 + 0x1e) & 3) == 2) {
        *(float *)(state + 4) =
            lbl_803E3734 * lbl_803E373C *
            (float)((double)(int)(*(short *)(state2 + 0x1a) ^ 0x80000000) - lbl_803E3748);
      }
    }
  }
}
