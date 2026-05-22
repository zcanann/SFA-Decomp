#include "ghidra_import.h"
#include "main/dll/dll_15B.h"


#pragma peephole off
#pragma scheduling off
extern uint GameBit_Get(int eventId);
extern void *Resource_Acquire(int resourceId, int mode);
extern void ObjHits_DisableObject(u32 obj);
extern u32 randomGetRange(int min, int max);
extern void fn_8006961C(u32 *boundsOut, f32 *startPoints, f32 *endPoints, f32 *radii,
                        int pointCount);
extern void hitDetectFn_800691c0(int obj, void *bounds, uint mask, int flags);
extern u8 hitDetectFn_80067958(int obj, f32 *startPoints, f32 *endPoints, int pointCount,
                               void *outHits, int flags);

extern f32 lbl_803AC7A0[4];
extern undefined4 lbl_802C2280;
extern undefined4 lbl_802C228C;
extern undefined4 lbl_803DDAC8;
extern f32 lbl_803E39AC;
extern f64 lbl_803E39C8;
extern f32 lbl_803E39E8;
extern f32 lbl_803E39F4;
extern void LargeCrate_SeqFn(void);

/*
 * --INFO--
 *
 * Function: largecrate_init
 * EN v1.0 Address: 0x80184180
 * EN v1.0 Size: 568b
 * EN v1.1 Address: 0x801841F4
 * EN v1.1 Size: 568b
 */
void largecrate_init(int obj, u8 *initData)
{
  int state;
  u32 r3rand;
  int constArrA[3];
  int constArrB[3];
  short id;

  /* copy two constant blobs to stack (used as lookup arrays) */
  constArrA[0] = *(int *)((char *)&lbl_802C2280 + 0);
  constArrA[1] = *(int *)((char *)&lbl_802C2280 + 4);
  constArrA[2] = *(int *)((char *)&lbl_802C2280 + 8);
  constArrB[0] = *(int *)((char *)&lbl_802C228C + 0);
  constArrB[1] = *(int *)((char *)&lbl_802C228C + 4);
  constArrB[2] = *(int *)((char *)&lbl_802C228C + 8);

  state = *(int *)(obj + 0xb8);
  *(void (**)(void))(obj + 0xbc) = LargeCrate_SeqFn;
  *(short *)obj = (short)((int)(signed char)initData[0x18] << 8);
  *(short *)(state + 0xe) = *(short *)(initData + 0x1e);

  id = *(short *)(initData + 0x1c);
  if (id == LARGECRATE_TIMER_SENTINEL_DISABLED) {
    *(int *)state = LARGECRATE_TIMER_SENTINEL_DISABLED;
  }
  else if (id == LARGECRATE_TIMER_SENTINEL_FOREVER) {
    *(int *)state = -1;
  }
  else {
    *(int *)state = (int)id * LARGECRATE_TIMER_SCALE_FRAMES;
  }

  if (GameBit_Get((int)*(short *)(state + 0xe)) != 0) {
    *(float *)(state + 4) = lbl_803E39AC;
    ObjHits_DisableObject((u32)obj);
  }

  *(u8 *)(state + 0x11) = initData[0x19];
  lbl_803DDAC8 = (undefined4)Resource_Acquire(LARGECRATE_RESOURCE_ID, LARGECRATE_RESOURCE_MODE);
  r3rand = randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_DELAY_MAX);
  *(short *)(state + 0xa) = (short)(r3rand + LARGECRATE_RANDOM_DELAY_BASE);
  *(short *)(state + 0xc) = LARGECRATE_DEFAULT_COUNTDOWN;
  *(u8 *)(state + 0x12) = (u8)*(short *)(initData + 0x1a);
  *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | LARGECRATE_OBJECT_FLAGS);
  *(short *)obj = (short)((int)(signed char)initData[0x18] << 8);

  id = *(short *)(obj + 0x46);
  if (id == LARGECRATE_VARIANT_A) {
    *(u8 *)(state + 0x11) = (u8)((short *)constArrA)[*(u8 *)(state + 0x11)];
    *(short *)(state + 0x14) = LARGECRATE_VARIANT_A_SFX_A;
    *(short *)(state + 0x16) = LARGECRATE_VARIANT_A_SFX_B;
  }
  else if (id == LARGECRATE_VARIANT_B || id == LARGECRATE_VARIANT_C) {
    *(u8 *)(state + 0x11) = (u8)((short *)constArrB)[*(u8 *)(state + 0x11)];
    *(short *)(state + 0x14) = LARGECRATE_VARIANT_B_SFX_A;
    *(short *)(state + 0x16) = LARGECRATE_VARIANT_B_SFX_B;
  }

  *(short *)(state + 0x20) = 0;
  r3rand = randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_BOB_MAX);
  *(float *)(state + 0x1c) =
      lbl_803E39E8 + (float)((double)(int)r3rand - lbl_803E39C8);
  *(float *)(state + 0x24) = *(float *)(obj + 0xc);

  if (*(short *)(obj + 0x46) == LARGECRATE_VARIANT_C) {
    *(u8 *)(state + 0x28) = 0;
  }
  else {
    *(u8 *)(state + 0x28) = 2;
  }
}

/*
 * --INFO--
 *
 * Function: largecrate_release
 * EN v1.0 Address: 0x801843B8
 * EN v1.0 Size: 4b
 */
void largecrate_release(void)
{
}

/*
 * --INFO--
 *
 * Function: largecrate_initialise
 * EN v1.0 Address: 0x801843BC
 * EN v1.0 Size: 4b
 */
void largecrate_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: objHitboxFn_801843c0
 * EN v1.0 Address: 0x801843C0
 * EN v1.0 Size: 572b
 */
int objHitboxFn_801843c0(int obj)
{
  typedef struct HitDetectResults {
    f32 hitInfo[4][4];
    u8 pad40[0x1c];
    u32 solidFlags[4];
  } HitDetectResults;

  int state;
  f32 endPoints[12];
  f32 startPoints[3];
  u32 sweptBounds[6];
  f32 radii[4];
  HitDetectResults hitResults;
  u8 hitAxisTable[16];
  int idx;
  u8 hitMask;
  u8 hit;

  state = *(int *)(obj + 0x54);
  if (state == 0) {
    return 0;
  }
  endPoints[0] = *(float *)(obj + 0xc);
  endPoints[1] = *(float *)(obj + 0x10);
  endPoints[2] = *(float *)(obj + 0x14);
  startPoints[0] = *(float *)(obj + 0x80);
  startPoints[1] = *(float *)(obj + 0x84);
  startPoints[2] = *(float *)(obj + 0x88);
  radii[0] = lbl_803E39F4;
  hitAxisTable[0] = 0xff;
  hitAxisTable[4] = 0x3;

  fn_8006961C(sweptBounds, startPoints, endPoints, radii, 1);
  hitDetectFn_800691c0(obj, sweptBounds, *(ushort *)(state + 0xb2), 1);
  hit = hitDetectFn_80067958(obj, startPoints, endPoints, 1, &hitResults, 0);
  if (hit == 0) {
    return 0;
  }

  if ((hit & 1) != 0) {
    idx = 0;
  }
  else if ((hit & 2) != 0) {
    idx = 1;
  }
  else if ((hit & 4) != 0) {
    idx = 2;
  }
  else {
    idx = 3;
  }

  hitMask = ((u8 *)&hitAxisTable)[idx];
  *(u8 *)(state + 0xac) = hitMask;
  *(float *)(state + 0x3c) = endPoints[idx * 3];
  *(float *)(state + 0x40) = endPoints[idx * 3 + 1];
  *(float *)(state + 0x44) = endPoints[idx * 3 + 2];
  lbl_803AC7A0[0] = hitResults.hitInfo[idx][0];
  lbl_803AC7A0[1] = hitResults.hitInfo[idx][1];
  lbl_803AC7A0[2] = hitResults.hitInfo[idx][2];
  lbl_803AC7A0[3] = hitResults.hitInfo[idx][3];

  if (hitResults.solidFlags[idx] != 0) {
    *(u8 *)(state + 0xad) = (u8)((int)(signed char)*(u8 *)(state + 0xad) | 2);
  }
  else {
    *(u8 *)(state + 0xad) = (u8)((int)(signed char)*(u8 *)(state + 0xad) | 1);
  }
  *(float *)(obj + 0xc) = *(float *)(state + 0x3c);
  *(float *)(obj + 0x10) = *(float *)(state + 0x40);
  *(float *)(obj + 0x14) = *(float *)(state + 0x44);
  *(float *)(state + 0x10) = *(float *)(obj + 0x80);
  *(float *)(state + 0x14) = *(float *)(obj + 0x84);
  *(float *)(state + 0x18) = *(float *)(obj + 0x88);
  return 1;
}
