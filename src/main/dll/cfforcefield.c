#include "ghidra_import.h"
#include "main/dll/cfforcefield.h"


#pragma peephole off
#pragma scheduling off
extern uint GameBit_Get(int eventId);
extern void *Resource_Acquire(int resourceId, int mode);
extern void ObjHits_DisableObject(u32 obj);
extern u32 randomGetRange(int min, int max);
extern void hitDetect_calcSweptSphereBounds(u32 *boundsOut, f32 *startPoints, f32 *endPoints, f32 *radii,
                        int pointCount);
extern void hitDetectFn_800691c0(int obj, void *bounds, uint mask, int flags);
extern u8 hitDetectFn_80067958(int obj, f32 *startPoints, f32 *endPoints, int pointCount,
                               void *outHits, int flags);

extern f32 lbl_803AC7A0[4];
extern undefined4 lbl_803DDAC8;
extern f32 lbl_803E39AC;
extern f32 lbl_803E39E8;
extern f32 lbl_803E39F4;
extern void LargeCrate_SeqFn(void);

typedef union LargeCrateVariantRemap {
  s16 entries[6];
  int words[3];
} LargeCrateVariantRemap;

extern LargeCrateVariantRemap lbl_802C2280;
extern LargeCrateVariantRemap lbl_802C228C;

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
  f32 fr;
  LargeCrateVariantRemap constArrA;
  LargeCrateVariantRemap constArrB;
  short id;

  /* copy two constant blobs to stack (used as lookup arrays) */
  constArrA = lbl_802C2280;
  constArrB = lbl_802C228C;

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
    *(u8 *)(state + 0x11) = (u8)constArrA.entries[*(u8 *)(state + 0x11)];
    *(short *)(state + 0x14) = LARGECRATE_VARIANT_A_SFX_A;
    *(short *)(state + 0x16) = LARGECRATE_VARIANT_A_SFX_B;
  }
  else if (id == LARGECRATE_VARIANT_B || id == LARGECRATE_VARIANT_C) {
    *(u8 *)(state + 0x11) = (u8)constArrB.entries[*(u8 *)(state + 0x11)];
    *(short *)(state + 0x14) = LARGECRATE_VARIANT_B_SFX_A;
    *(short *)(state + 0x16) = LARGECRATE_VARIANT_B_SFX_B;
  }

  *(short *)(state + 0x20) = 0;
  r3rand = randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_BOB_MAX);
  fr = (float)(int)r3rand;
  fr = lbl_803E39E8 + fr;
  *(float *)(state + 0x1c) = fr;
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
    f32 radii[4];
    u8 axisTable[12];
    u32 solidFlags[4];
  } HitDetectResults;

  u8 *state;
  u32 sweptBounds[6];
  f32 endPoints[12];
  f32 startPoints[12];
  HitDetectResults results;
  int idx;
  u8 hit;

  state = *(u8 **)(obj + 0x54);
  if (state != 0) {
    endPoints[0] = *(float *)(obj + 0xc);
    endPoints[1] = *(float *)(obj + 0x10);
    endPoints[2] = *(float *)(obj + 0x14);
    startPoints[0] = *(float *)(obj + 0x80);
    startPoints[1] = *(float *)(obj + 0x84);
    startPoints[2] = *(float *)(obj + 0x88);
    results.radii[0] = lbl_803E39F4;
    *(s8 *)&results.axisTable[0] = -1;
    results.axisTable[4] = 0x3;
  } else {
    return 0;
  }

  hitDetect_calcSweptSphereBounds(sweptBounds, startPoints, endPoints, results.radii, 1);
  hitDetectFn_800691c0(obj, sweptBounds, *(ushort *)(state + 0xb2), 1);
  hit = hitDetectFn_80067958(obj, startPoints, endPoints, 1, &results, 0);
  if (hit != 0) {

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

  *(u8 *)(state + 0xac) = results.axisTable[idx];
  *(float *)(state + 0x3c) = endPoints[idx * 3];
  *(float *)(state + 0x40) = endPoints[idx * 3 + 1];
  *(float *)(state + 0x44) = endPoints[idx * 3 + 2];
  lbl_803AC7A0[0] = results.hitInfo[idx][0];
  lbl_803AC7A0[1] = results.hitInfo[idx][1];
  lbl_803AC7A0[2] = results.hitInfo[idx][2];
  lbl_803AC7A0[3] = results.hitInfo[idx][3];

  if (results.solidFlags[idx] != 0) {
    *(s8 *)(state + 0xad) = *(u8 *)(state + 0xad) | 2;
    *(float *)(obj + 0xc) = *(float *)(state + 0x3c);
    *(float *)(obj + 0x10) = *(float *)(state + 0x40);
    *(float *)(obj + 0x14) = *(float *)(state + 0x44);
    *(float *)(state + 0x10) = *(float *)(obj + 0x80);
    *(float *)(state + 0x14) = *(float *)(obj + 0x84);
    *(float *)(state + 0x18) = *(float *)(obj + 0x88);
    return 1;
  }
  *(s8 *)(state + 0xad) = *(u8 *)(state + 0xad) | 1;
  *(float *)(obj + 0xc) = *(float *)(state + 0x3c);
  *(float *)(obj + 0x10) = *(float *)(state + 0x40);
  *(float *)(obj + 0x14) = *(float *)(state + 0x44);
  *(float *)(state + 0x10) = *(float *)(obj + 0x80);
  *(float *)(state + 0x14) = *(float *)(obj + 0x84);
  *(float *)(state + 0x18) = *(float *)(obj + 0x88);
  return 1;
  }
  return 0;
}
