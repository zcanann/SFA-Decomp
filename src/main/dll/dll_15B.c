#include "ghidra_import.h"
#include "main/dll/dll_15B.h"

extern uint GameBit_Get(int eventId);
extern void *Resource_Acquire(int resourceId, int mode);
extern void ObjHits_DisableObject(u32 obj);
extern u32 randomGetRange(int min, int max);
extern int fn_8006961C(void *outA, void *inA, void *inB, int param4);
extern int hitDetectFn_800691c0(int obj, void *outA, short id, int param4);
extern int hitDetectFn_80067958(int obj, void *inA, void *inB, int param4, void *outVec, int param6);

extern f32 *lbl_803AC7A0;
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
  if (id == 0) {
    *(int *)state = 0;
  }
  else if (id == 0xff) {
    *(int *)state = -1;
  }
  else {
    *(int *)state = (int)id * 0x3c;
  }

  if (GameBit_Get((int)*(short *)(state + 0xe)) != 0) {
    *(float *)(state + 4) = lbl_803E39AC;
    ObjHits_DisableObject((u32)obj);
  }

  *(u8 *)(state + 0x11) = initData[0x19];
  lbl_803DDAC8 = (undefined4)Resource_Acquire(0x5b, 1);
  r3rand = randomGetRange(0, 100);
  *(short *)(state + 0xa) = (short)(r3rand + 300);
  *(short *)(state + 0xc) = 0x190;
  *(u8 *)(state + 0x12) = (u8)*(short *)(initData + 0x1a);
  *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x2000);
  *(short *)obj = (short)((int)(signed char)initData[0x18] << 8);

  id = *(short *)(obj + 0x46);
  if (id == 0x3de) {
    *(u8 *)(state + 0x11) = (u8)((short *)constArrA)[*(u8 *)(state + 0x11)];
    *(short *)(state + 0x14) = 0x5f;
    *(short *)(state + 0x16) = 0x60;
  }
  else if (id == 0x49f || id == 0x7be) {
    *(u8 *)(state + 0x11) = (u8)((short *)constArrB)[*(u8 *)(state + 0x11)];
    *(short *)(state + 0x14) = 0x48;
    *(short *)(state + 0x16) = 0x4a;
  }

  *(short *)(state + 0x20) = 0;
  r3rand = randomGetRange(0, 200);
  *(float *)(state + 0x1c) =
      lbl_803E39E8 + (float)((double)(int)r3rand - lbl_803E39C8);
  *(float *)(state + 0x24) = *(float *)(obj + 0xc);

  if (*(short *)(obj + 0x46) == 0x7be) {
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
  int state;
  float locA[3], locB[3], locC[3];
  float origin[3];
  float resultTable[16];
  u8 hitTable[16];
  u32 *zeroTable;
  float gridVec[4];
  int idx;
  u8 hitMask;
  int hit;

  state = *(int *)(obj + 0x54);
  if (state == 0) {
    return 0;
  }
  locA[0] = *(float *)(obj + 0xc);
  locA[1] = *(float *)(obj + 0x10);
  locA[2] = *(float *)(obj + 0x14);
  locB[0] = *(float *)(obj + 0x80);
  locB[1] = *(float *)(obj + 0x84);
  locB[2] = *(float *)(obj + 0x88);
  gridVec[0] = lbl_803E39F4;
  hitTable[0] = 0xff;
  hitTable[4] = 0x3;

  fn_8006961C(&locC, locB, locA, 1);
  hitDetectFn_800691c0(obj, &locC, *(short *)(state + 0xb2), 1);
  hit = hitDetectFn_80067958(obj, locB, locA, 1, locB, 0);
  hit = hit & 0xff;
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

  hitMask = ((u8 *)&hitTable)[idx];
  *(u8 *)(state + 0xac) = hitMask;
  *(float *)(state + 0x3c) = locA[idx];
  *(float *)(state + 0x40) = locA[idx];  /* same column trick */
  *(float *)(state + 0x44) = locA[idx];
  *(float *)&lbl_803AC7A0 = locB[idx];

  zeroTable = (u32 *)((char *)&hitTable + 0x0c);
  if (zeroTable[idx] != 0) {
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
