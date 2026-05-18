#include "ghidra_import.h"
#include "main/dll/dll_14C.h"

extern void objRenderFn_80041018(void);
extern int  ObjGroup_FindNearestObject(byte type, int obj, float *dist_out);
extern u32  GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern u32  randomGetRange(int min, int max);

extern f32 lbl_803E384C;
extern void *lbl_803DCA54;

#pragma scheduling off
#pragma peephole off
void dll_FC_update(int param_1)
{
  int *piVar1;
  byte *pbState;
  uint uVar3;
  float local8;

  local8 = lbl_803E384C;
  piVar1 = *(int **)(param_1 + 0x4c);
  pbState = *(byte **)(param_1 + 0xb8);

  if (*(uint *)(pbState + 4) == 0) {
    *(int *)(pbState + 4) = ObjGroup_FindNearestObject(*(byte *)((int)piVar1 + 0x1c), param_1, &local8);
    if (*(uint *)(pbState + 4) == 0) goto end;
    if ((int)*(short *)((int)piVar1 + 0x1a) == -1) {
      pbState[2] = 0;
    } else {
      uVar3 = GameBit_Get((int)*(short *)((int)piVar1 + 0x1a));
      pbState[2] = (byte)uVar3;
    }
    pbState[0] = 1;
  }

  *(float *)(param_1 + 0x0c) = *(float *)(*(int *)(pbState + 4) + 0x0c);
  *(float *)(param_1 + 0x10) = *(float *)(*(int *)(pbState + 4) + 0x10);
  *(float *)(param_1 + 0x14) = *(float *)(*(int *)(pbState + 4) + 0x14);
  *(short *)(param_1 + 0x00) = *(short *)(*(int *)(pbState + 4) + 0x00);
  *(short *)(param_1 + 0x04) = *(short *)(*(int *)(pbState + 4) + 0x04);
  *(short *)(param_1 + 0x02) = *(short *)(*(int *)(pbState + 4) + 0x02);

  switch (pbState[0]) {
  case 3:
    break;
  case 1:
    if ((pbState[2] != 0) && ((*(byte *)((int)piVar1 + 0x1f) & 1) == 0)) {
      *(byte *)(*(int *)(pbState + 4) + 0xaf) &= ~0x20;
      *(byte *)(param_1 + 0xaf) |= 0x08;
      pbState[0] = 3;
    } else if (((int)*(short *)((int)piVar1 + 0x18) != -1) &&
               (GameBit_Get((int)*(short *)((int)piVar1 + 0x18)) == 0)) {
      *(byte *)(*(int *)(pbState + 4) + 0xaf) &= ~0x20;
      *(byte *)(param_1 + 0xaf) |= 0x08;
      pbState[0] = 2;
    } else if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      if ((*(byte *)((int)piVar1 + 0x1f) & 2) != 0) {
        GameBit_Set((int)*(short *)((int)piVar1 + 0x18), 0);
      }
      if ((int)*(short *)((int)piVar1 + 0x1a) != -1) {
        GameBit_Set((int)*(short *)((int)piVar1 + 0x1a), 1);
      }
      if ((*(byte *)((int)piVar1 + 0x1f) & 4) != 0) {
        uVar3 = randomGetRange((int)*(byte *)((int)piVar1 + 0x1d), (int)*(byte *)((int)piVar1 + 0x1e));
        pbState[1] = (byte)uVar3;
      } else {
        pbState[1] += 1;
        if (pbState[1] > *(byte *)((int)piVar1 + 0x1e)) {
          pbState[1] = *(byte *)((int)piVar1 + 0x1d);
        }
      }
      *(byte *)(param_1 + 0xaf) |= 0x08;
      pbState[2] = 1;
      (*(void (***)(byte, int, int))lbl_803DCA54)[0x12](pbState[1], param_1, -1);
    } else {
      *(byte *)(*(int *)(pbState + 4) + 0xaf) |= 0x20;
      *(byte *)(param_1 + 0xaf) &= ~0x08;
    }
    break;
  case 2:
    if (GameBit_Get((int)*(short *)((int)piVar1 + 0x18)) != 0) {
      pbState[0] = 1;
    }
    break;
  }
end:
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dll_FC_init
 * EN v1.0 Address: 0x8017EF3C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017F17C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void dll_FC_init(int param_1, int param_2)
{
  byte *pbVar1;

  pbVar1 = *(byte **)(param_1 + 0xb8);
  pbVar1[0] = 0;
  pbVar1[1] = *(byte *)(param_2 + 0x1e);
  *(ushort *)(param_1 + 0xb0) |= 0x4000;
  return;
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: dll_14D_hitDetect
 * EN v1.0 Address: 0x8017EFB0
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x8017F1AC
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
void dll_14D_hitDetect(int param_1)
{
  if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) && (*(uint *)(param_1 + 0x74) != 0)) {
    objRenderFn_80041018();
  }
  return;
}
#pragma peephole reset


/* Trivial 4b 0-arg blr leaves. */
void dll_FC_release_nop(void) {}
void dll_FC_initialise_nop(void) {}
void dll_14D_free_nop(void) {}

/* 8b "li r3, N; blr" returners. */
int dll_14D_getExtraSize_ret_8(void) { return 0x8; }
int dll_14D_func08_ret_0(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3850;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void dll_14D_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E3850); }
#pragma peephole reset
