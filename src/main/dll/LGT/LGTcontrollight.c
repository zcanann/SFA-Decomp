#include "ghidra_import.h"
#include "main/dll/LGT/LGTcontrollight.h"

extern u32 randomGetRange(int min, int max);
extern void mathFn_80021ac8(void *params, void *outVec);

extern f32 lbl_803E5EAC;
extern f32 lbl_803E5EB0;
extern f32 lbl_803E5EB4;
extern f32 lbl_803E5EB8;
extern f32 lbl_803E5EBC;
extern f32 lbl_803E5EC0;
extern f32 lbl_803E5EC4;
extern f32 lbl_803E5EC8;
extern f64 lbl_803E5ED0;


/*
 * --INFO--
 *
 * Function: fn_801F4C28
 * EN v1.0 Address: 0x801F4C28
 * EN v1.0 Size: 300b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_801F4C28(u8 *param_1, u8 *param_2)
{
  *(f32 *)(param_2 + 0x04) = *(f32 *)(param_1 + 0x0c);
  *(f32 *)(param_2 + 0x14) = *(f32 *)(param_1 + 0x10);
  *(f32 *)(param_2 + 0x24) = *(f32 *)(param_1 + 0x14);
  *(f32 *)(param_2 + 0x08) = *(f32 *)(param_1 + 0x0c);
  *(f32 *)(param_2 + 0x18) = *(f32 *)(param_1 + 0x10);
  *(f32 *)(param_2 + 0x28) = *(f32 *)(param_1 + 0x14);
  *(f32 *)(param_2 + 0x0c) = *(f32 *)(param_1 + 0x0c);
  *(f32 *)(param_2 + 0x1c) = *(f32 *)(param_1 + 0x10);
  *(f32 *)(param_2 + 0x2c) = *(f32 *)(param_1 + 0x14);
  *(f32 *)(param_2 + 0x10) = *(f32 *)(param_1 + 0x0c);
  *(f32 *)(param_2 + 0x20) = *(f32 *)(param_1 + 0x10);
  *(f32 *)(param_2 + 0x30) = *(f32 *)(param_1 + 0x14);
  *(f32 *)(param_2 + 0x44) = lbl_803E5EAC;
  *(f32 *)(param_2 + 0x48) = lbl_803E5EB0;
  *(f32 *)(param_2 + 0x40) = lbl_803E5EB4;
  param_2[0x68] = 0;
  param_2[0x67] = 0;
  *(s16 *)(param_2 + 0x62) = (s16)randomGetRange(0x1f4, 0x5dc);
  *(s16 *)(param_2 + 0x60) = (s16)randomGetRange(0, 0xfde8);
  *(s16 *)(param_2 + 0x64) = 0x3c;
  param_2[0x66] = 4;
  *(f32 *)(param_2 + 0x4c) = lbl_803E5EB8;
  *(f32 *)(param_2 + 0x50) = lbl_803E5EBC;
  *(f32 *)(param_2 + 0x54) = *(f32 *)(param_1 + 0x0c);
  *(f32 *)(param_2 + 0x58) = *(f32 *)(param_1 + 0x10);
  *(f32 *)(param_2 + 0x5c) = *(f32 *)(param_1 + 0x14);
  param_2[0x6b] = 1;
  *(f32 *)(param_2 + 0x78) = lbl_803E5EC0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_801F4D54
 * EN v1.0 Address: 0x801F4D54
 * EN v1.0 Size: 376b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_801F4D54(int param_1, u8 *param_2)
{
  struct {
    s16 angle;
    s16 a;
    s16 b;
    u8 pad0e[2];
    f32 m;
    f32 z0;
    f32 z1;
    f32 z2;
  } locals;

  *(f32 *)(param_2 + 0x34) = lbl_803E5EC4;
  if (param_2[0x6b] != 0) {
    *(f32 *)(param_2 + 0x38) = (f32)(s32)(*(s16 *)(param_2 + 0x64));
    param_2[0x6b] = 0;
  } else {
    *(f32 *)(param_2 + 0x38) =
        (f32)(s32)(randomGetRange(0, *(s16 *)(param_2 + 0x64)));
  }
  if (*(f32 *)(param_2 + 0x50) < lbl_803E5EC8) {
    *(f32 *)(param_2 + 0x3c) = lbl_803E5EC4;
  } else {
    *(f32 *)(param_2 + 0x3c) =
        *(f32 *)(param_2 + 0x50) -
        (f32)(s32)(randomGetRange(0x14, (s16)(s32)*(f32 *)(param_2 + 0x50)));
  }
  *(s16 *)(param_2 + 0x60) =
      *(s16 *)(param_2 + 0x60) + (s16)randomGetRange(0xbb8, 0x1388);
  locals.m = lbl_803E5EB4;
  locals.z0 = lbl_803E5EC4;
  locals.z1 = lbl_803E5EC4;
  locals.z2 = lbl_803E5EC4;
  locals.b = 0;
  locals.a = 0;
  locals.angle = *(s16 *)(param_2 + 0x60);
  mathFn_80021ac8(&locals, param_2 + 0x34);
  *(f32 *)(param_2 + 0x34) =
      *(f32 *)(param_2 + 0x34) + *(f32 *)(param_2 + 0x54);
  *(f32 *)(param_2 + 0x38) =
      *(f32 *)(param_2 + 0x38) + *(f32 *)(param_2 + 0x58);
  *(f32 *)(param_2 + 0x3c) =
      *(f32 *)(param_2 + 0x3c) + *(f32 *)(param_2 + 0x5c);
}
#pragma peephole reset
#pragma scheduling reset
