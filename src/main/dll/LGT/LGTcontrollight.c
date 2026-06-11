#include "main/dll/LGT/LGTcontrollight.h"

extern u32 randomGetRange(int min, int max);
extern void vecRotateZXY(void *params, void *outVec);

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
void fn_801F4C28(u8 *obj, u8 *rec)
{
  *(f32 *)(rec + 0x04) = *(f32 *)(obj + 0x0c);
  *(f32 *)(rec + 0x14) = *(f32 *)(obj + 0x10);
  *(f32 *)(rec + 0x24) = *(f32 *)(obj + 0x14);
  *(f32 *)(rec + 0x08) = *(f32 *)(obj + 0x0c);
  *(f32 *)(rec + 0x18) = *(f32 *)(obj + 0x10);
  *(f32 *)(rec + 0x28) = *(f32 *)(obj + 0x14);
  *(f32 *)(rec + 0x0c) = *(f32 *)(obj + 0x0c);
  *(f32 *)(rec + 0x1c) = *(f32 *)(obj + 0x10);
  *(f32 *)(rec + 0x2c) = *(f32 *)(obj + 0x14);
  *(f32 *)(rec + 0x10) = *(f32 *)(obj + 0x0c);
  *(f32 *)(rec + 0x20) = *(f32 *)(obj + 0x10);
  *(f32 *)(rec + 0x30) = *(f32 *)(obj + 0x14);
  *(f32 *)(rec + 0x44) = lbl_803E5EAC;
  *(f32 *)(rec + 0x48) = lbl_803E5EB0;
  *(f32 *)(rec + 0x40) = lbl_803E5EB4;
  rec[0x68] = 0;
  rec[0x67] = 0;
  *(s16 *)(rec + 0x62) = (s16)randomGetRange(0x1f4, 0x5dc);
  *(s16 *)(rec + 0x60) = (s16)randomGetRange(0, 0xfde8);
  *(s16 *)(rec + 0x64) = 0x3c;
  rec[0x66] = 4;
  *(f32 *)(rec + 0x4c) = lbl_803E5EB8;
  *(f32 *)(rec + 0x50) = lbl_803E5EBC;
  *(f32 *)(rec + 0x54) = *(f32 *)(obj + 0x0c);
  *(f32 *)(rec + 0x58) = *(f32 *)(obj + 0x10);
  *(f32 *)(rec + 0x5c) = *(f32 *)(obj + 0x14);
  rec[0x6b] = 1;
  *(f32 *)(rec + 0x78) = lbl_803E5EC0;
}

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
void fn_801F4D54(int obj, u8 *rec)
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

  *(f32 *)(rec + 0x34) = lbl_803E5EC4;
  if (rec[0x6b] != 0) {
    *(f32 *)(rec + 0x38) = (f32)(s32)(*(s16 *)(rec + 0x64));
    rec[0x6b] = 0;
  } else {
    *(f32 *)(rec + 0x38) =
        (f32)(s32)(randomGetRange(0, *(s16 *)(rec + 0x64)));
  }
  if (*(f32 *)(rec + 0x50) < lbl_803E5EC8) {
    *(f32 *)(rec + 0x3c) = lbl_803E5EC4;
  } else {
    *(f32 *)(rec + 0x3c) =
        *(f32 *)(rec + 0x50) -
        (f32)(s32)(randomGetRange(0x14, (s16)(s32)*(f32 *)(rec + 0x50)));
  }
  *(s16 *)(rec + 0x60) += (s16)randomGetRange(0xbb8, 0x1388);
  locals.z0 = lbl_803E5EC4;
  locals.z1 = lbl_803E5EC4;
  locals.z2 = lbl_803E5EC4;
  locals.m = lbl_803E5EB4;
  locals.b = 0;
  locals.a = 0;
  locals.angle = *(s16 *)(rec + 0x60);
  vecRotateZXY(&locals, rec + 0x34);
  *(f32 *)(rec + 0x34) =
      *(f32 *)(rec + 0x34) + *(f32 *)(rec + 0x54);
  *(f32 *)(rec + 0x38) =
      *(f32 *)(rec + 0x38) + *(f32 *)(rec + 0x58);
  *(f32 *)(rec + 0x3c) =
      *(f32 *)(rec + 0x3c) + *(f32 *)(rec + 0x5c);
}
