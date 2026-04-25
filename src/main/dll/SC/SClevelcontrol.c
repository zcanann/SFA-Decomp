#include "ghidra_import.h"
#include "main/dll/SC/SClevelcontrol.h"

extern undefined4 fn_8003842C();
extern undefined4 fn_8003B8F4();
extern undefined4 fn_80114DEC();

extern f32 lbl_803E5448;

/*
 * --INFO--
 *
 * Function: sh_thorntail_render
 * EN v1.0 Address: 0x801D5ED4
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801D64C4
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void sh_thorntail_render(SHthorntailObject *obj)
{
  int pointIndex;
  int runtime;

  runtime = *(int *)((int)obj + 0xb8);
  fn_8003B8F4((double)lbl_803E5448);
  fn_80114DEC((int)obj,runtime,0);
  pointIndex = 0;
  do {
    fn_8003842C((int)obj,pointIndex,runtime + 0x8e0,runtime + 0x8e4,runtime + 0x8e8,0);
    runtime = runtime + 0xc;
    pointIndex = pointIndex + 1;
  } while (pointIndex < SHTHORNTAIL_RENDER_PATH_POINT_COUNT);
}
