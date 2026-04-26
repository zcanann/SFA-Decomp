#include "ghidra_import.h"
#include "main/dll/SC/SClevelcontrol.h"

extern void ObjPath_GetPointWorldPosition(SHthorntailObject *obj,int pointIndex,f32 *x,f32 *y,f32 *z,int param_6);
extern void fn_8003B8F4(f32 scale);
extern void fn_80114DEC(SHthorntailObject *obj,SHthorntailRuntime *runtime,int param_3);

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
#pragma scheduling off
void sh_thorntail_render(SHthorntailObject *obj)
{
  SHthorntailRuntime *runtime;
  int pointIndex;

  runtime = obj->runtime;
  fn_8003B8F4(lbl_803E5448);
  fn_80114DEC(obj,runtime,0);
  pointIndex = 0;
  do {
    ObjPath_GetPointWorldPosition(obj,pointIndex,&runtime->renderPathPoints[0].x,&runtime->renderPathPoints[0].y,
                &runtime->renderPathPoints[0].z,0);
    runtime = (SHthorntailRuntime *)((int)runtime + sizeof(Vec));
    pointIndex = pointIndex + 1;
  } while (pointIndex < SHTHORNTAIL_RENDER_PATH_POINT_COUNT);
}
#pragma scheduling reset
