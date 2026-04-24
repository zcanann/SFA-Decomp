#include "ghidra_import.h"
#include "main/dll/SH/SHthorntail_internal.h"
#include "main/dll/SC/SClightfoot.h"

extern undefined4 FUN_80037180();
extern undefined4 FUN_800388b4();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_801149bc();

extern undefined4 DAT_803dcc60;

/*
 * --INFO--
 *
 * Function: SHthorntail_free
 * EN v1.0 Address: 0x801D5F58
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x801D6484
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_free(int param_1)
{
  SHthorntailObject *obj;
  
  obj = (SHthorntailObject *)param_1;
  if (DAT_803dcc60 == obj->config->configToken) {
    DAT_803dcc60 = -1;
  }
  FUN_80037180(param_1,0x4d);
  return;
}

/*
 * --INFO--
 *
 * Function: SHthorntail_render
 * EN v1.0 Address: 0x801D5F98
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x801D64C4
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_render(short *param_1)
{
  SHthorntailRuntime *runtime;
  Vec *pathPoint;
  int pointIndex;
  
  runtime = ((SHthorntailObject *)param_1)->runtime;
  FUN_8003b818((int)param_1);
  FUN_801149bc(param_1,(int)runtime,0);
  pathPoint = runtime->renderPathPoints;
  pointIndex = 0;
  do {
    FUN_800388b4(param_1,pointIndex,&pathPoint->x,(undefined4 *)&pathPoint->y,&pathPoint->z,0);
    pathPoint = pathPoint + 1;
    pointIndex = pointIndex + 1;
  } while (pointIndex < SHTHORNTAIL_RENDER_PATH_POINT_COUNT);
  return;
}
