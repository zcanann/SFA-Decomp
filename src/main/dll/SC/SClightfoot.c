#include "ghidra_import.h"
#include "main/dll/SC/SClightfoot.h"

extern undefined4 FUN_80037180();
extern undefined4 FUN_800388b4();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_801149bc();

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
void SHthorntail_free(SHthorntailObject *obj)
{
  if (gSHthorntailActiveConfigToken == obj->config->configToken) {
    gSHthorntailActiveConfigToken = SHTHORNTAIL_CONFIG_TOKEN_NONE;
  }
  FUN_80037180((int)obj,0x4d);
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
void SHthorntail_render(SHthorntailObject *obj)
{
  SHthorntailRuntime *runtime;
  Vec *pathPoint;
  int pointIndex;
  
  runtime = obj->runtime;
  FUN_8003b818((int)obj);
  FUN_801149bc((short *)obj,(int)runtime,0);
  pathPoint = runtime->renderPathPoints;
  pointIndex = 0;
  do {
    FUN_800388b4((short *)obj,pointIndex,&pathPoint->x,(undefined4 *)&pathPoint->y,&pathPoint->z,0);
    pathPoint = pathPoint + 1;
    pointIndex = pointIndex + 1;
  } while (pointIndex < SHTHORNTAIL_RENDER_PATH_POINT_COUNT);
  return;
}
