#include "ghidra_import.h"
#include "main/dll/dll_C5.h"

extern undefined4 FUN_800069c8();

extern undefined4 gCamcontrolState;

/*
 * --INFO--
 *
 * Function: FUN_8010224c
 * EN v1.0 Address: 0x8010224C
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x80102354
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010224c(int param_1,int param_2)
{
  if (*(char *)(gCamcontrolState + 0x13b) < param_1) {
    *(char *)(gCamcontrolState + 0x13b) = (char)param_1;
    *(undefined *)(gCamcontrolState + 0x13c) = 2;
    if (param_2 != 0) {
      FUN_800069c8((short)param_1);
    }
  }
  return;
}
