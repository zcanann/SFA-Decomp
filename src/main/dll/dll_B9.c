#include "ghidra_import.h"
#include "main/dll/dll_B9.h"

extern void* FUN_800069a8();
extern double FUN_800069f8();

extern undefined4 gCamcontrolState;
extern f64 DOUBLE_803e22e0;
extern f32 FLOAT_803e22ac;

/*
 * --INFO--
 *
 * Function: FUN_80101980
 * EN v1.0 Address: 0x80101980
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x80101B44
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80101980(uint param_1,undefined param_2)
{
  float fVar1;
  undefined2 *puVar2;
  double dVar3;
  
  FUN_800069a8();
  fVar1 = FLOAT_803e22ac;
  *(float *)(gCamcontrolState + 0xf4) = FLOAT_803e22ac;
  *(float *)(gCamcontrolState + 0xf8) =
       fVar1 / (float)((double)CONCAT44(0x43300000,param_1 & 0xff) - DOUBLE_803e22e0);
  *(undefined *)(gCamcontrolState + 0x13f) = param_2;
  puVar2 = FUN_800069a8();
  *(undefined4 *)(gCamcontrolState + 0x10c) = *(undefined4 *)(puVar2 + 6);
  *(undefined4 *)(gCamcontrolState + 0x110) = *(undefined4 *)(puVar2 + 8);
  *(undefined4 *)(gCamcontrolState + 0x114) = *(undefined4 *)(puVar2 + 10);
  *(undefined2 *)(gCamcontrolState + 0x106) = *puVar2;
  *(undefined2 *)(gCamcontrolState + 0x108) = puVar2[1];
  *(undefined2 *)(gCamcontrolState + 0x10a) = puVar2[2];
  dVar3 = FUN_800069f8();
  *(float *)(gCamcontrolState + 0x118) = (float)dVar3;
  return;
}
