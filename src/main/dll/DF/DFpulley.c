#include "ghidra_import.h"
#include "main/dll/DF/DFpulley.h"

extern uint FUN_80020078();
extern uint FUN_80022264();
extern undefined4 FUN_80035a6c();
extern undefined4 FUN_80035eec();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_800372f8();

extern f64 DOUBLE_803e5a60;
extern f64 DOUBLE_803e5a70;
extern f32 FLOAT_803e5a68;
extern f32 FLOAT_803e5a6c;

/*
 * --INFO--
 *
 * Function: FUN_801c0f60
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C0F60
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c0f60(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_80035eec(param_1,0,0,0);
  FUN_80035a6c(param_1,0);
  FUN_80035ff8(param_1);
  if (param_3 == 0) {
    uVar1 = FUN_80022264(0xf0,0x1e0);
    *(float *)(iVar2 + 0xc) =
         (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5a60);
    uVar1 = FUN_80022264(0,9);
    *(char *)(iVar2 + 1) = (char)uVar1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c101c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C101C
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c101c(int param_1)
{
  if (**(char **)(param_1 + 0xb8) != '\0') {
    FUN_8003709c(param_1,0x14);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c1054
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C1054
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c1054(int param_1)
{
  uint uVar1;
  char *pcVar2;
  
  uVar1 = (uint)*(short *)(*(int *)(param_1 + 0x4c) + 0x1c);
  if (uVar1 != 0xffffffff) {
    pcVar2 = *(char **)(param_1 + 0xb8);
    uVar1 = FUN_80020078(uVar1);
    if (uVar1 == 0) {
      if (*pcVar2 == '\0') {
        *pcVar2 = '\x01';
        FUN_800372f8(param_1,0x14);
      }
    }
    else if (*pcVar2 != '\0') {
      *pcVar2 = '\0';
      FUN_8003709c(param_1,0x14);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c10e8
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801C10E8
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c10e8(short *param_1,int param_2)
{
  if (*(short *)(param_2 + 0x1c) == -1) {
    FUN_800372f8((int)param_1,0x14);
    **(undefined **)(param_1 + 0x5c) = 1;
  }
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4);
  *(float *)(param_1 + 4) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x19)) - DOUBLE_803e5a70) *
       FLOAT_803e5a68 + *(float *)(param_1 + 4);
  if (*(float *)(param_1 + 4) < FLOAT_803e5a6c) {
    *(float *)(param_1 + 4) = FLOAT_803e5a6c;
  }
  if (*(char *)(param_2 + 0x1a) == '\0') {
    *(undefined *)(param_2 + 0x1a) = 0xff;
  }
  return;
}
