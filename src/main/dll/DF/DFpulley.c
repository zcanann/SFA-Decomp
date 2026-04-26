#include "ghidra_import.h"
#include "main/dll/DF/DFpulley.h"

extern uint FUN_80017690();
extern uint FUN_80017760();
extern undefined4 FUN_80035b84();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 FUN_800360d4();
extern undefined4 FUN_80037180();
extern undefined4 FUN_8003735c();

extern f64 DOUBLE_803e5a60;
extern f64 DOUBLE_803e5a70;
extern f32 FLOAT_803e5a68;
extern f32 FLOAT_803e5a6c;

/*
 * --INFO--
 *
 * Function: FUN_801c0e60
 * EN v1.0 Address: 0x801C0E60
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x801C0F60
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c0e60(int param_1,undefined4 param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  ObjHits_SetHitVolumeSlot(param_1,0,0,0);
  FUN_80035b84(param_1,0);
  FUN_800360d4(param_1);
  if (param_3 == 0) {
    uVar1 = FUN_80017760(0xf0,0x1e0);
    *(float *)(iVar2 + 0xc) =
         (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5a60);
    uVar1 = FUN_80017760(0,9);
    *(char *)(iVar2 + 1) = (char)uVar1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c0f04
 * EN v1.0 Address: 0x801C0F04
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801C101C
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c0f04(int param_1)
{
  if (**(char **)(param_1 + 0xb8) != '\0') {
    FUN_80037180(param_1,0x14);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c0f38
 * EN v1.0 Address: 0x801C0F38
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801C1054
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c0f38(int param_1)
{
  uint uVar1;
  char *pcVar2;
  
  uVar1 = (uint)*(short *)(*(int *)(param_1 + 0x4c) + 0x1c);
  if (uVar1 != 0xffffffff) {
    pcVar2 = *(char **)(param_1 + 0xb8);
    uVar1 = FUN_80017690(uVar1);
    if (uVar1 == 0) {
      if (*pcVar2 == '\0') {
        *pcVar2 = '\x01';
        FUN_8003735c(param_1,0x14);
      }
    }
    else if (*pcVar2 != '\0') {
      *pcVar2 = '\0';
      FUN_80037180(param_1,0x14);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c0fd0
 * EN v1.0 Address: 0x801C0FD0
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x801C10E8
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c0fd0(short *param_1,int param_2)
{
  if (*(short *)(param_2 + 0x1c) == -1) {
    FUN_8003735c((int)param_1,0x14);
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
