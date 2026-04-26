#include "ghidra_import.h"
#include "main/dll/baddie/chukachuck.h"

extern uint FUN_80017690();
extern undefined4 FUN_80017a78();
extern int FUN_80017b00();

extern u8 gDfpfloorbarModeTable[9];
extern f64 DOUBLE_803e7098;
extern f32 FLOAT_803e7090;
extern f32 FLOAT_803e7094;

/*
 * --INFO--
 *
 * Function: dfpfloorbar_update
 * EN v1.0 Address: 0x8020652C
 * EN v1.0 Size: 912b
 * EN v1.1 Address: 0x802065F0
 * EN v1.1 Size: 964b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfpfloorbar_update(int param_1)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int local_28;
  int local_24 [6];
  
  iVar6 = *(int *)(param_1 + 0x4c);
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar2 = *(int *)(iVar5 + 4);
  if ((iVar2 == 0) || ((*(ushort *)(iVar2 + 6) & 0x40) == 0)) {
    if (iVar2 == 0) {
      iVar2 = FUN_80017b00(local_24,&local_28);
      for (; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
        iVar4 = *(int *)(iVar2 + local_24[0] * 4);
        if (*(short *)(iVar4 + 0x46) == 0x431) {
          *(int *)(iVar5 + 4) = iVar4;
          local_24[0] = local_28;
        }
      }
      if (*(int *)(iVar5 + 4) == 0) {
        return;
      }
    }
    (**(code **)(**(int **)(*(int *)(iVar5 + 4) + 0x68) + 0x20))
              (*(int *)(iVar5 + 4),gDfpfloorbarModeTable);
    uVar3 = FUN_80017690(0x5e4);
    if (uVar3 == 0) {
      *(undefined *)(iVar5 + 9) = 0;
    }
    else {
      *(u8 *)(iVar5 + 9) = gDfpfloorbarModeTable[*(byte *)(iVar5 + 8)];
    }
    bVar1 = *(byte *)(iVar5 + 9);
    if (bVar1 == 2) {
      if (*(char *)(param_1 + 0xad) != '\x02') {
        FUN_80017a78(param_1,2);
      }
      if ((int)*(short *)(iVar6 + 0x1c) != 0) {
        *(float *)(param_1 + 8) =
             FLOAT_803e7090 /
             ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e7098) / FLOAT_803e7094);
      }
      if (*(short *)(param_1 + 4) != 0) {
        *(undefined2 *)(param_1 + 4) = 0;
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        if (*(char *)(param_1 + 0xad) != '\0') {
          FUN_80017a78(param_1,0);
        }
        if ((int)*(short *)(iVar6 + 0x1c) != 0) {
          *(float *)(param_1 + 8) =
               FLOAT_803e7090 /
               ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                       DOUBLE_803e7098) / FLOAT_803e7094);
        }
      }
      else {
        if (*(char *)(param_1 + 0xad) != '\x01') {
          FUN_80017a78(param_1,1);
        }
        if ((int)*(short *)(iVar6 + 0x1c) != 0) {
          *(float *)(param_1 + 8) =
               FLOAT_803e7090 /
               ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                       DOUBLE_803e7098) / FLOAT_803e7094);
        }
        if (*(short *)(param_1 + 4) != 0) {
          *(undefined2 *)(param_1 + 4) = 0;
        }
      }
    }
    else if (bVar1 == 4) {
      if (*(char *)(param_1 + 0xad) != '\x01') {
        FUN_80017a78(param_1,1);
      }
      if ((int)*(short *)(iVar6 + 0x1c) != 0) {
        *(float *)(param_1 + 8) =
             FLOAT_803e7090 /
             ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e7098) / FLOAT_803e7094);
      }
      if (*(short *)(param_1 + 4) != 0x3fff) {
        *(undefined2 *)(param_1 + 4) = 0x7fff;
      }
    }
    else if (bVar1 < 4) {
      if (*(char *)(param_1 + 0xad) != '\x02') {
        FUN_80017a78(param_1,2);
      }
      if ((int)*(short *)(iVar6 + 0x1c) != 0) {
        *(float *)(param_1 + 8) =
             FLOAT_803e7090 /
             ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e7098) / FLOAT_803e7094);
      }
      if (*(short *)(param_1 + 4) != 0x3fff) {
        *(undefined2 *)(param_1 + 4) = 0x7fff;
      }
    }
    else {
      if (*(char *)(param_1 + 0xad) != '\0') {
        FUN_80017a78(param_1,0);
      }
      if ((int)*(short *)(iVar6 + 0x1c) != 0) {
        *(float *)(param_1 + 8) =
             FLOAT_803e7090 /
             ((float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x1c) ^ 0x80000000) -
                     DOUBLE_803e7098) / FLOAT_803e7094);
      }
      if (*(short *)(param_1 + 4) != 0) {
        *(undefined2 *)(param_1 + 4) = 0;
      }
    }
  }
  else {
    *(undefined4 *)(iVar5 + 4) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dfpfloorbar_release
 * EN v1.0 Address: 0x80206928
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfpfloorbar_release(void)
{
}
