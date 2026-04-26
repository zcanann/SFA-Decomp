#include "ghidra_import.h"
#include "main/dll/CF/dll_166.h"

extern uint FUN_80017690();
extern undefined4 FUN_800305c4();
extern undefined4 FUN_80035b84();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern f64 DOUBLE_803e4868;
extern f32 FLOAT_803e4854;
extern f32 FLOAT_803e48a0;
extern f32 FLOAT_803e48a4;
extern f32 FLOAT_803e48a8;
extern f32 FLOAT_803e48ac;
extern f32 FLOAT_803e48b0;

/*
 * --INFO--
 *
 * Function: treasurechest_update
 * EN v1.0 Address: 0x8018AA60
 * EN v1.0 Size: 788b
 * EN v1.1 Address: 0x8018AA94
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void treasurechest_update(short *param_1,int param_2)
{
  byte bVar2;
  uint uVar1;
  undefined unaff_r28;
  float *pfVar3;
  double dVar4;
  
  pfVar3 = *(float **)(param_1 + 0x5c);
  ObjGroup_AddObject((int)param_1,0x41);
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  bVar2 = *(byte *)(param_2 + 0x1d);
  if (2 < bVar2) {
    bVar2 = 2;
  }
  if (*(char *)(param_2 + 0x1c) != '\x02') {
    dVar4 = (double)FLOAT_803e4854;
    goto LAB_8018ab40;
  }
  if (bVar2 != 1) {
    if (bVar2 == 0) {
      unaff_r28 = 0;
      dVar4 = (double)FLOAT_803e48a4;
      goto LAB_8018ab40;
    }
    if (bVar2 < 3) {
      unaff_r28 = 2;
      dVar4 = (double)FLOAT_803e48a0;
      goto LAB_8018ab40;
    }
  }
  unaff_r28 = 1;
  dVar4 = (double)FLOAT_803e4854;
LAB_8018ab40:
  if (*(int *)(param_1 + 0x2a) != 0) {
    FUN_80035b84((int)param_1,
                 (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                               (int)*(short *)(*(int *)(param_1 +
                                                                                       0x2a) + 0x5a)
                                                               ^ 0x80000000) - DOUBLE_803e4868) *
                             dVar4));
  }
  *(float *)(param_1 + 4) = (float)((double)*(float *)(*(int *)(param_1 + 0x28) + 4) * dVar4);
  if (*(float *)(param_1 + 4) < FLOAT_803e48a8) {
    *(float *)(param_1 + 4) = FLOAT_803e48a8;
  }
  bVar2 = *(byte *)(param_2 + 0x1c);
  if (bVar2 == 3) {
    dVar4 = (double)FUN_80293f90();
    *pfVar3 = FLOAT_803e48ac * *(float *)(param_1 + 4) * (float)((double)FLOAT_803e48b0 * dVar4) +
              *(float *)(param_1 + 6);
    dVar4 = (double)FUN_80294964();
    pfVar3[1] = FLOAT_803e48ac * *(float *)(param_1 + 4) * (float)((double)FLOAT_803e48b0 * dVar4) +
                *(float *)(param_1 + 10);
  }
  else if ((bVar2 < 3) && (1 < bVar2)) {
    *(undefined *)(param_1 + 0x72) = unaff_r28;
    dVar4 = (double)FUN_80293f90();
    *pfVar3 = -(FLOAT_803e48ac * *(float *)(param_1 + 4) * (float)((double)FLOAT_803e48b0 * dVar4) -
               *(float *)(param_1 + 6));
    dVar4 = (double)FUN_80294964();
    pfVar3[1] = -(FLOAT_803e48ac * *(float *)(param_1 + 4) * (float)((double)FLOAT_803e48b0 * dVar4)
                 - *(float *)(param_1 + 10));
  }
  else {
    *pfVar3 = *(float *)(param_1 + 6);
    pfVar3[1] = *(float *)(param_1 + 10);
  }
  if (*(short *)(param_2 + 0x22) < 1) {
    *(byte *)((int)pfVar3 + 0x1d) = *(byte *)((int)pfVar3 + 0x1d) & 0x7f | 0x80;
  }
  else {
    uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x22));
    *(byte *)((int)pfVar3 + 0x1d) =
         (byte)((uVar1 & 0xff) << 7) | *(byte *)((int)pfVar3 + 0x1d) & 0x7f;
  }
  *(byte *)((int)pfVar3 + 0x1d) = *(byte *)((int)pfVar3 + 0x1d) & 0xef;
  if (0 < *(short *)(param_2 + 0x24)) {
    uVar1 = FUN_80017690((int)*(short *)(param_2 + 0x24));
    *(byte *)((int)pfVar3 + 0x1d) = (byte)((uVar1 & 1) << 6) | *(byte *)((int)pfVar3 + 0x1d) & 0xbf;
    if ((uVar1 & 1) != 0) {
      bVar2 = *(byte *)(param_2 + 0x1c);
      if (bVar2 == 4) {
        *(byte *)((int)pfVar3 + 0x1d) = *(byte *)((int)pfVar3 + 0x1d) & 0xbf;
      }
      else if (((bVar2 < 4) && (bVar2 != 2)) && (1 < bVar2)) {
        FUN_800305c4((double)FLOAT_803e4854,(int)param_1);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: treasurechest_release
 * EN v1.0 Address: 0x8018ADB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018AF9C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void treasurechest_release(void)
{
}

/*
 * --INFO--
 *
 * Function: treasurechest_initialise
 * EN v1.0 Address: 0x8018ADB8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018AFA0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void treasurechest_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: magiccavebottom_getExtraSize
 * EN v1.0 Address: 0x8018ADBC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018AFA4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int magiccavebottom_getExtraSize(void)
{
  return 1;
}
