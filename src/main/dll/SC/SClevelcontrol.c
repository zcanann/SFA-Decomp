#include "ghidra_import.h"
#include "main/dll/SC/SClevelcontrol.h"

extern undefined4 FUN_8000b7dc();
extern undefined4 FUN_8000bb38();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern double FUN_80021730();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern int FUN_8003811c();
extern undefined4 FUN_8003b408();
extern undefined4 FUN_8006f0b4();
extern int FUN_80114e4c();
extern int FUN_801d52c0();
extern undefined4 FUN_801d5470();
extern undefined4 SHthorntail_updateState();

extern undefined4 DAT_80328014;
extern undefined4 DAT_803dcc64;
extern undefined4 DAT_803dcc6c;
extern f64 DOUBLE_803e60c0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e60b0;
extern f32 FLOAT_803e60bc;
extern f32 FLOAT_803e60d0;
extern f32 FLOAT_803e60e0;

/*
 * --INFO--
 *
 * Function: FUN_801d5ed4
 * EN v1.0 Address: 0x801D5ED4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D5ED4
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d5ed4(uint param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801d6158
 * EN v1.0 Address: 0x801D5ED8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D6158
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d6158(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,int param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801d6338
 * EN v1.0 Address: 0x801D5EDC
 * EN v1.0 Size: 472b
 * EN v1.1 Address: 0x801D6338
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801d6338(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  if ((*(byte *)((int)pfVar3 + 0x625) & 8) == 0) {
    FUN_8000b7dc(param_9,0x7f);
    *(undefined *)(pfVar3 + 0x189) = 0;
    uVar1 = FUN_80022264(1000,2000);
    param_1 = DOUBLE_803e60c0;
    pfVar3[0x18c] = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e60c0);
    *(byte *)((int)pfVar3 + 0x625) = *(byte *)((int)pfVar3 + 0x625) & 0xfb;
    *(byte *)((int)pfVar3 + 0x625) = *(byte *)((int)pfVar3 + 0x625) | 0x18;
    *(undefined *)((int)pfVar3 + 0x63f) = 0;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  }
  if ((*(byte *)((int)pfVar3 + 0x625) & 2) != 0) {
    iVar2 = FUN_80114e4c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_11,pfVar3,0,0,param_14,param_15,param_16);
    if (iVar2 != 0) {
      return 0;
    }
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xffbf;
    FUN_8003b408(param_9,(int)(pfVar3 + 0x22c));
  }
  *(undefined *)((int)pfVar3 + 0x89f) = 0;
  FUN_8006f0b4((double)FLOAT_803e60e0,(double)FLOAT_803e60e0,param_9,param_11 + 0xf0,8,
               (int)(pfVar3 + 0x238),(int)(pfVar3 + 0x191));
  return 0;
}
