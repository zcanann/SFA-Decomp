#include "ghidra_import.h"
#include "main/dll/dll_226.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80017698();
extern undefined4 FUN_801be520();

extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de814;
extern undefined4 DAT_803de828;
extern undefined4 DAT_803de830;
extern f32 lbl_803DC074;
extern f32 lbl_803DE818;
extern f32 lbl_803DE81C;
extern f32 lbl_803DE820;
extern f32 lbl_803DE824;
extern f32 lbl_803E5928;
extern f32 lbl_803E5934;
extern f32 lbl_803E594C;
extern f32 lbl_803E5950;
extern f32 lbl_803E5954;
extern f32 lbl_803E5958;

/*
 * --INFO--
 *
 * Function: dll_DIM_BossGutSpik_update
 * EN v1.0 Address: 0x801BE44C
 * EN v1.0 Size: 804b
 * EN v1.1 Address: 0x801BE750
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_DIM_BossGutSpik_update(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                                undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                undefined8 param_7,undefined8 param_8,uint param_9,
                                undefined4 param_10,int param_11,int param_12)
{
  double dVar1;
  double dVar2;
  
  dVar2 = (double)lbl_803E5928;
  *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) | 1;
  *(undefined *)(param_12 + 0x25f) = 1;
  (**(code **)(*DAT_803dd738 + 0x2c))(dVar2,param_9,param_12,1);
  (**(code **)(*DAT_803dd738 + 0x54))
            (param_9,param_12,param_11 + 0x35c,(int)*(short *)(param_11 + 0x3f4),param_11 + 0x405,0,
             0,0);
  dVar1 = (double)lbl_803E5928;
  if (dVar1 == (double)lbl_803DE824) {
    dVar2 = (double)(float)(dVar2 + (double)lbl_803E5954);
  }
  else {
    lbl_803DE824 = (float)((double)lbl_803DE824 - (double)lbl_803DC074);
    dVar2 = (double)(lbl_803DE824 * lbl_803E594C);
    if (lbl_803DE824 <= lbl_803E5950) {
      lbl_803DE824 = lbl_803E5928;
      *(undefined *)(param_12 + 0x349) = 0;
      *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      FUN_80017698(0x20e,0);
      if (DAT_803de814 < '\a') {
        FUN_80017698(0x268,1);
      }
      else {
        FUN_80017698(0x311,1);
      }
    }
  }
  if (lbl_803DE81C <= lbl_803DE820) {
    FUN_80006824(param_9,0x189);
    if ((double)lbl_803E5954 < dVar2) {
      dVar2 = (double)lbl_803E5954;
    }
    if (dVar2 < (double)lbl_803E5934) {
      dVar2 = (double)lbl_803E5934;
    }
    lbl_803DE81C = (float)((double)lbl_803DE81C + dVar2);
    FUN_80006b94((double)lbl_803E5958);
  }
  dVar2 = (double)lbl_803DE820;
  lbl_803DE820 = (float)(dVar2 + (double)lbl_803DC074);
  FUN_801be520(dVar2,dVar1,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_12);
  if ((lbl_803E5928 != lbl_803DE818) &&
     (lbl_803DE818 = lbl_803DE818 - lbl_803DC074, lbl_803DE818 <= lbl_803E5928)) {
    lbl_803DE818 = lbl_803E5928;
    *(undefined *)(param_12 + 0x349) = 0;
    *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    FUN_80017698(0x20e,0);
    if (DAT_803de814 == '\x03') {
      FUN_80017698(0x268,1);
    }
    else {
      FUN_80017698(0x311,1);
    }
  }
  *(undefined4 *)(param_11 + 0x3e0) = *(undefined4 *)(param_9 + 0xc0);
  *(undefined4 *)(param_9 + 0xc0) = 0;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)lbl_803DC074,(double)lbl_803DC074,param_9,param_12,&DAT_803de830,
             &DAT_803de828);
  *(undefined4 *)(param_9 + 0xc0) = *(undefined4 *)(param_11 + 0x3e0);
  return;
}

/*
 * --INFO--
 *
 * Function: dimbosstonsil_func11
 * EN v1.0 Address: 0x801BE86C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbosstonsil_func11(void)
{
}

/*
 * --INFO--
 *
 * Function: dimbosstonsil_setScale
 * EN v1.0 Address: 0x801BE870
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimbosstonsil_setScale(int obj)
{
  return *(short *)(*(int *)(obj + 0xb8) + 0x274);
}

/*
 * --INFO--
 *
 * Function: dimbosstonsil_getExtraSize
 * EN v1.0 Address: 0x801BE87C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimbosstonsil_getExtraSize(void)
{
  return 0x410;
}

/*
 * --INFO--
 *
 * Function: dimbosstonsil_func08
 * EN v1.0 Address: 0x801BE884
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dimbosstonsil_func08(void)
{
  return 0x4b;
}
