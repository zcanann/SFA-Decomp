#include "ghidra_import.h"
#include "main/dll/SH/SHspore.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175d0();
extern void* FUN_80017624();
extern undefined4 FUN_80017680();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern uint FUN_80017760();
extern undefined4 FUN_80017a6c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 ObjHits_DisableObject();
extern undefined4 FUN_80037ce0();
extern int FUN_80038470();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b444();
extern undefined4 FUN_800400b0();
extern short FUN_8011e824();
extern int FUN_8012efc4();
extern uint FUN_80294cc4();

extern undefined4 DAT_803279d8;
extern undefined4 DAT_803dcc28;
extern undefined4 DAT_803dcc38;
extern undefined4 DAT_803dcc40;
extern undefined4 DAT_803dcc44;
extern undefined4 DAT_803dcc54;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd728;
extern f64 DOUBLE_803e6038;
extern f32 FLOAT_803e6020;
extern f32 FLOAT_803e6024;
extern f32 FLOAT_803e6028;
extern f32 FLOAT_803e6088;
extern f32 FLOAT_803e608c;
extern f32 FLOAT_803e6094;
extern f32 FLOAT_803e6098;

/*
 * --INFO--
 *
 * Function: FUN_801d4364
 * EN v1.0 Address: 0x801D4364
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x801D441C
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d4364(int param_1)
{
  uint uVar1;
  int *piVar2;
  int iVar3;
  undefined local_28 [8];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  local_28[0] = 5;
  *(float *)(iVar3 + 0x274) = FLOAT_803e6088;
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  *(float *)(param_1 + 0x28) = FLOAT_803e608c;
  ObjHits_DisableObject(param_1);
  uVar1 = FUN_80017760(0,0xffff);
  *(short *)(iVar3 + 0x2ac) = (short)uVar1;
  uStack_1c = FUN_80017760(0,1000);
  uStack_1c = uStack_1c ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(iVar3 + 0x280) =
       (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6038) / FLOAT_803e6028;
  (**(code **)(*DAT_803dd728 + 4))(iVar3 + 8,0,0x40002,1);
  (**(code **)(*DAT_803dd728 + 0xc))(iVar3 + 8,1,&DAT_803279d8,&DAT_803dcc28,local_28);
  (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar3 + 8);
  (**(code **)(*DAT_803dd708 + 8))(param_1,0x3f1,0,4,0xffffffff,0);
  piVar2 = FUN_80017624(param_1,'\x01');
  if (piVar2 != (int *)0x0) {
    FUN_800175b0((int)piVar2,2);
    FUN_8001759c((int)piVar2,0xff,0,0xff,0);
    FUN_800175a0((int)piVar2,1);
    FUN_800175d0((double)FLOAT_803e6020,(double)FLOAT_803e6024,(int)piVar2);
  }
  *(int **)(iVar3 + 0x270) = piVar2;
  FUN_80037ce0(param_1,2);
  uVar1 = FUN_80017760(0xfffffe00,0x200);
  *(short *)(iVar3 + 0x2ae) = (short)uVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d4524
 * EN v1.0 Address: 0x801D4524
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x801D45E4
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d4524(undefined2 *param_1)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x26);
  *param_1 = (short)((int)*(char *)(iVar3 + 0x18) << 8);
  if (((int)*(short *)(iVar3 + 0x20) == 0xffffffff) ||
     (uVar1 = FUN_80017690((int)*(short *)(iVar3 + 0x20)), uVar1 != 0)) {
    uVar1 = FUN_80017690(0x66c);
    if (uVar1 == 0) {
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 0x10;
    }
    else {
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xef;
    }
    iVar2 = FUN_80038470((int)param_1,0x66c);
    if (iVar2 == 0) {
      if (((*(byte *)((int)param_1 + 0xaf) & 4) != 0) && (uVar1 = FUN_80017690(0x196), uVar1 == 0))
      {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
        FUN_80017698(0x196,1);
      }
    }
    else {
      FUN_80017680(0x66c);
      FUN_80017698((int)*(short *)(iVar3 + 0x1e),1);
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    }
    uVar1 = FUN_80017690((int)*(short *)(iVar3 + 0x1e));
    if (uVar1 == 0) {
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
      FUN_800400b0();
    }
    else {
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
    }
  }
  else {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d468c
 * EN v1.0 Address: 0x801D468C
 * EN v1.0 Size: 388b
 * EN v1.1 Address: 0x801D4788
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801d468c(short *param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  if ((*(byte *)(iVar3 + 2) & 0x20) == 0) {
    FUN_8000680c((int)param_1,0x7f);
    *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) & 0xef;
    *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) | 0x20;
  }
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    bVar1 = *(byte *)(param_3 + iVar2 + 0x81);
    if (bVar1 == 2) {
      *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) | 2;
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) | 8;
      }
      else {
        *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) & 0xf7;
      }
    }
    else if (bVar1 < 4) {
      *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) & 0xfd;
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) | 8;
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) | 0x40;
    }
  }
  if ((*(byte *)(iVar3 + 2) & 2) != 0) {
    if ((*(byte *)(iVar3 + 2) & 4) == 0) {
      *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfff7;
      iVar2 = FUN_80017a98();
      *(undefined *)(iVar3 + 8) = 1;
      *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
      *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
      FUN_8003b444(param_1,(char *)(iVar3 + 8));
    }
    *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xffbf;
    if ((*(byte *)(iVar3 + 2) & 8) == 0) {
      FUN_8003b280((int)param_1,iVar3 + 8);
    }
    else {
      FUN_8003b1a4((int)param_1,iVar3 + 8);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801d4810
 * EN v1.0 Address: 0x801D4810
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D4954
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d4810(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801d4814
 * EN v1.0 Address: 0x801D4814
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D4A94
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d4814(short *param_1,byte *param_2)
{
}

/*
 * --INFO--
 *
 * Function: sh_queenearthwalker_getExtraSize
 * EN v1.0 Address: 0x801D4794
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int sh_queenearthwalker_getExtraSize(void)
{
  return 0x40;
}
