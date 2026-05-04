#include "ghidra_import.h"
#include "main/dll/DR/DRyoutube.h"

extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 ObjGroup_FindNearestObject();
extern int FUN_80039520();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4 DAT_803dcd18;
extern undefined4 DAT_803dcd1c;
extern f64 DOUBLE_803e6768;
extern f32 lbl_803E6738;
extern f32 lbl_803E6754;
extern f32 lbl_803E6758;
extern f32 lbl_803E675C;
extern f32 lbl_803E6770;

/*
 * --INFO--
 *
 * Function: FUN_801e9c00
 * EN v1.0 Address: 0x801E9C00
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E9C74
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e9c00(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801e9c04
 * EN v1.0 Address: 0x801E9C04
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x801E9E30
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e9c04(int param_1)
{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  float local_18 [3];
  
  iVar4 = *(int *)(param_1 + 0xf4);
  iVar3 = *(int *)(param_1 + 0x4c);
  local_18[0] = lbl_803E6770;
  if (iVar4 == 0) {
    uVar1 = ObjGroup_FindNearestObject(9,param_1,local_18);
    *(undefined4 *)(param_1 + 0xf4) = uVar1;
  }
  else {
    iVar2 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x28))(iVar4,(int)*(short *)(iVar3 + 0x1a));
    if ((iVar2 == 0) ||
       (iVar3 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x2c))(iVar4,(int)*(short *)(iVar3 + 0x1a)),
       iVar3 != 0)) {
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
    }
    iVar3 = FUN_80039520(param_1,0);
    if (iVar3 != 0) {
      *(short *)(iVar3 + 8) = *(short *)(iVar3 + 8) + 8;
      if (0x400 < *(short *)(iVar3 + 8)) {
        *(short *)(iVar3 + 8) = *(short *)(iVar3 + 8) + -0x400;
      }
    }
  }
  return;
}
