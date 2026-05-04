#include "ghidra_import.h"
#include "main/dll/LGT/LGTcontrollight.h"

extern undefined4 FUN_80017698();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern int FUN_80044404();

extern undefined4* DAT_803dd72c;
extern f32 lbl_803E6B28;

/*
 * --INFO--
 *
 * Function: FUN_801f4c28
 * EN v1.0 Address: 0x801F4C28
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x801F4C60
 * EN v1.1 Size: 656b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4c28(int param_1)
{
  int iVar1;
  undefined uVar2;
  float *pfVar3;
  
  ObjGroup_AddObject(param_1,9);
  iVar1 = FUN_80044404(0xb);
  FUN_80042b9c(iVar1,0,0);
  pfVar3 = *(float **)(param_1 + 0xb8);
  *(undefined *)((int)pfVar3 + 0xb) = 0;
  *(undefined2 *)((int)pfVar3 + 6) = 0x1e;
  *pfVar3 = lbl_803E6B28;
  pfVar3[4] = 0.0;
  FUN_80042bec(0xf,0);
  uVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  switch(uVar2) {
  case 1:
    (**(code **)(*DAT_803dd72c + 0x44))(0xe,1);
    (**(code **)(*DAT_803dd72c + 0x50))(0xe,0,1);
    break;
  case 2:
    FUN_80017698(0xd1b,1);
    FUN_80017698(0xe6f,1);
    FUN_80017698(0xf43,1);
    FUN_80017698(0xf44,0);
    break;
  case 3:
    FUN_80017698(0xd1b,1);
    FUN_80017698(0xd1c,1);
    FUN_80017698(0xa7f,1);
    FUN_80017698(0xf43,0);
    FUN_80017698(0xf44,1);
    break;
  case 4:
    FUN_80017698(0xd1b,1);
    FUN_80017698(0xd1c,1);
    FUN_80017698(0xd1d,1);
    FUN_80017698(0xa7f,1);
    FUN_80017698(0xf43,0);
    FUN_80017698(0xf44,1);
    *(undefined2 *)(pfVar3 + 1) = 0xffff;
    break;
  case 5:
    FUN_80017698(0xd1b,1);
    FUN_80017698(0xd1c,1);
    FUN_80017698(0xd1d,1);
    FUN_80017698(0xd1e,1);
    FUN_80017698(0xf43,0);
    FUN_80017698(0xf44,1);
    break;
  case 6:
    FUN_80017698(0xd1b,1);
    FUN_80017698(0xd1c,1);
    FUN_80017698(0xd1d,1);
    FUN_80017698(0xd1e,1);
    FUN_80017698(0xd1f,1);
    FUN_80017698(0x164,1);
    FUN_80017698(0xf43,0);
    FUN_80017698(0xf44,0);
    break;
  case 7:
    *(undefined2 *)(pfVar3 + 2) = 700;
    *(undefined *)((int)pfVar3 + 10) = 0x1e;
    *(ushort *)((int)pfVar3 + 6) = (ushort)*(byte *)((int)pfVar3 + 10);
    *(undefined *)(pfVar3 + 5) = 1;
  }
  return;
}
