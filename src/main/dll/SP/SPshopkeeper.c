#include "ghidra_import.h"
#include "main/dll/SP/SPshopkeeper.h"

extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern int FUN_80017a98();
extern undefined4 FUN_80135814();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_80328258;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd72c;
extern f64 DOUBLE_803e6150;
extern f32 lbl_803DC074;
extern f32 lbl_803E6148;
extern f32 lbl_803E614C;

/*
 * --INFO--
 *
 * Function: FUN_801d87f8
 * EN v1.0 Address: 0x801D87F8
 * EN v1.0 Size: 1380b
 * EN v1.1 Address: 0x801D88F8
 * EN v1.1 Size: 1264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d87f8(void)
{
  int iVar1;
  char cVar6;
  uint uVar2;
  short *psVar3;
  uint uVar4;
  int iVar5;
  uint *puVar7;
  byte bVar8;
  undefined8 uVar9;
  undefined8 local_28;
  
  uVar9 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar9 >> 0x20);
  puVar7 = (uint *)uVar9;
  cVar6 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(iVar1 + 0xac),0);
  if ((cVar6 == '\0') && (uVar2 = FUN_80017690(0x13f), uVar2 == 0)) {
    *(undefined *)((int)puVar7 + 6) = 0;
    (**(code **)(*DAT_803dd6e8 + 100))();
    for (bVar8 = 0; bVar8 < 0x12; bVar8 = bVar8 + 1) {
      FUN_80017698((int)(short)(&DAT_80328258)[bVar8],0);
    }
  }
  psVar3 = (short *)FUN_80017a98();
  switch(*(undefined *)((int)puVar7 + 6)) {
  case 0:
    uVar2 = FUN_80017690(0x13f);
    if (uVar2 == 0) {
      *(undefined *)((int)puVar7 + 6) = 1;
    }
    else {
      *(undefined *)((int)puVar7 + 6) = 7;
    }
    break;
  case 1:
    uVar2 = FUN_80017690(0x124);
    if (uVar2 != 0) {
      (**(code **)(*DAT_803dd72c + 0x1c))(psVar3 + 6,(int)*psVar3,1,0);
      puVar7[2] = (uint)lbl_803E6148;
      (**(code **)(*DAT_803dd6e8 + 0x58))(100000,0x5db);
      *(undefined *)((int)puVar7 + 6) = 2;
    }
    break;
  case 2:
    uVar2 = 0x12;
    for (bVar8 = 0; bVar8 < 0x12; bVar8 = bVar8 + 1) {
      uVar4 = FUN_80017690((int)(short)(&DAT_80328258)[bVar8]);
      if (uVar4 != 0) {
        uVar2 = uVar2 - 1 & 0xff;
      }
    }
    FUN_80135814();
    if (uVar2 == 0) {
      (**(code **)(*DAT_803dd6e8 + 100))();
      (**(code **)(*DAT_803dd6cc + 8))(0x14,1);
      *(undefined *)((int)puVar7 + 6) = 3;
      FUN_80006824(0,0x7e);
    }
    else {
      local_28 = (double)CONCAT44(0x43300000,uVar2);
      puVar7[2] = (uint)-((float)(local_28 - DOUBLE_803e6150) * lbl_803DC074 - (float)puVar7[2]);
      if ((float)puVar7[2] < lbl_803E614C) {
        cVar6 = (**(code **)(*DAT_803dd72c + 0x4c))((int)*(char *)(iVar1 + 0xac),0);
        if (cVar6 == '\0') {
          puVar7[2] = (uint)lbl_803E614C;
          (**(code **)(*DAT_803dd6e8 + 0x5c))(1);
        }
        else {
          (**(code **)(*DAT_803dd6e8 + 100))();
          (**(code **)(*DAT_803dd6cc + 8))(0x14,1);
          *(undefined *)((int)puVar7 + 6) = 5;
        }
      }
      else {
        (**(code **)(*DAT_803dd6e8 + 0x5c))((int)(float)puVar7[2]);
      }
    }
    break;
  case 3:
    iVar5 = (**(code **)(*DAT_803dd6cc + 0x14))();
    if ((iVar5 != 0) && (iVar5 = FUN_80017a98(), (*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0)) {
      FUN_80017698(0x13f,1);
      (**(code **)(*DAT_803dd6d4 + 0x48))(3,iVar1,0xffffffff);
      *(undefined *)((int)puVar7 + 6) = 4;
    }
    break;
  case 4:
    *(undefined *)((int)puVar7 + 6) = 7;
    break;
  case 5:
    iVar5 = (**(code **)(*DAT_803dd6cc + 0x14))();
    if ((iVar5 != 0) && (iVar5 = FUN_80017a98(), (*(ushort *)(iVar5 + 0xb0) & 0x1000) == 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(2,iVar1,0xffffffff);
      *(undefined *)((int)puVar7 + 6) = 6;
    }
    break;
  case 6:
    (**(code **)(*DAT_803dd72c + 0x28))();
    break;
  case 7:
    uVar2 = FUN_80017690(0xea6);
    if (uVar2 == 0) {
      FUN_80017698(0xea6,1);
      uVar2 = FUN_80017690(0x1a2);
      if (uVar2 == 0) {
        FUN_80017698(0x9d5,1);
      }
    }
  }
  if (*(char *)((int)puVar7 + 6) == '\x02') {
    if (*(short *)((int)puVar7 + 0x12) != 0xf2) {
      *(undefined2 *)((int)puVar7 + 0x12) = 0xf2;
      FUN_80017698(0xc0,1);
      *puVar7 = *puVar7 & 0xfffffffd;
    }
  }
  else if (*(short *)((int)puVar7 + 0x12) != 0xcc) {
    *(undefined2 *)((int)puVar7 + 0x12) = 0xcc;
    FUN_80017698(0xc0,1);
    *puVar7 = *puVar7 & 0xfffffffd;
  }
  uVar2 = FUN_80017690(0xea8);
  if ((uVar2 == 0) && (uVar2 = FUN_80017690(0x91b), uVar2 != 0)) {
    FUN_80017698(0xea8,1);
    (**(code **)(*DAT_803dd72c + 0x1c))(0,0,1,0);
  }
  FUN_8028688c();
  return;
}
