// Function: FUN_801d87f8
// Entry: 801d87f8
// Size: 776 bytes

/* WARNING: Removing unreachable block (ram,0x801d8880) */

void FUN_801d87f8(undefined4 param_1,uint *param_2)

{
  int iVar1;
  
  iVar1 = FUN_8001ffb4(0x193);
  if (iVar1 == 0) {
    if (*(short *)((int)param_2 + 0x12) == 0xcc) {
      *(undefined2 *)((int)param_2 + 0x12) = 0xffff;
    }
  }
  else if (*(short *)((int)param_2 + 0x12) != 0xcc) {
    *(undefined2 *)((int)param_2 + 0x12) = 0xcc;
    FUN_800200e8(0xc0,1);
    *param_2 = *param_2 & 0xfffffffd;
  }
  if (*(char *)((int)param_2 + 6) == '\x01') {
    iVar1 = FUN_8002e0b4(0x442ff);
    if (((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0) &&
       (iVar1 = FUN_8002b9ec(), (*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) {
      (**(code **)(*DAT_803dca54 + 0x48))(6,param_1,0xffffffff);
      *(undefined *)((int)param_2 + 6) = 7;
      FUN_800200e8(0xd39,1);
    }
  }
  else if (*(char *)((int)param_2 + 6) == '\0') {
    iVar1 = FUN_8001ffb4(0xd39);
    if (iVar1 == 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(5,param_1,0xffffffff);
      *(undefined *)((int)param_2 + 6) = 1;
    }
    else {
      *(undefined *)((int)param_2 + 6) = 7;
    }
  }
  if (((((*param_2 & 0x40) == 0) && (iVar1 = FUN_8001ffb4(400), iVar1 != 0)) &&
      (iVar1 = FUN_8001ffb4(0x191), iVar1 != 0)) && (iVar1 = FUN_8001ffb4(0x192), iVar1 != 0)) {
    iVar1 = FUN_8001ffb4(0x193);
    if (iVar1 == 0) {
      iVar1 = FUN_8002e0b4(0x442ff);
      if ((iVar1 != 0) && (iVar1 = FUN_8002b9ec(), (*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) {
        iVar1 = FUN_800d7aec();
        if (iVar1 == 0) {
          FUN_800200e8(0x193,1);
          (**(code **)(*DAT_803dca4c + 8))(0x14,1);
        }
        else {
          FUN_800200e8(0x193,1);
          (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
          *param_2 = *param_2 | 0x40;
        }
      }
    }
    else {
      iVar1 = (**(code **)(*DAT_803dca4c + 0x14))();
      if (((iVar1 != 0) && (iVar1 = FUN_8002e0b4(0x442ff), iVar1 != 0)) &&
         (iVar1 = FUN_8002b9ec(), (*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) {
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
        *param_2 = *param_2 | 0x40;
      }
    }
  }
  iVar1 = FUN_8001ffb4(0xea9);
  if ((iVar1 == 0) && (iVar1 = FUN_8001ffb4(0x611), iVar1 != 0)) {
    FUN_800200e8(0xea9,1);
    (**(code **)(*DAT_803dcaac + 0x1c))(0,0,1,0);
  }
  return;
}

