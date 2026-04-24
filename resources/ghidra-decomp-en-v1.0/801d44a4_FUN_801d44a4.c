// Function: FUN_801d44a4
// Entry: 801d44a4
// Size: 752 bytes

/* WARNING: Removing unreachable block (ram,0x801d44e0) */

void FUN_801d44a4(int param_1,byte *param_2)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  short local_18 [6];
  
  bVar1 = *param_2;
  if (bVar1 == 2) {
    (**(code **)(*DAT_803dca54 + 0x48))(6,param_1,0xffffffff);
    FUN_800200e8(0x9e,1);
    *param_2 = 3;
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      iVar2 = FUN_8001ffb4(0xbf);
      if (iVar2 != 0) {
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
        *param_2 = 1;
      }
    }
    else {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      iVar2 = FUN_8012ebc8();
      if ((iVar2 == -1) && ((iVar2 = FUN_8011f3a8(local_18), iVar2 == 0 || (local_18[0] != 0x66d))))
      {
        iVar2 = FUN_8002b9ac();
        if ((iVar2 == 0) ||
           (dVar4 = (double)FUN_8002166c(iVar2 + 0x18,param_1 + 0x18),
           (double)FLOAT_803e5400 <= dVar4)) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        }
        else {
          FUN_8002b6d8(param_1,0,0,0,0,2);
        }
      }
      else {
        FUN_8002b6d8(param_1,0,0,0,0,4);
        iVar2 = FUN_80037fa4(param_1,0x66d);
        if (iVar2 != 0) {
          param_2[2] = param_2[2] | 0x10;
          iVar2 = FUN_8001ffb4(0x66d);
          iVar3 = FUN_8001ffb4(0xc2);
          FUN_800200e8(0x66d,0);
          FUN_800200e8(0xc2,iVar2 + iVar3);
          if (iVar2 + iVar3 == 6) {
            (**(code **)(*DAT_803dca54 + 0x48))(5,param_1,0xffffffff);
            *param_2 = 2;
          }
          else {
            param_2[2] = param_2[2] | 2;
            iVar2 = FUN_800221a0(0,1);
            if (iVar2 == 0) {
              (**(code **)(*DAT_803dca54 + 0x48))(4,param_1,0xffffffff);
            }
            else {
              (**(code **)(*DAT_803dca54 + 0x48))(3,param_1,0xffffffff);
            }
          }
        }
      }
    }
  }
  else if (bVar1 < 4) {
    FUN_8002b6d8(param_1,0,0,0,0,2);
    param_2[2] = param_2[2] & 0xfb;
    param_2[2] = param_2[2] & 0xf7;
    *(undefined **)(param_2 + 0x38) = &DAT_803dbfd0;
    iVar2 = FUN_8002b9ec();
    param_2[8] = 1;
    *(undefined4 *)(param_2 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
    *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
    *(undefined4 *)(param_2 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
    FUN_8003b500((double)FLOAT_803e53f8,param_1,param_2 + 8);
  }
  return;
}

