// Function: FUN_801d4a94
// Entry: 801d4a94
// Size: 752 bytes

/* WARNING: Removing unreachable block (ram,0x801d4ad0) */

void FUN_801d4a94(short *param_1,byte *param_2)

{
  byte bVar1;
  int iVar2;
  short sVar5;
  uint uVar3;
  uint uVar4;
  double dVar6;
  short local_18 [6];
  
  bVar1 = *param_2;
  if (bVar1 == 2) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(6,param_1,0xffffffff);
    FUN_800201ac(0x9e,1);
    *param_2 = 3;
  }
  else if (bVar1 < 2) {
    if (bVar1 == 0) {
      uVar3 = FUN_80020078(0xbf);
      if (uVar3 != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
        *param_2 = 1;
      }
    }
    else {
      *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
      iVar2 = FUN_8012f000();
      if ((iVar2 == -1) && ((sVar5 = FUN_8011f68c(local_18), sVar5 == 0 || (local_18[0] != 0x66d))))
      {
        iVar2 = FUN_8002ba84();
        if ((iVar2 == 0) ||
           (dVar6 = FUN_80021730((float *)(iVar2 + 0x18),(float *)(param_1 + 0xc)),
           (double)FLOAT_803e6098 <= dVar6)) {
          *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
        }
        else {
          FUN_8002b7b0((int)param_1,0,0,0,'\0','\x02');
        }
      }
      else {
        FUN_8002b7b0((int)param_1,0,0,0,'\0','\x04');
        iVar2 = FUN_8003809c((int)param_1,0x66d);
        if (iVar2 != 0) {
          param_2[2] = param_2[2] | 0x10;
          uVar3 = FUN_80020078(0x66d);
          uVar4 = FUN_80020078(0xc2);
          FUN_800201ac(0x66d,0);
          FUN_800201ac(0xc2,uVar3 + uVar4);
          if (uVar3 + uVar4 == 6) {
            (**(code **)(*DAT_803dd6d4 + 0x48))(5,param_1,0xffffffff);
            *param_2 = 2;
          }
          else {
            param_2[2] = param_2[2] | 2;
            uVar3 = FUN_80022264(0,1);
            if (uVar3 == 0) {
              (**(code **)(*DAT_803dd6d4 + 0x48))(4,param_1,0xffffffff);
            }
            else {
              (**(code **)(*DAT_803dd6d4 + 0x48))(3,param_1,0xffffffff);
            }
          }
        }
      }
    }
  }
  else if (bVar1 < 4) {
    FUN_8002b7b0((int)param_1,0,0,0,'\0','\x02');
    param_2[2] = param_2[2] & 0xfb;
    param_2[2] = param_2[2] & 0xf7;
    *(undefined **)(param_2 + 0x38) = &DAT_803dcc38;
    iVar2 = FUN_8002bac4();
    param_2[8] = 1;
    *(undefined4 *)(param_2 + 0xc) = *(undefined4 *)(iVar2 + 0xc);
    *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(iVar2 + 0x10);
    *(undefined4 *)(param_2 + 0x14) = *(undefined4 *)(iVar2 + 0x14);
    FUN_8003b5f8(param_1,(char *)(param_2 + 8));
  }
  return;
}

