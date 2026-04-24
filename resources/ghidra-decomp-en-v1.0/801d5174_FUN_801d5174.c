// Function: FUN_801d5174
// Entry: 801d5174
// Size: 920 bytes

void FUN_801d5174(int param_1,int param_2)

{
  undefined uVar3;
  int iVar1;
  uint uVar2;
  
  switch(*(undefined *)(param_2 + 0x624)) {
  case 0:
    iVar1 = FUN_8002208c((double)FLOAT_803e5430,(double)FLOAT_803e5434,param_2 + 0x910);
    if (iVar1 != 0) {
      FUN_8000bb18(param_1,0x410);
    }
    *(float *)(param_2 + 0x630) = *(float *)(param_2 + 0x630) - FLOAT_803db414;
    if (*(float *)(param_2 + 0x630) <= FLOAT_803e5438) {
      *(undefined *)(param_2 + 0x624) = 1;
    }
    break;
  case 1:
    *(float *)(param_2 + 0x630) = *(float *)(param_2 + 0x630) - FLOAT_803db414;
    if (*(float *)(param_2 + 0x630) <= FLOAT_803e5418) {
      iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(0);
      if (iVar1 == 0) {
        uVar3 = FUN_801d4f68(param_1,param_2,*(undefined4 *)(param_1 + 0x4c));
        *(undefined *)(param_2 + 0x624) = uVar3;
      }
      else {
        *(undefined *)(param_2 + 0x624) = 0xb;
      }
    }
    break;
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
    if ((*(byte *)(param_2 + 0x625) & 1) != 0) {
      iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(0);
      if (iVar1 == 0) {
        uVar3 = FUN_801d4f68(param_1,param_2,*(undefined4 *)(param_1 + 0x4c));
        *(undefined *)(param_2 + 0x624) = uVar3;
      }
      else {
        *(undefined *)(param_2 + 0x624) = 0xb;
      }
    }
    break;
  case 7:
    if ((*(byte *)(param_2 + 0x625) & 1) != 0) {
      *(undefined *)(param_2 + 0x624) = 8;
      uVar2 = FUN_800221a0(500,800);
      *(float *)(param_2 + 0x634) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5428);
      uVar3 = FUN_800221a0(1,3);
      *(undefined *)(param_2 + 0x63e) = uVar3;
    }
    break;
  case 8:
    *(float *)(param_2 + 0x634) =
         *(float *)(param_2 + 0x634) -
         (float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) - DOUBLE_803e5440);
    if (*(float *)(param_2 + 0x634) <= FLOAT_803e5418) {
      if (*(char *)(param_2 + 0x63e) < '\x01') {
        *(undefined *)(param_2 + 0x624) = 10;
      }
      else {
        *(undefined *)(param_2 + 0x624) = 9;
      }
    }
    break;
  case 9:
    if ((*(byte *)(param_2 + 0x625) & 1) != 0) {
      *(undefined *)(param_2 + 0x624) = 8;
      uVar2 = FUN_800221a0(500,800);
      *(float *)(param_2 + 0x634) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5428);
      *(char *)(param_2 + 0x63e) = *(char *)(param_2 + 0x63e) + -1;
    }
    break;
  case 10:
    if ((*(byte *)(param_2 + 0x625) & 1) != 0) {
      *(undefined *)(param_2 + 0x624) = 0;
      uVar2 = FUN_800221a0(1000,2000);
      *(float *)(param_2 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5428);
    }
    break;
  case 0xb:
    if ((*(byte *)(param_2 + 0x625) & 1) != 0) {
      *(undefined *)(param_2 + 0x627) = 2;
      *(undefined *)(param_2 + 0x624) = 0xc;
    }
    break;
  case 0xc:
    FUN_801d4e80();
    if (((*(byte *)(param_2 + 0x625) & 1) != 0) &&
       (iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(0), iVar1 == 0)) {
      *(undefined *)(param_2 + 0x624) = 0xd;
    }
    break;
  case 0xd:
    if ((*(byte *)(param_2 + 0x625) & 1) != 0) {
      *(undefined *)(param_2 + 0x624) = 0;
      uVar2 = FUN_800221a0(1000,2000);
      *(float *)(param_2 + 0x630) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5428);
    }
    break;
  default:
    FUN_802428c8(s_SHthorntail_c_80327488,0x6cd,s_Thorntail_entered_an_invalid_sta_80327498);
  }
  return;
}

