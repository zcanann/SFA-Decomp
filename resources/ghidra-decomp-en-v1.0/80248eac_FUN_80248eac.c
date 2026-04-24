// Function: FUN_80248eac
// Entry: 80248eac
// Size: 192 bytes

undefined4
FUN_80248eac(int param_1,undefined4 param_2,int param_3,uint param_4,undefined4 param_5,
            undefined4 param_6)

{
  if (-1 < (int)param_4) {
    if (param_4 < *(uint *)(param_1 + 0x34)) goto LAB_80248efc;
  }
  FUN_802428c8(&DAT_803dc560,0x2e3,s_DVDReadAsync____specified_area_i_8032d930);
LAB_80248efc:
  if (((int)(param_4 + param_3) < 0) || (*(int *)(param_1 + 0x34) + 0x20U <= param_4 + param_3)) {
    FUN_802428c8(&DAT_803dc560,0x2e9,s_DVDReadAsync____specified_area_i_8032d930);
  }
  *(undefined4 *)(param_1 + 0x38) = param_5;
  FUN_8024ac94(param_1,param_2,param_3,*(int *)(param_1 + 0x30) + param_4,&LAB_80248f6c,param_6);
  return 1;
}

