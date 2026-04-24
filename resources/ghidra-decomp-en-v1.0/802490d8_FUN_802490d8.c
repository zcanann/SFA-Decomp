// Function: FUN_802490d8
// Entry: 802490d8
// Size: 236 bytes

void FUN_802490d8(int param_1,uint param_2,uint param_3,undefined4 param_4)

{
  if ((*(int *)(param_1 + 0x30) + param_3 & 0x7fff) != 0) {
    FUN_802428c8(&DAT_803dc560,0x4a2,s_DVDPrepareStreamAsync____Specifi_8032d9f8,
                 *(int *)(param_1 + 0x30),param_3);
  }
  if (param_2 == 0) {
    param_2 = *(int *)(param_1 + 0x34) - param_3;
  }
  if ((param_2 & 0x7fff) != 0) {
    FUN_802428c8(&DAT_803dc560,0x4ac,s_DVDPrepareStreamAsync____Specifi_8032da60,param_2);
  }
  if ((*(uint *)(param_1 + 0x34) <= param_3) || (*(uint *)(param_1 + 0x34) < param_3 + param_2)) {
    FUN_802428c8(&DAT_803dc560,0x4b4,s_DVDPrepareStreamAsync____The_are_8032dab8,param_3,param_2);
  }
  *(undefined4 *)(param_1 + 0x38) = param_4;
  FUN_8024af14(param_1,param_2,*(int *)(param_1 + 0x30) + param_3,&LAB_802491c4);
  return;
}

