// Function: FUN_80248f9c
// Entry: 80248f9c
// Size: 280 bytes

undefined4 FUN_80248f9c(int param_1,undefined4 param_2,int param_3,uint param_4,undefined4 param_5)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  if (-1 < (int)param_4) {
    if (param_4 < *(uint *)(param_1 + 0x34)) goto LAB_80248fe8;
  }
  FUN_802428c8(&DAT_803dc560,0x329,s_DVDRead____specified_area_is_out_8032d964);
LAB_80248fe8:
  if (((int)(param_4 + param_3) < 0) || (*(int *)(param_1 + 0x34) + 0x20U <= param_4 + param_3)) {
    FUN_802428c8(&DAT_803dc560,0x32f,s_DVDRead____specified_area_is_out_8032d964);
  }
  iVar1 = FUN_8024ac94(param_1,param_2,param_3,*(int *)(param_1 + 0x30) + param_4,&LAB_802490b4,
                       param_5);
  if (iVar1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    uVar3 = FUN_8024377c();
    while (iVar1 = *(int *)(param_1 + 0xc), iVar1 != 0) {
      if (iVar1 == -1) {
        uVar2 = 0xffffffff;
        goto LAB_80249094;
      }
      if (iVar1 == 10) {
        uVar2 = 0xfffffffd;
        goto LAB_80249094;
      }
      FUN_80246a60(&DAT_803ddf00);
    }
    uVar2 = *(undefined4 *)(param_1 + 0x20);
LAB_80249094:
    FUN_802437a4(uVar3);
  }
  return uVar2;
}

