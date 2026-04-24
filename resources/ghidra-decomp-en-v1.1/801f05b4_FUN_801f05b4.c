// Function: FUN_801f05b4
// Entry: 801f05b4
// Size: 576 bytes

undefined4
FUN_801f05b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11)

{
  uint uVar1;
  char cVar2;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  
  DAT_803dcd58 = (uint)DAT_803dc070;
  *(undefined2 *)(param_11 + 0x6e) = 0xffff;
  *(undefined *)(param_11 + 0x56) = 0;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)(param_11 + iVar3 + 0x81)) {
    case 1:
      *(undefined4 *)(param_9 + 0xf4) = 10;
      break;
    case 2:
      FUN_800066e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x77,0,0,0,in_r9,in_r10);
      FUN_800066e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x78,0,0,0,in_r9,in_r10);
      FUN_800066e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                   0x80,0,0,0,in_r9,in_r10);
      break;
    case 3:
      param_1 = (**(code **)(*DAT_803dd714 + 0x14))(0,0x1e,0x50);
      break;
    case 4:
      *(undefined4 *)(param_9 + 0xf4) = 0xc;
      break;
    case 5:
      *(undefined4 *)(param_9 + 0xf4) = 0xd;
      break;
    case 6:
      (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_9 + 0x34),1,0);
      (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_9 + 0x34),2,0);
      (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_9 + 0x34),4,0);
      param_1 = FUN_800201ac(0xd1,0);
      break;
    case 7:
      DAT_803de8f0 = 1;
      break;
    case 8:
      DAT_803de8f0 = 0;
      break;
    case 9:
      *(undefined4 *)(param_9 + 0xf4) = 0xb;
    }
  }
  uVar1 = FUN_80020078(0x429);
  if ((uVar1 != 0) &&
     (cVar2 = (**(code **)(*DAT_803dd72c + 0x4c))(*(undefined *)(param_9 + 0x34),2), cVar2 != '\0'))
  {
    (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_9 + 0x34),1,0);
    (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_9 + 0x34),2,0);
  }
  return 0;
}

